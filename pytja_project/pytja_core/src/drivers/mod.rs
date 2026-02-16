pub mod sqlite;
pub mod postgres;

use crate::repo::PytjaRepository;
use crate::error::PytjaError;
use std::sync::{Arc, RwLock}; // WICHTIG: Sync Locks für High-Performance RAM Zugriff
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use tokio::fs; // WICHTIG: Async FS für non-blocking I/O
use tracing::{info, warn, error};

// Enterprise Database Support
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DatabaseType {
    Sqlite,
    Postgres,
    MySQL,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MountConfig {
    pub name: String,
    pub path: String,
    pub db_type: DatabaseType,
}

/// Der DriverManager verwaltet alle aktiven Datenbank-Verbindungen.
pub struct DriverManager {
    // Sync RwLock ist hier besser, da HashMap-Lookups extrem schnell sind (Nanosekunden).
    // Async Locks (Tokio) sind nur nötig, wenn wir lange warten müssten (z.B. I/O).
    connections: Arc<RwLock<HashMap<String, Arc<dyn PytjaRepository>>>>,
    config_cache: Arc<RwLock<Vec<MountConfig>>>,
}

impl DriverManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            config_cache: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Lädt die Konfiguration asynchron beim Start.
    pub async fn load_config(&self, config_path: &str) {
        info!("Loading configuration from '{}'", config_path);

        // Asynchrones Lesen der Datei (blockiert den Server nicht)
        match fs::read_to_string(config_path).await {
            Ok(content) => {
                match serde_json::from_str::<Vec<MountConfig>>(&content) {
                    Ok(configs) => {
                        info!("Found {} mount definitions.", configs.len());

                        // Cache updaten (kurzes Blocking ist hier okay)
                        {
                            let mut cache = self.config_cache.write().unwrap();
                            *cache = configs.clone();
                        }

                        // Mounts ausführen
                        for cfg in configs {
                            // save=false, da wir gerade erst geladen haben
                            if let Err(e) = self.mount_internal(&cfg.name, &cfg.path, cfg.db_type.clone(), false).await {
                                error!("Failed to mount database '{}': {}", cfg.name, e);
                            }
                        }
                    },
                    Err(e) => warn!("Could not parse mounts.json: {}", e),
                }
            },
            Err(_) => warn!("No mounts.json found. Starting with empty configuration."),
        }
    }

    /// Öffentliche Methode zum Mounten.
    pub async fn mount(&self, name: &str, path: &str, db_type: DatabaseType) -> Result<(), PytjaError> {
        self.mount_internal(name, path, db_type, true).await
    }

    /// Interne Logik
    async fn mount_internal(&self, name: &str, path: &str, db_type: DatabaseType, save_to_disk: bool) -> Result<(), PytjaError> {
        // Treiber Initialisierung ist async (DB Connect)
        let repo: Arc<dyn PytjaRepository> = match db_type {
            DatabaseType::Sqlite => {
                let driver = sqlite::SqliteDriver::new(path).await?;
                driver.init().await?;
                Arc::new(driver)
            },
            DatabaseType::Postgres => {
                let driver = postgres::PostgresDriver::new(path).await?;
                driver.init().await?;
                Arc::new(driver)
            },
            _ => return Err(PytjaError::System("Unsupported DB Type".into())),
        };

        // In-Memory registrieren (Sync Lock)
        {
            let mut map = self.connections.write().unwrap();
            map.insert(name.to_string(), repo);
        }
        info!("Mounted database '{}' ({:?})", name, db_type);

        // Persistent speichern (Async I/O)
        if save_to_disk {
            self.persist_mount(name, path, db_type).await?;
        }

        Ok(())
    }

    /// Speichert Config atomar (Async Write + Rename)
    async fn persist_mount(&self, name: &str, path: &str, db_type: DatabaseType) -> Result<(), PytjaError> {
        let config_path = "mounts.json";

        // 1. Cache im RAM aktualisieren (schnell)
        let configs_copy;
        {
            let mut cache = self.config_cache.write().unwrap();

            if let Some(existing) = cache.iter_mut().find(|c| c.name == name) {
                existing.path = path.to_string();
                existing.db_type = db_type;
            } else {
                cache.push(MountConfig {
                    name: name.to_string(),
                    path: path.to_string(),
                    db_type,
                });
            }
            configs_copy = cache.clone(); // Kopie für Async Write erstellen, damit Lock frei wird
        }

        // 2. JSON generieren
        let json = serde_json::to_string_pretty(&configs_copy)
            .map_err(|e| PytjaError::System(format!("Serialization error: {}", e)))?;

        // 3. Atomic Write Pattern (Async I/O)
        let temp_path = format!("{}.tmp", config_path);

        if let Err(e) = fs::write(&temp_path, &json).await {
            return Err(PytjaError::System(format!("Failed to write temp config: {}", e)));
        }

        if let Err(e) = fs::rename(&temp_path, config_path).await {
            return Err(PytjaError::System(format!("Failed to commit config file: {}", e)));
        }

        info!("Persisted configuration to {}", config_path);
        Ok(())
    }

    pub async fn unmount(&self, name: &str) -> Result<(), PytjaError> {
        // Memory cleanup
        {
            let mut map = self.connections.write().unwrap();
            if map.remove(name).is_none() {
                return Err(PytjaError::NotFound(format!("Database '{}' not found", name)));
            }
        }

        // Config cleanup
        let config_path = "mounts.json";
        let configs_copy;

        {
            let mut cache = self.config_cache.write().unwrap();
            if let Some(pos) = cache.iter().position(|c| c.name == name) {
                cache.remove(pos);
                configs_copy = Some(cache.clone());
            } else {
                configs_copy = None;
            }
        }

        if let Some(cfg) = configs_copy {
            let json = serde_json::to_string_pretty(&cfg)
                .map_err(|e| PytjaError::System(format!("Serialization error: {}", e)))?;

            let temp_path = format!("{}.tmp", config_path);
            let _ = fs::write(&temp_path, &json).await;
            let _ = fs::rename(&temp_path, config_path).await;

            info!("Unmounted '{}' and removed from config.", name);
        }

        Ok(())
    }

    // High-Performance Sync Reads (Kein .await nötig im Server Code!)

    pub fn get_repo(&self, name: &str) -> Option<Arc<dyn PytjaRepository>> {
        let map = self.connections.read().unwrap();
        map.get(name).cloned()
    }

    pub fn list_mounts(&self) -> Vec<String> {
        let map = self.connections.read().unwrap();
        map.keys().cloned().collect()
    }
}