pub mod sqlite;
pub mod postgres;

use crate::repo::PytjaRepository;
use crate::error::PytjaError;
use std::sync::Arc;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use tokio::fs;
use tokio::sync::RwLock; // WICHTIG: Async Lock für 100% Non-Blocking
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
    // Async RwLock: Verhindert, dass Reader/Writer den Thread blockieren
    connections: Arc<RwLock<HashMap<String, Arc<dyn PytjaRepository>>>>,
    config_cache: Arc<RwLock<Vec<MountConfig>>>,
    config_file_path: Arc<RwLock<String>>,
}

impl Default for DriverManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DriverManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            config_cache: Arc::new(RwLock::new(Vec::new())),
            config_file_path: Arc::new(RwLock::new("mounts.json".to_string())),
        }
    }

    /// Lädt die Konfiguration asynchron beim Start.
    pub async fn load_config(&self, config_path: &str) {
        info!("Loading configuration from '{}'", config_path);

        // Pfad speichern für spätere Writes (Async Lock)
        {
            let mut p = self.config_file_path.write().await;
            *p = config_path.to_string();
        }

        // Asynchrones Lesen der Datei
        match fs::read_to_string(config_path).await {
            Ok(content) => {
                match serde_json::from_str::<Vec<MountConfig>>(&content) {
                    Ok(configs) => {
                        info!("Found {} mount definitions.", configs.len());

                        // Cache updaten
                        {
                            let mut cache = self.config_cache.write().await;
                            *cache = configs.clone();
                        }

                        // Mounts ausführen
                        for cfg in configs {
                            if let Err(e) = self.mount_internal(&cfg.name, &cfg.path, cfg.db_type.clone(), false).await {
                                error!("Failed to mount database '{}': {}", cfg.name, e);
                            }
                        }
                    },
                    Err(e) => warn!("Could not parse mounts.json: {}", e),
                }
            },
            Err(_) => warn!("No mounts.json found at '{}'. Starting with empty configuration.", config_path),
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

        // In-Memory registrieren (Async Lock)
        {
            let mut map = self.connections.write().await;
            map.insert(name.to_string(), repo);
        }
        info!("Mounted database '{}' ({:?})", name, db_type);

        // Persistent speichern
        if save_to_disk {
            self.persist_mount(name, path, db_type).await?;
        }

        Ok(())
    }

    /// Speichert Config atomar (Async Write + Rename)
    async fn persist_mount(&self, name: &str, path: &str, db_type: DatabaseType) -> Result<(), PytjaError> {
        // Pfad holen (Async Lock)
        let config_path = {
            let p = self.config_file_path.read().await;
            p.clone()
        };

        // 1. Cache aktualisieren
        let configs_copy;
        {
            let mut cache = self.config_cache.write().await;

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
            configs_copy = cache.clone();
        }

        // 2. JSON generieren
        let json = serde_json::to_string_pretty(&configs_copy)
            .map_err(|e| PytjaError::System(format!("Serialization error: {}", e)))?;

        // 3. Atomic Write Pattern
        let temp_path = format!("{}.tmp", config_path);

        if let Err(e) = fs::write(&temp_path, &json).await {
            return Err(PytjaError::System(format!("Failed to write temp config: {}", e)));
        }

        if let Err(e) = fs::rename(&temp_path, &config_path).await {
            return Err(PytjaError::System(format!("Failed to commit config file: {}", e)));
        }

        info!("Persisted configuration to {}", config_path);
        Ok(())
    }

    pub async fn unmount(&self, name: &str) -> Result<(), PytjaError> {
        // Pfad holen
        let config_path = {
            let p = self.config_file_path.read().await;
            p.clone()
        };

        // Memory cleanup (Async Lock)
        {
            let mut map = self.connections.write().await;
            if map.remove(name).is_none() {
                return Err(PytjaError::NotFound(format!("Database '{}' not found", name)));
            }
        }

        // Config cleanup
        let configs_copy;
        {
            let mut cache = self.config_cache.write().await;
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

    // Zugriffsmethoden sind jetzt ASYNC für 100% Non-Blocking

    pub async fn get_repo(&self, name: &str) -> Option<Arc<dyn PytjaRepository>> {
        let map = self.connections.read().await;
        map.get(name).cloned()
    }

    pub async fn list_mounts(&self) -> Vec<String> {
        let map = self.connections.read().await;
        map.keys().cloned().collect()
    }

    pub async fn get_mount_configs(&self) -> Vec<MountConfig> {
        let cache = self.config_cache.read().await;
        cache.clone()
    }
}