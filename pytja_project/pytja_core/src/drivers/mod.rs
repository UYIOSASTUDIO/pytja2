pub mod sqlite;
pub mod postgres;
// pub mod postgres; // Kommt im nächsten Enterprise-Schritt

use crate::repo::PytjaRepository;
use crate::error::PytjaError;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::fs;
use tokio::fs;
use tracing::{info, warn, error};

// Enterprise Database Support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseType {
    Sqlite,
    Postgres, // Vorbereitet für SAP/Enterprise Integration
    MySQL,    // Vorbereitet
}

#[derive(Serialize, Deserialize, Clone)]
struct MountConfig {
    name: String,
    path: String,
    db_type: DatabaseType,
}

/// Der DriverManager verwaltet alle aktiven Datenbank-Verbindungen.
/// Er abstrahiert die darunterliegende Technologie (SQLite, Postgres, Oracle).
pub struct DriverManager {
    connections: Arc<RwLock<HashMap<String, Arc<dyn PytjaRepository>>>>,
}

impl DriverManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Lädt die Konfiguration asynchron.
    /// Da dies oft beim Server-Start passiert, ist es wichtig, Fehler nur zu loggen und nicht abzustürzen.
    /// Lädt die Konfiguration asynchron beim Start.
    pub async fn load_config(&self, config_path: &str) {
        info!("Loading configuration from '{}'", config_path);

        match fs::read_to_string(config_path).await {
            Ok(content) => {
                match serde_json::from_str::<Vec<MountConfig>>(&content) {
                    Ok(configs) => {
                        info!("Found {} mount definitions.", configs.len());
                        for cfg in configs {
                            // save=false verhindert Endlosschleifen beim Laden
                            if let Err(e) = self.mount_internal(&cfg.name, &cfg.path, cfg.db_type, false).await {
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

    /// Öffentliche Methode zum Mounten einer neuen DB. Speichert die Config persistent.
    pub async fn mount(&self, name: &str, path: &str, db_type: DatabaseType) -> Result<(), PytjaError> {
        self.mount_internal(name, path, db_type, true).await
    }

    async fn mount_internal(&self, name: &str, path: &str, db_type: DatabaseType, save: bool) -> Result<(), PytjaError> {
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

        // In-Memory registrieren (Sync Lock ist hier okay da kurzzeitig)
        {
            let mut map = self.connections.write().unwrap();
            map.insert(name.to_string(), repo);
        }
        info!("Mounted database '{}' type {:?}", name, db_type);

        // Persistent speichern (Atomic & Async)
        if save {
            self.persist_mount(name, path, db_type).await?;
        }

        Ok(())
    }

    /// Speichert die Konfiguration atomar auf der Festplatte.
    async fn persist_mount(&self, name: &str, path: &str, db_type: DatabaseType) -> Result<(), PytjaError> {
        let config_path = "mounts.json";
        let temp_path = "mounts.json.tmp";

        // 1. Bestehende Config lesen (oder leer starten)
        let mut configs: Vec<MountConfig> = match fs::read_to_string(config_path).await {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        let new_entry = MountConfig {
            name: name.to_string(),
            path: path.to_string(),
            db_type,
        };

        // 2. Eintrag aktualisieren oder hinzufügen
        if let Some(existing) = configs.iter_mut().find(|c| c.name == name) {
            *existing = new_entry;
        } else {
            configs.push(new_entry);
        }

        // 3. Serialisieren
        let json = serde_json::to_string_pretty(&configs)
            .map_err(|e| PytjaError::System(format!("Serialization error: {}", e)))?;

        // 4. Atomic Write Pattern (Write .tmp -> Rename)
        // Das verhindert korrupte Config-Dateien bei Abstürzen
        if let Err(e) = fs::write(temp_path, &json).await {
            return Err(PytjaError::System(format!("Failed to write temp config: {}", e)));
        }

        if let Err(e) = fs::rename(temp_path, config_path).await {
            return Err(PytjaError::System(format!("Failed to commit config file: {}", e)));
        }

        info!("Persisted configuration to {}", config_path);
        Ok(())
    }

    pub fn unmount(&self, name: &str) -> Result<(), PytjaError> {
        let mut map = self.connections.write().unwrap();
        if map.remove(name).is_some() {
            // TODO: Auch aus mounts.json entfernen für Perfektion
            info!("Unmounted database '{}'", name);
            Ok(())
        } else {
            Err(PytjaError::NotFound(format!("Database '{}' not found", name)))
        }
    }

    pub fn get_repo(&self, name: &str) -> Option<Arc<dyn PytjaRepository>> {
        let map = self.connections.read().unwrap();
        map.get(name).cloned()
    }

    pub fn list_mounts(&self) -> Vec<String> {
        let map = self.connections.read().unwrap();
        map.keys().cloned().collect()
    }
}