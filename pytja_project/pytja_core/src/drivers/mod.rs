pub mod sqlite;
pub mod postgres;
// pub mod postgres; // Kommt im nächsten Enterprise-Schritt

use crate::repo::PytjaRepository;
use crate::error::PytjaError;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::fs;
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
    pub async fn load_config(&self, config_path: &str) {
        if let Ok(content) = fs::read_to_string(config_path) {
            if let Ok(configs) = serde_json::from_str::<Vec<MountConfig>>(&content) {
                info!("Loading {} mounts from config...", configs.len());
                for cfg in configs {
                    if let Err(e) = self.mount_internal(&cfg.name, &cfg.path, cfg.db_type, false).await {
                        error!("Failed to mount {}: {}", cfg.name, e);
                    }
                }
            } else {
                warn!("Could not parse mounts.json");
            }
        }
    }

    /// Öffentliche Methode zum Mounten einer neuen DB. Speichert die Config persistent.
    pub async fn mount(&self, name: &str, path: &str, db_type: DatabaseType) -> Result<(), PytjaError> {
        self.mount_internal(name, path, db_type, true).await
    }

    /// Interne Logik: Erstellt den Treiber und speichert ihn in der Map.
    async fn mount_internal(&self, name: &str, path: &str, db_type: DatabaseType, save: bool) -> Result<(), PytjaError> {
        let repo: Arc<dyn PytjaRepository> = match db_type {
            DatabaseType::Sqlite => {
                let driver = sqlite::SqliteDriver::new(path).await?;
                driver.init().await?;
                Arc::new(driver)
            },
            DatabaseType::Postgres => {
                // Connection String wird als "path" übergeben
                let driver = postgres::PostgresDriver::new(path).await?;
                driver.init().await?;
                Arc::new(driver)
            },
            _ => return Err(PytjaError::System("Unsupported DB".into())),
        };

        // In-Memory registrieren
        {
            let mut map = self.connections.write().unwrap();
            map.insert(name.to_string(), repo);
        }
        info!("Mounted database '{}' type {:?}", name, db_type);

        // Persistent speichern (JSON)
        if save {
            let config_path = "mounts.json";
            let mut configs: Vec<MountConfig> = Vec::new();

            if let Ok(content) = fs::read_to_string(config_path) {
                if let Ok(old) = serde_json::from_str::<Vec<MountConfig>>(&content) {
                    configs = old;
                }
            }

            let new_entry = MountConfig {
                name: name.to_string(),
                path: path.to_string(),
                db_type: db_type.clone(),
            };

            // Update existierenden Eintrag oder füge neu hinzu
            if let Some(existing) = configs.iter_mut().find(|c| c.name == name) {
                *existing = new_entry;
            } else {
                configs.push(new_entry);
            }

            if let Ok(json) = serde_json::to_string_pretty(&configs) {
                let _ = fs::write(config_path, json);
            }
        }

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