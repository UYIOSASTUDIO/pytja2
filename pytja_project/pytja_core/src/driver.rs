use crate::repo::{PytjaRepository, SqliteRepository};
use crate::error::PytjaError;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::fs;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum DatabaseType {
    Sqlite,
}

// Struct zum Speichern in JSON
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct MountConfig {
    name: String,
    path: String,
    db_type: DatabaseType,
}

pub struct ConnectionManager {
    connections: Arc<RwLock<HashMap<String, Arc<dyn PytjaRepository>>>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Lädt die Konfiguration aus der JSON Datei (DAS HAT GEFEHLT!)
    pub fn load_config(&self, config_path: &str) {
        if let Ok(content) = fs::read_to_string(config_path) {
            if let Ok(configs) = serde_json::from_str::<Vec<MountConfig>>(&content) {
                println!("Loading {} mounts from config...", configs.len());
                for cfg in configs {
                    // Fehler beim Laden ignorieren wir (z.B. DB gelöscht)
                    let _ = self.mount_internal(&cfg.name, &cfg.path, cfg.db_type, false);
                }
            }
        }
    }

    /// Öffentliche Mount-Funktion (Speichert automatisch)
    pub fn mount(&self, name: &str, connection_string: &str, db_type: DatabaseType) -> Result<(), PytjaError> {
        self.mount_internal(name, connection_string, db_type, true)
    }

    /// Interne Logik mit Speicher-Option
    fn mount_internal(&self, name: &str, path: &str, db_type: DatabaseType, save: bool) -> Result<(), PytjaError> {
        // 1. Repo erstellen
        let repo: Arc<dyn PytjaRepository> = match db_type {
            DatabaseType::Sqlite => {
                let db = SqliteRepository::new(path);
                // Init aufrufen, damit Tabellen da sind
                db.init()?;
                Arc::new(db)
            }
        };

        // 2. In Map einfügen
        {
            let mut map = self.connections.write().map_err(|_| PytjaError::System("Lock Poisoned".to_string()))?;
            map.insert(name.to_string(), repo);
        }

        // 3. Speichern (wenn gewünscht)
        if save {
            let config_path = "mounts.json";
            let mut configs: Vec<MountConfig> = Vec::new();

            if let Ok(content) = fs::read_to_string(config_path) {
                if let Ok(old) = serde_json::from_str::<Vec<MountConfig>>(&content) {
                    configs = old;
                }
            }

            // Update oder Insert
            let new_entry = MountConfig {
                name: name.to_string(),
                path: path.to_string(),
                db_type: db_type.clone(),
            };

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

    pub fn get_repo(&self, mount_name: &str) -> Result<Arc<dyn PytjaRepository>, PytjaError> {
        let map = self.connections.read().map_err(|_| PytjaError::System("Lock Poisoned".to_string()))?;

        if let Some(repo) = map.get(mount_name) {
            Ok(repo.clone())
        } else {
            Err(PytjaError::NotFound(format!("Database '{}' is not mounted.", mount_name)))
        }
    }

    pub fn list_mounts(&self) -> Vec<String> {
        let map = self.connections.read().unwrap();
        map.keys().cloned().collect()
    }
}