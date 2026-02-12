use crate::repo::{PytjaRepository, SqliteRepository};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// Wir definieren verschiedene Datenbank-Typen für die Zukunft
#[derive(Debug, Clone)]
pub enum DatabaseType {
    Sqlite,
    // Später: Postgres, MySQL, InMemory, etc.
}

// Der Manager verwaltet alle offenen Verbindungen
pub struct ConnectionManager {
    // Map: "Mount Name" (z.B. "local", "company_db") -> Repository
    // Wir nutzen Arc<Box<...>>, um Polymorphismus zu ermöglichen (verschiedene Treiber gemischt)
    connections: Arc<RwLock<HashMap<String, Arc<dyn PytjaRepository>>>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Verbindet eine neue Datenbank und "mountet" sie unter einem Namen
    pub fn mount(&self, name: &str, connection_string: &str, db_type: DatabaseType) -> Result<()> {
        let repo: Arc<dyn PytjaRepository> = match db_type {
            DatabaseType::Sqlite => {
                let db = SqliteRepository::new(connection_string);
                db.init()?; // Initialisieren beim Mounten
                Arc::new(db)
            }
            // Hier fügen wir später Postgres hinzu
        };

        let mut map = self.connections.write().map_err(|_| anyhow!("Lock Poisoned"))?;
        map.insert(name.to_string(), repo);
        Ok(())
    }

    /// Holt die richtige Datenbank für einen Zugriff
    pub fn get_repo(&self, mount_name: &str) -> Result<Arc<dyn PytjaRepository>> {
        let map = self.connections.read().map_err(|_| anyhow!("Lock Poisoned"))?;

        if let Some(repo) = map.get(mount_name) {
            Ok(repo.clone())
        } else {
            Err(anyhow!("Database '{}' is not mounted/connected.", mount_name))
        }
    }

    /// Listet alle verbundenen Datenbanken auf
    pub fn list_mounts(&self) -> Vec<String> {
        let map = self.connections.read().unwrap();
        map.keys().cloned().collect()
    }
}