use crate::repo::{PytjaRepository, SqliteRepository};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub enum DatabaseType {
    Sqlite,
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

    pub fn mount(&self, name: &str, connection_string: &str, db_type: DatabaseType) -> Result<()> {
        let repo: Arc<dyn PytjaRepository> = match db_type {
            DatabaseType::Sqlite => {
                let db = SqliteRepository::new(connection_string);
                Arc::new(db)
            }
        };

        let mut map = self.connections.write().map_err(|_| anyhow!("Lock Poisoned"))?;
        map.insert(name.to_string(), repo);
        Ok(())
    }

    pub fn get_repo(&self, mount_name: &str) -> Result<Arc<dyn PytjaRepository>> {
        let map = self.connections.read().map_err(|_| anyhow!("Lock Poisoned"))?;

        if let Some(repo) = map.get(mount_name) {
            Ok(repo.clone())
        } else {
            Err(anyhow!("Database '{}' is not mounted/connected.", mount_name))
        }
    }

    pub fn list_mounts(&self) -> Vec<String> {
        let map = self.connections.read().unwrap();
        map.keys().cloned().collect()
    }
}