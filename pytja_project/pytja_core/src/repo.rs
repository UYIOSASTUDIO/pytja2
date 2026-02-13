use crate::models::{User, FileNode, AuditLogEntry};
use crate::error::PytjaError;
use rusqlite::{params, OptionalExtension};
use async_trait::async_trait;
use tracing::{info, instrument};
use deadpool_sqlite::{Config, Manager, Pool, Runtime};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::fs;

#[async_trait]
pub trait PytjaRepository: Send + Sync {
    fn init(&self) -> Result<(), PytjaError>;

    async fn create_user(&self, user: &User) -> Result<(), PytjaError>;
    async fn get_user(&self, username: &str) -> Result<Option<User>, PytjaError>;
    async fn user_exists(&self, username: &str) -> Result<bool, PytjaError>;

    async fn save_node(&self, node: &FileNode) -> Result<(), PytjaError>;
    async fn get_node(&self, path: &str) -> Result<Option<FileNode>, PytjaError>;
    async fn list_directory(&self, path: &str) -> Result<Vec<FileNode>, PytjaError>;
    async fn delete_node_recursive(&self, path: &str) -> Result<(), PytjaError>;
    async fn get_total_usage(&self, owner: &str) -> Result<usize, PytjaError>;

    async fn move_path(&self, old_path: &str, new_path: &str) -> Result<(), PytjaError>;
    async fn update_metadata(&self, path: &str, lock: Option<String>, owner: Option<String>) -> Result<(), PytjaError>;

    async fn find_nodes(&self, pattern: &str) -> Result<Vec<String>, PytjaError>;
    async fn get_all_files_content(&self) -> Result<Vec<(String, Vec<u8>)>, PytjaError>;
    async fn log_action(&self, actor: &str, action: &str, target: &str) -> Result<(), PytjaError>;
    async fn update_permissions(&self, path: &str, permissions: u8) -> Result<(), PytjaError>;
    async fn get_all_users(&self) -> Result<Vec<User>, PytjaError>;
    async fn get_audit_logs(&self, limit: usize) -> Result<Vec<AuditLogEntry>, PytjaError>;
    async fn update_user_status(&self, username: &str, is_active: bool, role_level: i32) -> Result<(), PytjaError>;
}

#[derive(Clone)]
pub struct SqliteRepository {
    pool: Pool,
    path: String,
}

impl SqliteRepository {
    pub fn new(path: &str) -> Self {
        let cfg = Config::new(path);
        let manager = Manager::from_config(&cfg, Runtime::Tokio1);
        let pool = Pool::builder(manager)
            .max_size(16)
            .build()
            .expect("Failed to create database pool");

        Self {
            pool,
            path: path.to_string()
        }
    }
}

#[async_trait]
impl PytjaRepository for SqliteRepository {
    #[instrument(skip(self))]
    fn init(&self) -> Result<(), PytjaError> {
        let conn = rusqlite::Connection::open(&self.path)
            .map_err(|e| PytjaError::DatabaseConnection(e.to_string()))?;

        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                description TEXT,
                role_level INTEGER,
                is_active INTEGER,
                created_at TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS file_system (
                        path TEXT PRIMARY KEY,
                        name TEXT,
                        owner TEXT,
                        is_folder INTEGER,
                        content BLOB,
                        lock_pass TEXT,
                        permissions INTEGER DEFAULT 0,
                        created_at REAL
                    )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                actor TEXT,
                action TEXT,
                target TEXT
            )",
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_files_path ON file_system(path)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_files_owner ON file_system(owner)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)", [])?;

        info!("Pytja Database initialized successfully (Sync Mode)");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn find_nodes(&self, pattern: &str) -> Result<Vec<String>, PytjaError> {
        let pattern = pattern.to_string();
        let conn = self.pool.get().await?;

        // Expliziter Typ für Closure Parameter!
        conn.interact(move |conn: &mut rusqlite::Connection| {
            let mut stmt = conn.prepare("SELECT path FROM file_system WHERE name LIKE ?")?;
            let rows = stmt.query_map(params![pattern], |row| row.get(0))?;

            let mut paths = Vec::new();
            for r in rows { paths.push(r?); }
            Ok(paths)
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn get_all_files_content(&self) -> Result<Vec<(String, Vec<u8>)>, PytjaError> {
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            let mut stmt = conn.prepare("SELECT path, content FROM file_system WHERE is_folder = 0")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;

            let mut results = Vec::new();
            for r in rows { results.push(r?); }
            Ok(results)
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn log_action(&self, actor: &str, action: &str, target: &str) -> Result<(), PytjaError> {
        let actor = actor.to_string();
        let action = action.to_string();
        let target = target.to_string();
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            let now = chrono::Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO audit_logs (timestamp, actor, action, target) VALUES (?1, ?2, ?3, ?4)",
                params![now, actor, action, target],
            )?;
            Ok(())
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self, user), fields(username = %user.username))]
    async fn create_user(&self, user: &User) -> Result<(), PytjaError> {
        let conn = self.pool.get().await?;
        let u = user.clone();

        conn.interact(move |conn: &mut rusqlite::Connection| {
            conn.execute(
                "INSERT INTO users (username, public_key, role_level, created_at, description, is_active)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    u.username, u.public_key, u.role_level, u.created_at, u.description, u.is_active
                ],
            )?;
            Ok(())
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn get_user(&self, username: &str) -> Result<Option<User>, PytjaError> {
        let username = username.to_string();
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            let mut stmt = conn.prepare("SELECT username, public_key, description, role_level, is_active, created_at FROM users WHERE username = ?")?;
            let user = stmt.query_row(params![username], |row| {
                Ok(User {
                    username: row.get(0)?,
                    public_key: row.get(1)?,
                    description: row.get(2)?,
                    role_level: row.get(3)?,
                    is_active: row.get(4)?,
                    created_at: row.get(5)?,
                })
            }).optional()?;
            Ok(user)
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn user_exists(&self, username: &str) -> Result<bool, PytjaError> {
        let username = username.to_string();
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            let count: i32 = conn.query_row(
                "SELECT COUNT(*) FROM users WHERE username = ?",
                params![username],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self, node), fields(path = %node.path))]
    async fn save_node(&self, node: &FileNode) -> Result<(), PytjaError> {
        let node = node.clone();
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            conn.execute(
                "INSERT OR REPLACE INTO file_system (path, name, owner, is_folder, content, lock_pass, permissions, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    node.path, node.name, node.owner, node.is_folder,
                    node.content, node.lock_pass, node.permissions,
                    node.created_at
                ],
            )?;
            Ok(())
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn get_node(&self, path: &str) -> Result<Option<FileNode>, PytjaError> {
        let path = path.to_string();
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            let mut stmt = conn.prepare("SELECT path, name, owner, is_folder, content, lock_pass, permissions, created_at FROM file_system WHERE path = ?")?;
            let node = stmt.query_row(params![path], |row| {
                Ok(FileNode {
                    path: row.get(0)?,
                    name: row.get(1)?,
                    owner: row.get(2)?,
                    is_folder: row.get(3)?,
                    content: row.get(4)?,
                    size: row.get::<_, Vec<u8>>(4)?.len(),
                    lock_pass: row.get(5)?,
                    permissions: row.get(6)?,
                    created_at: row.get(7)?,
                })
            }).optional()?;
            Ok(node)
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn list_directory(&self, path: &str) -> Result<Vec<FileNode>, PytjaError> {
        let current_path = path.to_string();
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            let query_path = if current_path == "/" { "".to_string() } else { current_path.clone() };

            let mut stmt = conn.prepare(
                "SELECT path, name, owner, is_folder, created_at, lock_pass, permissions, LENGTH(content)
                 FROM file_system
                 WHERE path LIKE ? || '/%' AND path NOT LIKE ? || '/%/%'"
            )?;

            let param1 = query_path.clone();
            let param2 = query_path.clone();

            let rows = stmt.query_map(params![param1, param2], |row| {
                Ok(FileNode {
                    path: row.get(0)?,
                    name: row.get(1)?,
                    owner: row.get(2)?,
                    is_folder: row.get(3)?,
                    content: Vec::new(),
                    size: row.get(7)?,
                    lock_pass: row.get(5)?,
                    permissions: row.get(6)?,
                    created_at: row.get(4)?,
                })
            })?;

            let mut nodes = Vec::new();
            for r in rows { nodes.push(r?); }
            Ok(nodes)
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn delete_node_recursive(&self, path: &str) -> Result<(), PytjaError> {
        let path = path.to_string();
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            let like_pattern = format!("{}/%", path);
            conn.execute(
                "DELETE FROM file_system WHERE path = ? OR path LIKE ?",
                params![path, like_pattern]
            )?;
            Ok(())
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn get_total_usage(&self, owner: &str) -> Result<usize, PytjaError> {
        let owner = owner.to_string();
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            let size: Option<usize> = conn.query_row(
                "SELECT SUM(LENGTH(content)) FROM file_system WHERE owner = ?",
                params![owner],
                |row| row.get(0)
            ).optional()?;
            Ok(size.unwrap_or(0))
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn move_path(&self, old_path: &str, new_path: &str) -> Result<(), PytjaError> {
        let old_path = old_path.to_string();
        let new_path = new_path.to_string();
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            conn.execute(
                "UPDATE file_system
                 SET path = ?2 || SUBSTR(path, LENGTH(?1) + 1)
                 WHERE path = ?1 OR path LIKE ?1 || '/%'",
                params![old_path, new_path]
            )?;
            Ok(())
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn update_metadata(&self, path: &str, lock: Option<String>, owner: Option<String>) -> Result<(), PytjaError> {
        let path = path.to_string();
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            if let Some(l) = lock {
                conn.execute("UPDATE file_system SET lock_pass = ? WHERE path = ?", params![l, path])?;
            }
            if let Some(o) = owner {
                conn.execute("UPDATE file_system SET owner = ? WHERE path = ?", params![o, path])?;
            }
            Ok(())
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn update_permissions(&self, path: &str, permissions: u8) -> Result<(), PytjaError> {
        let path = path.to_string();
        let conn = self.pool.get().await?;

        conn.interact(move |conn: &mut rusqlite::Connection| {
            conn.execute(
                "UPDATE file_system SET permissions = ? WHERE path = ?",
                params![permissions, path]
            )?;
            Ok(())
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn get_all_users(&self) -> Result<Vec<User>, PytjaError> {
        let conn = self.pool.get().await?;

        conn.interact(move |conn| {
            let mut stmt = conn.prepare("SELECT username, public_key, description, role_level, is_active, created_at FROM users")?;

            let rows = stmt.query_map([], |row| {
                Ok(User {
                    username: row.get(0)?,
                    public_key: row.get(1)?,
                    description: row.get(2)?,
                    role_level: row.get(3)?,
                    is_active: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })?;

            let mut users = Vec::new();
            for r in rows { users.push(r?); }
            Ok(users)
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn get_audit_logs(&self, limit: usize) -> Result<Vec<AuditLogEntry>, PytjaError> {
        let conn = self.pool.get().await?;

        conn.interact(move |conn| {
            // Wir sortieren absteigend (neueste zuerst)
            let mut stmt = conn.prepare("SELECT id, timestamp, actor, action, target FROM audit_logs ORDER BY id DESC LIMIT ?")?;

            let rows = stmt.query_map(params![limit], |row| {
                Ok(AuditLogEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    target: row.get(4)?,
                })
            })?;

            let mut logs = Vec::new();
            for r in rows { logs.push(r?); }
            Ok(logs)
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }

    #[instrument(skip(self))]
    async fn update_user_status(&self, username: &str, is_active: bool, role_level: i32) -> Result<(), PytjaError> {
        let username = username.to_string();
        let conn = self.pool.get().await?;

        conn.interact(move |conn| {
            conn.execute(
                "UPDATE users SET is_active = ?1, role_level = ?2 WHERE username = ?3",
                params![is_active, role_level, username],
            )?;
            Ok(())
        }).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use std::fs;

    // Hilfsfunktion: Erstellt eine wegwerfbare Test-Datenbank
    fn setup_test_db() -> (SqliteRepository, String) {
        let db_name = format!("test_db_{}.sqlite", Uuid::new_v4());
        let repo = SqliteRepository::new(&db_name);
        repo.init().expect("Init failed");
        (repo, db_name)
    }

    // Hilfsfunktion: Löscht die Test-Datenbank nach dem Test
    fn teardown(db_name: &str) {
        let _ = fs::remove_file(db_name);
    }

    #[tokio::test]
    async fn test_full_workflow() {
        // 1. Setup
        let (repo, db_path) = setup_test_db();
        let user = User {
            username: "agent_test".to_string(),
            public_key: "key123".to_string(),
            description: None,
            role_level: 1,
            is_active: true,
            created_at: "2026-01-01".to_string(),
        };

        // 2. User erstellen & prüfen
        repo.create_user(&user).await.expect("Create user failed");
        let loaded_user = repo.get_user("agent_test").await.expect("DB Error").unwrap();
        assert_eq!(loaded_user.public_key, "key123");

        // 3. Datei erstellen
        let file = FileNode {
            path: "/secret_plans.txt".to_string(),
            name: "secret_plans.txt".to_string(),
            owner: "agent_test".to_string(),
            is_folder: false,
            size: 12,
            content: b"Hello Pytja".to_vec(),
            lock_pass: None,
            created_at: 123456.0,
        };
        repo.save_node(&file).await.expect("Save node failed");

        // 4. Datei lesen
        let loaded_file = repo.get_node("/secret_plans.txt").await.expect("DB Error").unwrap();
        assert_eq!(loaded_file.content, b"Hello Pytja");

        // 5. Ordner auflisten
        let list = repo.list_directory("/").await.expect("List failed");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "secret_plans.txt");

        // 6. Aufräumen (Teardown)
        // Wir droppen den Pool explizit, damit die Datei nicht gelockt ist (bei Windows wichtig)
        drop(repo);
        teardown(&db_path);
    }

    #[tokio::test]
    async fn test_quota_calculation() {
        let (repo, db_path) = setup_test_db();

        let file1 = FileNode {
            path: "/a".to_string(), name: "a".to_string(), owner: "user1".to_string(),
            is_folder: false, size: 100, content: vec![0; 100], lock_pass: None, created_at: 0.0
        };
        let file2 = FileNode {
            path: "/b".to_string(), name: "b".to_string(), owner: "user1".to_string(),
            is_folder: false, size: 50, content: vec![0; 50], lock_pass: None, created_at: 0.0
        };

        repo.save_node(&file1).await.unwrap();
        repo.save_node(&file2).await.unwrap();

        let usage = repo.get_total_usage("user1").await.unwrap();
        assert_eq!(usage, 150);

        teardown(&db_path);
    }

}

#[derive(Clone)]
pub enum DatabaseType {
    Sqlite,
    Postgres, // Platzhalter für deine Vision
    MySQL,    // Platzhalter
}

// Der Hub-Manager
pub struct ConnectionManager {
    mounts: Arc<RwLock<HashMap<String, Arc<dyn PytjaRepository + Send + Sync>>>>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct MountConfig {
    name: String,
    path: String,
    db_type: String, // Das Feld hat beim Initialisieren gefehlt
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            mounts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // DIESE METHODE HAT GEFEHLT ODER WAR NICHT PUBLIC:
    pub fn load_config(&self, config_path: &str) {
        if let Ok(content) = fs::read_to_string(config_path) {
            if let Ok(configs) = serde_json::from_str::<Vec<MountConfig>>(&content) {
                println!("Loading {} mounts from config...", configs.len());
                for cfg in configs {
                    // Wir ignorieren Fehler beim Laden (z.B. wenn DB gelöscht wurde)
                    let _ = self.mount_internal(&cfg.name, &cfg.path, false);
                }
            }
        }
    }

    pub fn mount(&self, name: &str, path: &str, _db_type: DatabaseType) -> Result<(), PytjaError> {
        self.mount_internal(name, path, true)
    }

    fn mount_internal(&self, name: &str, path: &str, save: bool) -> Result<(), PytjaError> {
        let repo = SqliteRepository::new(path);
        repo.init()?;

        {
            let mut mounts = self.mounts.write().unwrap();
            mounts.insert(name.to_string(), Arc::new(repo));
        }

        if save {
            let config_path = "mounts.json";
            let mut configs: Vec<MountConfig> = Vec::new();

            if let Ok(content) = fs::read_to_string(config_path) {
                if let Ok(old) = serde_json::from_str::<Vec<MountConfig>>(&content) {
                    configs = old;
                }
            }

            if let Some(existing) = configs.iter_mut().find(|c| c.name == name) {
                existing.path = path.to_string();
                existing.db_type = "sqlite".to_string();
            } else {
                configs.push(MountConfig {
                    name: name.to_string(),
                    path: path.to_string(),
                    db_type: "sqlite".to_string(),
                });
            }

            if let Ok(json) = serde_json::to_string_pretty(&configs) {
                let _ = fs::write(config_path, json);
            }
        }
        Ok(())
    }

    pub fn unmount(&self, name: &str) -> Result<(), PytjaError> {
        let mut mounts = self.mounts.write().unwrap();
        if mounts.remove(name).is_some() {
            Ok(())
        } else {
            Err(PytjaError::NotFound(format!("Database '{}' not mounted", name)))
        }
    }

    pub fn get_repo(&self, name: &str) -> Option<Arc<dyn PytjaRepository + Send + Sync>> {
        let mounts = self.mounts.read().unwrap();
        mounts.get(name).cloned()
    }

    pub fn list_mounts_details(&self) -> Vec<(String, String)> {
        let mounts = self.mounts.read().unwrap();
        mounts.keys().map(|k| (k.clone(), "Mounted".to_string())).collect()
    }

    pub fn list_mounts(&self) -> Vec<String> {
        let mounts = self.mounts.read().unwrap();
        mounts.keys().cloned().collect()
    }

    #[allow(dead_code)]
    fn save_config(&self) {}
}