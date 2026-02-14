use crate::repo::PytjaRepository;
use crate::models::{User, FileNode, AuditLogEntry};
use crate::error::PytjaError;
use async_trait::async_trait;
use sqlx::{SqlitePool, Row};
use sqlx::sqlite::SqliteConnectOptions;
use std::str::FromStr;
use tracing::info;

#[derive(Clone)]
pub struct SqliteDriver {
    pool: SqlitePool,
}

impl SqliteDriver {
    pub async fn new(path: &str) -> Result<Self, PytjaError> {
        let conn_str = format!("sqlite://{}", path);
        let options = SqliteConnectOptions::from_str(&conn_str)
            .map_err(|e| PytjaError::System(format!("Connection string error: {}", e)))?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

        let pool = SqlitePool::connect_with(options).await
            .map_err(|e| PytjaError::DatabaseConnection(e.to_string()))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl PytjaRepository for SqliteDriver {
    async fn init(&self) -> Result<(), PytjaError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                description TEXT,
                role_level INTEGER,
                is_active BOOLEAN,
                created_at TEXT
            )"
        ).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        // UPDATE: blob_id hinzugefügt!
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS file_system (
                path TEXT PRIMARY KEY,
                name TEXT,
                owner TEXT,
                is_folder BOOLEAN,
                content BLOB,
                blob_id TEXT, -- NEU FÜR OBJECT STORAGE
                lock_pass TEXT,
                permissions INTEGER DEFAULT 0,
                created_at REAL
            )"
        ).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                actor TEXT,
                action TEXT,
                target TEXT
            )"
        ).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        info!("SQLite DB initialized (Enterprise Schema)");
        Ok(())
    }

    // --- USER MANAGEMENT ---

    async fn create_user(&self, user: &User) -> Result<(), PytjaError> {
        sqlx::query("INSERT INTO users (username, public_key, role_level, created_at, description, is_active) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(&user.username).bind(&user.public_key).bind(user.role_level).bind(&user.created_at).bind(&user.description).bind(user.is_active)
            .execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_user(&self, username: &str) -> Result<Option<User>, PytjaError> {
        let row = sqlx::query("SELECT * FROM users WHERE username = ?").bind(username).fetch_optional(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        if let Some(r) = row {
            Ok(Some(User {
                username: r.try_get("username").unwrap_or_default(),
                public_key: r.try_get("public_key").unwrap_or_default(),
                description: r.try_get("description").ok(),
                role_level: r.try_get("role_level").unwrap_or(0),
                is_active: r.try_get("is_active").unwrap_or(true),
                created_at: r.try_get("created_at").unwrap_or_default(),
            }))
        } else { Ok(None) }
    }

    async fn user_exists(&self, username: &str) -> Result<bool, PytjaError> {
        let c: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = ?").bind(username).fetch_one(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(c > 0)
    }

    async fn get_all_users(&self) -> Result<Vec<User>, PytjaError> {
        let rows = sqlx::query("SELECT * FROM users").fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(rows.into_iter().map(|r| User {
            username: r.try_get("username").unwrap_or_default(),
            public_key: r.try_get("public_key").unwrap_or_default(),
            description: r.try_get("description").ok(),
            role_level: r.try_get("role_level").unwrap_or(0),
            is_active: r.try_get("is_active").unwrap_or(true),
            created_at: r.try_get("created_at").unwrap_or_default(),
        }).collect())
    }

    async fn update_user_status(&self, username: &str, is_active: bool, role_level: i32) -> Result<(), PytjaError> {
        sqlx::query("UPDATE users SET is_active = ?, role_level = ? WHERE username = ?").bind(is_active).bind(role_level).bind(username).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    // --- FILES ---

    async fn save_node(&self, node: &FileNode) -> Result<(), PytjaError> {
        // UPDATE: blob_id wird gespeichert
        sqlx::query(
            "INSERT OR REPLACE INTO file_system (path, name, owner, is_folder, content, blob_id, lock_pass, permissions, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
            .bind(&node.path)
            .bind(&node.name)
            .bind(&node.owner)
            .bind(node.is_folder)
            .bind(&node.content)
            .bind(&node.blob_id) // <-- NEU
            .bind(&node.lock_pass)
            .bind(node.permissions)
            .bind(node.created_at)
            .execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_node(&self, path: &str) -> Result<Option<FileNode>, PytjaError> {
        let row = sqlx::query("SELECT * FROM file_system WHERE path = ?")
            .bind(path)
            .fetch_optional(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        if let Some(row) = row {
            Ok(Some(FileNode {
                path: row.try_get("path").unwrap_or_default(),
                name: row.try_get("name").unwrap_or_default(),
                owner: row.try_get("owner").unwrap_or_default(),
                is_folder: row.try_get("is_folder").unwrap_or(false),
                content: row.try_get("content").unwrap_or_default(),
                blob_id: row.try_get("blob_id").ok(), // <-- NEU: Laden
                size: 0,
                lock_pass: row.try_get("lock_pass").ok(),
                permissions: row.try_get::<i32, _>("permissions").unwrap_or(0) as u8,
                created_at: row.try_get("created_at").unwrap_or(0.0),
            }))
        } else {
            Ok(None)
        }
    }

    async fn list_directory(&self, path: &str) -> Result<Vec<FileNode>, PytjaError> {
        let query_path = if path == "/" { "".to_string() } else { path.to_string() };

        let rows = sqlx::query(
            "SELECT path, name, owner, is_folder, created_at, blob_id, lock_pass, permissions, LENGTH(content) as size
              FROM file_system
              WHERE path LIKE ? || '/%' AND path NOT LIKE ? || '/%/%'"
        )
            .bind(&query_path)
            .bind(&query_path)
            .fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        let mut nodes = Vec::new();
        for row in rows {
            nodes.push(FileNode {
                path: row.try_get("path").unwrap_or_default(),
                name: row.try_get("name").unwrap_or_default(),
                owner: row.try_get("owner").unwrap_or_default(),
                is_folder: row.try_get("is_folder").unwrap_or(false),
                content: vec![],
                blob_id: row.try_get("blob_id").ok(), // <-- NEU
                size: row.try_get::<i64, _>("size").unwrap_or(0) as usize,
                lock_pass: row.try_get("lock_pass").ok(),
                permissions: row.try_get::<i32, _>("permissions").unwrap_or(0) as u8,
                created_at: row.try_get("created_at").unwrap_or(0.0),
            });
        }
        Ok(nodes)
    }

    async fn delete_node_recursive(&self, path: &str) -> Result<(), PytjaError> {
        let like_pattern = format!("{}/%", path);
        sqlx::query("DELETE FROM file_system WHERE path = ? OR path LIKE ?").bind(path).bind(like_pattern).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn move_path(&self, old_path: &str, new_path: &str) -> Result<(), PytjaError> {
        sqlx::query("UPDATE file_system SET path = ? || SUBSTR(path, LENGTH(?) + 1) WHERE path = ? OR path LIKE ? || '/%'").bind(new_path).bind(old_path).bind(old_path).bind(old_path).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn update_metadata(&self, path: &str, lock: Option<String>, owner: Option<String>) -> Result<(), PytjaError> {
        if let Some(l) = lock { sqlx::query("UPDATE file_system SET lock_pass = ? WHERE path = ?").bind(l).bind(path).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?; }
        if let Some(o) = owner { sqlx::query("UPDATE file_system SET owner = ? WHERE path = ?").bind(o).bind(path).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?; }
        Ok(())
    }

    async fn update_permissions(&self, path: &str, permissions: u8) -> Result<(), PytjaError> {
        sqlx::query("UPDATE file_system SET permissions = ? WHERE path = ?").bind(permissions).bind(path).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_total_usage(&self, owner: &str) -> Result<usize, PytjaError> {
        let size: Option<i64> = sqlx::query_scalar("SELECT SUM(LENGTH(content)) FROM file_system WHERE owner = ?").bind(owner).fetch_one(&self.pool).await.ok();
        Ok(size.unwrap_or(0) as usize)
    }

    async fn find_nodes(&self, pattern: &str) -> Result<Vec<String>, PytjaError> {
        let rows = sqlx::query("SELECT path FROM file_system WHERE name LIKE ?").bind(pattern).fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(rows.iter().map(|r| r.try_get("path").unwrap_or_default()).collect())
    }

    async fn get_all_files_content(&self) -> Result<Vec<(String, Vec<u8>)>, PytjaError> {
        let rows = sqlx::query("SELECT path, content FROM file_system WHERE is_folder = 0").fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        let mut res = Vec::new();
        for r in rows { res.push((r.try_get("path")?, r.try_get("content")?)); }
        Ok(res)
    }

    async fn log_action(&self, actor: &str, action: &str, target: &str) -> Result<(), PytjaError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("INSERT INTO audit_logs (timestamp, actor, action, target) VALUES (?, ?, ?, ?)").bind(now).bind(actor).bind(action).bind(target).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_audit_logs(&self, limit: usize) -> Result<Vec<AuditLogEntry>, PytjaError> {
        let rows = sqlx::query("SELECT id, timestamp, actor, action, target FROM audit_logs ORDER BY id DESC LIMIT ?").bind(limit as i64).fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        let mut logs = Vec::new();
        for r in rows {
            logs.push(AuditLogEntry { id: r.try_get("id")?, timestamp: r.try_get("timestamp")?, actor: r.try_get("actor")?, action: r.try_get("action")?, target: r.try_get("target")? });
        }
        Ok(logs)
    }
}