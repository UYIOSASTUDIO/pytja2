use crate::repo::PytjaRepository;
use crate::models::{User, FileNode, AuditLogEntry};
use crate::error::PytjaError;
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;
use tracing::{info, instrument};

#[derive(Clone)]
pub struct PostgresDriver {
    pool: PgPool,
}

impl PostgresDriver {
    /// Erstellt einen High-Performance Connection Pool für PostgreSQL
    pub async fn new(connection_string: &str) -> Result<Self, PytjaError> {
        // Parsing des Connection Strings (z.B. postgres://user:pass@localhost/mydb)
        let options = PgConnectOptions::from_str(connection_string)
            .map_err(|e| PytjaError::System(format!("Invalid Postgres Connection String: {}", e)))?;

        // Enterprise Tuning: Connection Pool Konfiguration
        let pool = PgPoolOptions::new()
            .max_connections(50) // Skaliert für hohe Last (Discord-Scale)
            .min_connections(5)  // Hält Verbindungen warm
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(|e| PytjaError::DatabaseConnection(format!("Failed to connect to Postgres: {}", e)))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl PytjaRepository for PostgresDriver {

    #[instrument(skip(self))]
    async fn init(&self) -> Result<(), PytjaError> {
        // Tabellen-Initialisierung (Schema Migration)

        // 1. Users
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

        // 2. File System (Postgres spezifisch: BYTEA für Binary Data)
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS file_system (
                path TEXT PRIMARY KEY,
                name TEXT,
                owner TEXT,
                is_folder BOOLEAN,
                content BYTEA,
                lock_pass TEXT,
                permissions INTEGER DEFAULT 0,
                created_at DOUBLE PRECISION
            )"
        ).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        // 3. Audit Logs (Postgres spezifisch: SERIAL für Auto-Increment)
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                timestamp TEXT,
                actor TEXT,
                action TEXT,
                target TEXT
            )"
        ).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        // Performance Indizes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_owner ON file_system(owner)").execute(&self.pool).await.ok();
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_parent ON file_system(path text_pattern_ops)").execute(&self.pool).await.ok();
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_logs_actor ON audit_logs(actor)").execute(&self.pool).await.ok();

        info!("PostgreSQL Database initialized successfully");
        Ok(())
    }

    // --- USER MANAGEMENT ---

    async fn create_user(&self, user: &User) -> Result<(), PytjaError> {
        sqlx::query(
            "INSERT INTO users (username, public_key, role_level, created_at, description, is_active)
             VALUES ($1, $2, $3, $4, $5, $6)"
        )
            .bind(&user.username)
            .bind(&user.public_key)
            .bind(user.role_level)
            .bind(&user.created_at)
            .bind(&user.description)
            .bind(user.is_active)
            .execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_user(&self, username: &str) -> Result<Option<User>, PytjaError> {
        let row = sqlx::query("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        if let Some(row) = row {
            Ok(Some(User {
                username: row.try_get("username").unwrap_or_default(),
                public_key: row.try_get("public_key").unwrap_or_default(),
                description: row.try_get("description").ok(),
                role_level: row.try_get("role_level").unwrap_or(0),
                is_active: row.try_get("is_active").unwrap_or(true),
                created_at: row.try_get("created_at").unwrap_or_default(),
            }))
        } else {
            Ok(None)
        }
    }

    async fn user_exists(&self, username: &str) -> Result<bool, PytjaError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1")
            .bind(username)
            .fetch_one(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(count > 0)
    }

    async fn get_all_users(&self) -> Result<Vec<User>, PytjaError> {
        let rows = sqlx::query("SELECT * FROM users").fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        let mut users = Vec::new();
        for r in rows {
            users.push(User {
                username: r.try_get("username")?,
                public_key: r.try_get("public_key")?,
                description: r.try_get("description").ok(),
                role_level: r.try_get("role_level")?,
                is_active: r.try_get("is_active")?,
                created_at: r.try_get("created_at")?,
            });
        }
        Ok(users)
    }

    async fn update_user_status(&self, username: &str, is_active: bool, role_level: i32) -> Result<(), PytjaError> {
        sqlx::query("UPDATE users SET is_active = $1, role_level = $2 WHERE username = $3")
            .bind(is_active).bind(role_level).bind(username)
            .execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    // --- FILE SYSTEM OPERATIONS ---

    async fn save_node(&self, node: &FileNode) -> Result<(), PytjaError> {
        // Upsert (Insert or Update) für Postgres
        sqlx::query(
            "INSERT INTO file_system (path, name, owner, is_folder, content, lock_pass, permissions, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (path) DO UPDATE SET
             name = EXCLUDED.name,
             owner = EXCLUDED.owner,
             content = EXCLUDED.content,
             lock_pass = EXCLUDED.lock_pass,
             permissions = EXCLUDED.permissions,
             created_at = EXCLUDED.created_at"
        )
            .bind(&node.path)
            .bind(&node.name)
            .bind(&node.owner)
            .bind(node.is_folder)
            .bind(&node.content)
            .bind(&node.blob_id)
            .bind(&node.lock_pass)
            .bind(node.permissions as i32) // Cast u8 -> i32 für Postgres
            .bind(node.created_at)
            .execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_node(&self, path: &str) -> Result<Option<FileNode>, PytjaError> {
        let row = sqlx::query("SELECT * FROM file_system WHERE path = $1")
            .bind(path)
            .fetch_optional(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        if let Some(row) = row {
            Ok(Some(FileNode {
                path: row.try_get("path").unwrap_or_default(),
                name: row.try_get("name").unwrap_or_default(),
                owner: row.try_get("owner").unwrap_or_default(),
                is_folder: row.try_get("is_folder").unwrap_or(false),
                content: row.try_get("content").unwrap_or_default(),
                blob_id: row.try_get("blob_id").ok(),
                size: 0, // Größe wird dynamisch berechnet oder bei Bedarf geladen
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

        // Optimierte Query: Lädt NICHT den Content (spart Bandbreite), sondern berechnet LENGTH()
        let rows = sqlx::query(
            "SELECT path, name, owner, is_folder, created_at, lock_pass, permissions, LENGTH(content) as size
              FROM file_system
              WHERE path LIKE $1 || '/%' AND path NOT LIKE $1 || '/%/%'"
        )
            .bind(&query_path)
            .bind(&query_path) // Zweimal binden, da Postgres Parameter nicht wiederverwendet wie SQLite
            .fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        let mut nodes = Vec::new();
        for row in rows {
            nodes.push(FileNode {
                path: row.try_get("path").unwrap_or_default(),
                name: row.try_get("name").unwrap_or_default(),
                owner: row.try_get("owner").unwrap_or_default(),
                is_folder: row.try_get("is_folder").unwrap_or(false),
                content: vec![],
                blob_id: row.try_get("blob_id").ok(),
                size: row.try_get::<i32, _>("size").unwrap_or(0) as usize,
                lock_pass: row.try_get("lock_pass").ok(),
                permissions: row.try_get::<i32, _>("permissions").unwrap_or(0) as u8,
                created_at: row.try_get("created_at").unwrap_or(0.0),
            });
        }
        Ok(nodes)
    }

    async fn delete_node_recursive(&self, path: &str) -> Result<(), PytjaError> {
        let like_pattern = format!("{}/%", path);
        sqlx::query("DELETE FROM file_system WHERE path = $1 OR path LIKE $2")
            .bind(path)
            .bind(like_pattern)
            .execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn move_path(&self, old_path: &str, new_path: &str) -> Result<(), PytjaError> {
        // Transaktionale Verschiebung im Dateisystem
        sqlx::query(
            "UPDATE file_system
             SET path = $1 || SUBSTR(path, LENGTH($2) + 1)
             WHERE path = $3 OR path LIKE $4 || '/%'"
        )
            .bind(new_path)
            .bind(old_path)
            .bind(old_path)
            .bind(old_path)
            .execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn update_metadata(&self, path: &str, lock: Option<String>, owner: Option<String>) -> Result<(), PytjaError> {
        if let Some(l) = lock {
            sqlx::query("UPDATE file_system SET lock_pass = $1 WHERE path = $2")
                .bind(l).bind(path).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        }
        if let Some(o) = owner {
            sqlx::query("UPDATE file_system SET owner = $1 WHERE path = $2")
                .bind(o).bind(path).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        }
        Ok(())
    }

    async fn update_permissions(&self, path: &str, permissions: u8) -> Result<(), PytjaError> {
        sqlx::query("UPDATE file_system SET permissions = $1 WHERE path = $2")
            .bind(permissions as i32) // Cast u8 -> i32
            .bind(path).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_total_usage(&self, owner: &str) -> Result<usize, PytjaError> {
        let size: Option<i64> = sqlx::query_scalar("SELECT SUM(LENGTH(content)) FROM file_system WHERE owner = $1")
            .bind(owner)
            .fetch_one(&self.pool).await.ok();
        Ok(size.unwrap_or(0) as usize)
    }

    async fn find_nodes(&self, pattern: &str) -> Result<Vec<String>, PytjaError> {
        let rows = sqlx::query("SELECT path FROM file_system WHERE name LIKE $1")
            .bind(pattern)
            .fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(rows.iter().map(|r| r.try_get("path").unwrap_or_default()).collect())
    }

    async fn get_all_files_content(&self) -> Result<Vec<(String, Vec<u8>)>, PytjaError> {
        let rows = sqlx::query("SELECT path, content FROM file_system WHERE is_folder = false") // Postgres boolean literal
            .fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        let mut res = Vec::new();
        for r in rows {
            res.push((r.try_get("path")?, r.try_get("content")?));
        }
        Ok(res)
    }

    // --- AUDIT LOGS ---

    async fn log_action(&self, actor: &str, action: &str, target: &str) -> Result<(), PytjaError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("INSERT INTO audit_logs (timestamp, actor, action, target) VALUES ($1, $2, $3, $4)")
            .bind(now).bind(actor).bind(action).bind(target)
            .execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_audit_logs(&self, limit: usize) -> Result<Vec<AuditLogEntry>, PytjaError> {
        let rows = sqlx::query("SELECT id, timestamp, actor, action, target FROM audit_logs ORDER BY id DESC LIMIT $1")
            .bind(limit as i64)
            .fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        let mut logs = Vec::new();
        for r in rows {
            logs.push(AuditLogEntry {
                id: r.try_get("id")?,
                timestamp: r.try_get("timestamp")?,
                actor: r.try_get("actor")?,
                action: r.try_get("action")?,
                target: r.try_get("target")?,
            });
        }
        Ok(logs)
    }
}