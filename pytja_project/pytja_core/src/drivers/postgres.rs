use crate::repo::PytjaRepository;
use crate::models::{User, FileNode, AuditLogEntry, Role}; // Role importiert
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
    pub async fn new(connection_string: &str) -> Result<Self, PytjaError> {
        let options = PgConnectOptions::from_str(connection_string)
            .map_err(|e| PytjaError::System(format!("Invalid Postgres Connection String: {}", e)))?;

        let pool = PgPoolOptions::new()
            .max_connections(50)
            .min_connections(5)
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
        // RBAC Tabellen
        sqlx::query("CREATE TABLE IF NOT EXISTS roles (name TEXT PRIMARY KEY)").execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        sqlx::query("CREATE TABLE IF NOT EXISTS role_permissions (role_name TEXT REFERENCES roles(name) ON DELETE CASCADE, permission TEXT, PRIMARY KEY (role_name, permission))").execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        // User & Files
        sqlx::query("CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            description TEXT,
            role TEXT DEFAULT 'guest',
            is_active BOOLEAN,
            created_at TEXT
        )").execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        sqlx::query("CREATE TABLE IF NOT EXISTS file_system (path TEXT PRIMARY KEY, name TEXT, owner TEXT, is_folder BOOLEAN, content BYTEA, blob_id TEXT, lock_pass TEXT, permissions INTEGER DEFAULT 0, created_at DOUBLE PRECISION)").execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        sqlx::query("CREATE TABLE IF NOT EXISTS audit_logs (id SERIAL PRIMARY KEY, timestamp TEXT, actor TEXT, action TEXT, target TEXT)").execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;

        info!("PostgreSQL Database initialized successfully");
        Ok(())
    }

    // --- USER MANAGEMENT ---

    async fn create_user(&self, user: &User) -> Result<(), PytjaError> {
        sqlx::query("INSERT INTO users (username, public_key, role, created_at, description, is_active) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(&user.username).bind(&user.public_key).bind(&user.role).bind(&user.created_at).bind(&user.description).bind(user.is_active)
            .execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_user(&self, username: &str) -> Result<Option<User>, PytjaError> {
        let row = sqlx::query("SELECT * FROM users WHERE username = $1").bind(username).fetch_optional(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        if let Some(r) = row {
            Ok(Some(User {
                username: r.try_get("username").unwrap_or_default(),
                public_key: r.try_get("public_key").unwrap_or_default(),
                description: r.try_get("description").ok(),
                role: r.try_get("role").unwrap_or("guest".to_string()),
                is_active: r.try_get("is_active").unwrap_or(true),
                created_at: r.try_get("created_at").unwrap_or_default(),
            }))
        } else { Ok(None) }
    }

    async fn user_exists(&self, u: &str) -> Result<bool, PytjaError> { let c: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1").bind(u).fetch_one(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?; Ok(c > 0) }

    async fn get_all_users(&self) -> Result<Vec<User>, PytjaError> {
        let rows = sqlx::query("SELECT * FROM users").fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(rows.into_iter().map(|r| User {
            username: r.try_get("username").unwrap_or_default(),
            public_key: r.try_get("public_key").unwrap_or_default(),
            description: r.try_get("description").ok(),
            role: r.try_get("role").unwrap_or("guest".to_string()),
            is_active: r.try_get("is_active").unwrap_or(true),
            created_at: r.try_get("created_at").unwrap_or_default(),
        }).collect())
    }

    async fn update_user_status(&self, username: &str, is_active: bool, role: &str) -> Result<(), PytjaError> {
        sqlx::query("UPDATE users SET is_active = $1, role = $2 WHERE username = $3").bind(is_active).bind(role).bind(username).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    // --- RBAC ---

    async fn create_role(&self, role: &Role) -> Result<(), PytjaError> {
        let mut tx = self.pool.begin().await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        sqlx::query("INSERT INTO roles (name) VALUES ($1) ON CONFLICT DO NOTHING").bind(&role.name).execute(&mut *tx).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        sqlx::query("DELETE FROM role_permissions WHERE role_name = $1").bind(&role.name).execute(&mut *tx).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        for perm in &role.permissions {
            sqlx::query("INSERT INTO role_permissions (role_name, permission) VALUES ($1, $2)").bind(&role.name).bind(perm).execute(&mut *tx).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        }
        tx.commit().await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_role(&self, name: &str) -> Result<Option<Role>, PytjaError> {
        let exists: Option<String> = sqlx::query_scalar("SELECT name FROM roles WHERE name = $1").bind(name).fetch_optional(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        if exists.is_none() { return Ok(None); }
        let perms: Vec<String> = sqlx::query_scalar("SELECT permission FROM role_permissions WHERE role_name = $1").bind(name).fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        Ok(Some(Role { name: name.to_string(), permissions: perms }))
    }

    async fn list_roles(&self) -> Result<Vec<Role>, PytjaError> {
        let names: Vec<String> = sqlx::query_scalar("SELECT name FROM roles").fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        let mut roles = Vec::new();
        for name in names {
            if let Ok(Some(r)) = self.get_role(&name).await { roles.push(r); }
        }
        Ok(roles)
    }

    async fn update_role_permissions(&self, role_name: &str, permissions: Vec<String>) -> Result<(), PytjaError> {
        self.create_role(&Role { name: role_name.to_string(), permissions }).await
    }

    // --- FILES & AUDIT (Stubs implementation um Compile-Fehler zu vermeiden) ---
    async fn save_node(&self, node: &FileNode) -> Result<(), PytjaError> {
        sqlx::query("INSERT INTO file_system (path, name, owner, is_folder, content, blob_id, lock_pass, permissions, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (path) DO UPDATE SET name=EXCLUDED.name, owner=EXCLUDED.owner, content=EXCLUDED.content, blob_id=EXCLUDED.blob_id, lock_pass=EXCLUDED.lock_pass, permissions=EXCLUDED.permissions, created_at=EXCLUDED.created_at")
            .bind(&node.path).bind(&node.name).bind(&node.owner).bind(node.is_folder).bind(&node.content).bind(&node.blob_id).bind(&node.lock_pass).bind(node.permissions as i32).bind(node.created_at).execute(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?; Ok(())
    }
    async fn get_node(&self, path: &str) -> Result<Option<FileNode>, PytjaError> {
        let r = sqlx::query("SELECT * FROM file_system WHERE path = $1").bind(path).fetch_optional(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        if let Some(row) = r { Ok(Some(FileNode { path: row.try_get("path")?, name: row.try_get("name")?, owner: row.try_get("owner")?, is_folder: row.try_get("is_folder")?, content: row.try_get("content")?, blob_id: row.try_get("blob_id").ok(), size: 0, lock_pass: row.try_get("lock_pass").ok(), permissions: row.try_get::<i32, _>("permissions").unwrap_or(0) as u8, created_at: row.try_get("created_at")? })) } else { Ok(None) }
    }
    async fn list_directory(&self, path: &str) -> Result<Vec<FileNode>, PytjaError> {
        let q = if path == "/" { "".to_string() } else { path.to_string() };
        let rows = sqlx::query("SELECT path, name, owner, is_folder, created_at, blob_id, lock_pass, permissions FROM file_system WHERE path LIKE $1 || '/%' AND path NOT LIKE $1 || '/%/%'").bind(&q).fetch_all(&self.pool).await.map_err(|e| PytjaError::DatabaseError(e.to_string()))?;
        let mut nodes = Vec::new(); for row in rows { nodes.push(FileNode { path: row.try_get("path")?, name: row.try_get("name")?, owner: row.try_get("owner")?, is_folder: row.try_get("is_folder")?, content: vec![], blob_id: row.try_get("blob_id").ok(), size: 0, lock_pass: row.try_get("lock_pass").ok(), permissions: row.try_get::<i32, _>("permissions").unwrap_or(0) as u8, created_at: row.try_get("created_at")? }); } Ok(nodes)
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