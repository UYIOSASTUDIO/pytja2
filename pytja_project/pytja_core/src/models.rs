use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,        // z.B. "admin", "editor", "guest"
    pub permissions: Vec<String>, // z.B. ["core:fs:read", "core:upload"]
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub username: String,
    pub public_key: Vec<u8>,
    pub role: String,
    pub is_active: bool,
    pub created_at: f64,
    #[sqlx(default)]
    pub quota_limit: i64,
    #[sqlx(default)]
    pub description: Option<String>, // Feld description hinzugefügt
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNode {
    pub path: String,
    pub name: String,
    pub owner: String,
    pub is_folder: bool,

    // Legacy Content (für kleine Files oder Configs)
    pub content: Vec<u8>,

    // ENTERPRISE: Referenz auf den Blob im Storage
    pub blob_id: Option<String>,

    pub size: usize,
    pub lock_pass: Option<String>,
    pub permissions: u8,
    pub created_at: f64,
    pub metadata: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub permissions: HashSet<String>,
    pub exp: usize,
    pub sid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub id: i64,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub target: String,
}

// Ergänze AuditLog Model falls noch nicht da:
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id: i64,
    pub user_id: String,
    pub action: String,
    pub target: String,
    pub timestamp: f64,
}