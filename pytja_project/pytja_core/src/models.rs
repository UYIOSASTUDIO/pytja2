use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub public_key: String,
    pub description: Option<String>,
    pub role_level: i32,
    pub is_active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNode {
    pub path: String,
    pub name: String,
    pub owner: String,
    pub is_folder: bool,
    pub size: usize,
    pub content: Vec<u8>,
    pub lock_pass: Option<String>,
    pub permissions: u8,
    pub created_at: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,       // Username
    pub role_level: i32,   // ÄNDERUNG: Zahl statt String (z.B. 100 = Admin)
    pub exp: usize,        // Expiration
}

#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub id: i64,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub target: String,
}