use crate::models::{User, FileNode, AuditLogEntry};
use crate::error::PytjaError;
use async_trait::async_trait;

#[async_trait]
pub trait PytjaRepository: Send + Sync {
    // Initialisiert Tabellen (Migrationen)
    async fn init(&self) -> Result<(), PytjaError>;

    // User Management
    async fn create_user(&self, user: &User) -> Result<(), PytjaError>;
    async fn get_user(&self, username: &str) -> Result<Option<User>, PytjaError>;
    async fn user_exists(&self, username: &str) -> Result<bool, PytjaError>;
    async fn get_all_users(&self) -> Result<Vec<User>, PytjaError>;
    async fn update_user_status(&self, username: &str, is_active: bool, role_level: i32) -> Result<(), PytjaError>;

    // File System Ops
    async fn save_node(&self, node: &FileNode) -> Result<(), PytjaError>;
    async fn get_node(&self, path: &str) -> Result<Option<FileNode>, PytjaError>;
    async fn list_directory(&self, path: &str) -> Result<Vec<FileNode>, PytjaError>;
    async fn delete_node_recursive(&self, path: &str) -> Result<(), PytjaError>;
    async fn move_path(&self, old_path: &str, new_path: &str) -> Result<(), PytjaError>;
    async fn update_metadata(&self, path: &str, lock: Option<String>, owner: Option<String>) -> Result<(), PytjaError>;
    async fn update_permissions(&self, path: &str, permissions: u8) -> Result<(), PytjaError>;

    // Analytics & Search
    async fn get_total_usage(&self, owner: &str) -> Result<usize, PytjaError>;
    async fn find_nodes(&self, pattern: &str) -> Result<Vec<String>, PytjaError>;
    async fn get_all_files_content(&self) -> Result<Vec<(String, Vec<u8>)>, PytjaError>;

    // Auditing
    async fn log_action(&self, actor: &str, action: &str, target: &str) -> Result<(), PytjaError>;
    async fn get_audit_logs(&self, limit: usize) -> Result<Vec<AuditLogEntry>, PytjaError>;
}