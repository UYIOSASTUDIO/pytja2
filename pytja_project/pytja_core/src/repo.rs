use crate::models::{User, Role, FileNode, AuditLog}; // AuditLog hinzugefügt
use crate::error::PytjaError;
use async_trait::async_trait;

#[async_trait]
pub trait PytjaRepository: Send + Sync {
    async fn init(&self) -> Result<(), PytjaError>;

    // User & Auth
    async fn get_user(&self, username: &str) -> Result<Option<User>, PytjaError>;
    async fn user_exists(&self, username: &str) -> Result<bool, PytjaError>;
    async fn save_user_keys(&self, username: &str, public_key: &[u8], private_key_encrypted: &[u8]) -> Result<(), PytjaError>;

    // NEU: User Management
    async fn list_users(&self) -> Result<Vec<User>, PytjaError>;
    async fn create_user(&self, user: &User) -> Result<(), PytjaError>;
    async fn update_user_status(&self, username: &str, is_active: bool, role: &str) -> Result<(), PytjaError>;
    async fn set_user_quota(&self, username: &str, limit: u64) -> Result<(), PytjaError>;
    async fn get_user_quota_limit(&self, username: &str) -> Result<u64, PytjaError>;

    // Filesystem
    async fn save_node(&self, node: &FileNode) -> Result<(), PytjaError>;
    async fn get_node(&self, path: &str) -> Result<Option<FileNode>, PytjaError>;
    async fn list_directory(&self, path: &str) -> Result<Vec<FileNode>, PytjaError>;
    async fn list_recursive(&self, path: &str) -> Result<Vec<FileNode>, PytjaError> {
        self.list_directory(path).await
    }
    async fn delete_node_recursive(&self, path: &str) -> Result<(), PytjaError>;
    async fn move_path(&self, src: &str, dst: &str) -> Result<(), PytjaError>;
    async fn update_metadata(&self, path: &str, lock_pass: Option<String>, owner: Option<String>) -> Result<(), PytjaError>;
    async fn update_permissions(&self, path: &str, perms: u8) -> Result<(), PytjaError>;

    // Search
    async fn find_nodes(&self, pattern: &str) -> Result<Vec<String>, PytjaError>;
    async fn get_all_files_content(&self) -> Result<Vec<(String, Vec<u8>)>, PytjaError>;
    async fn get_total_usage(&self, owner: &str) -> Result<usize, PytjaError>;

    // RBAC
    async fn get_role(&self, name: &str) -> Result<Option<Role>, PytjaError>;
    async fn create_role(&self, role: &Role) -> Result<(), PytjaError>;
    async fn update_role_permissions(&self, name: &str, permissions: Vec<String>) -> Result<(), PytjaError>;
    async fn list_roles(&self) -> Result<Vec<Role>, PytjaError>;
    async fn log_action(&self, user: &str, action: &str, target: &str) -> Result<(), PytjaError>;
    async fn get_audit_logs(&self, limit: u32, user_filter: Option<String>) -> Result<Vec<AuditLog>, PytjaError>;
    // --- INVITE SYSTEM ---
    async fn create_invite(&self, code: &str, role: &str, max_uses: u32, quota_limit: u64, creator: &str) -> Result<(), PytjaError>;
    // Gibt zurück: (role, quota_limit, max_uses, used_count)
    async fn get_invite(&self, code: &str) -> Result<Option<(String, u64, u32, u32)>, PytjaError>;
    async fn increment_invite_use(&self, code: &str) -> Result<(), PytjaError>;
    async fn revoke_invite(&self, code: &str) -> Result<(), PytjaError>;
    // Gibt zurück: (code, role, max_uses, used_count, created_by, created_at)
    async fn list_invites(&self) -> Result<Vec<(String, String, u32, u32, String, String)>, PytjaError>;

    // --- SECURE QUERY PUSHDOWN (RBAC auf Datenbank-Ebene) ---
    async fn list_directory_secure(&self, path: &str, username: &str, role: &str) -> Result<Vec<FileNode>, PytjaError>;
    async fn list_recursive_secure(&self, path: &str, username: &str, role: &str) -> Result<Vec<FileNode>, PytjaError>;
    async fn get_node_secure(&self, path: &str, username: &str, role: &str) -> Result<Option<FileNode>, PytjaError>;
    // Lädt einen Chunk einer Datei für performantes Streaming (ohne RAM-Overhead)
    async fn read_node_chunk_secure(&self, path: &str, username: &str, role: &str, offset: usize, size: usize) -> Result<Vec<u8>, PytjaError>;
    async fn query_metadata_secure(&self, query: &str, username: &str, role: &str) -> Result<Vec<FileNode>, PytjaError>;
}