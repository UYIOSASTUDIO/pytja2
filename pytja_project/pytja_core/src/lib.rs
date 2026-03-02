pub mod models;
pub mod error;
pub mod crypto;
pub mod telemetry;
pub mod repo;
pub mod drivers;
pub mod config;
pub mod storage; // <-- Modul muss da sein
pub mod identity;

// Re-Exports für einfachen Zugriff
pub use repo::PytjaRepository;
pub use drivers::{DriverManager, DatabaseType};
pub use error::PytjaError;
pub use models::{User, FileNode, AuditLogEntry, Role};
pub use config::AppConfig;
pub use storage::{BlobStorage, FileSystemStorage, S3Storage, StorageType};