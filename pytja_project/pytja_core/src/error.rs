use thiserror::Error;

#[derive(Error, Debug)]
pub enum PytjaError {
    #[error("Database connection failed: {0}")]
    DatabaseConnection(String),

    #[error("Database query failed: {0}")]
    DatabaseError(String),

    // FIX: Automatische Konvertierung für ? Operator bei SQLx
    #[error("SQLx Error: {0}")]
    SqlxError(#[from] sqlx::Error),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Item already exists: {0}")]
    AlreadyExists(String),

    #[error("Quota exceeded. Usage: {current}, Limit: {limit}")]
    QuotaExceeded { current: usize, limit: usize },

    #[error("I/O Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("System time error")]
    TimeError(#[from] std::time::SystemTimeError),

    #[error("Internal System Error: {0}")]
    System(String),
}