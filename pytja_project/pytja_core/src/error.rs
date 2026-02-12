use thiserror::Error;

#[derive(Error, Debug)]
pub enum PytjaError {
    // Datenbank-Ebene
    #[error("Database connection failed: {0}")]
    DatabaseConnection(String),

    #[error("Database query failed: {0}")]
    DatabaseQuery(#[from] rusqlite::Error),

    #[error("Database pool error: {0}")]
    PoolError(String),

    // Logik-Ebene
    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Item already exists: {0}")]
    AlreadyExists(String),

    #[error("Quota exceeded. Usage: {current}, Limit: {limit}")]
    QuotaExceeded { current: usize, limit: usize },

    // System-Ebene
    #[error("I/O Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("System time error")]
    TimeError(#[from] std::time::SystemTimeError),

    #[error("Internal System Error: {0}")]
    System(String),
}

// Hilfskonvertierung für DeadPool Fehler
impl From<deadpool_sqlite::PoolError> for PytjaError {
    fn from(err: deadpool_sqlite::PoolError) -> Self {
        PytjaError::PoolError(err.to_string())
    }
}

// Hilfskonvertierung für DeadPool Interact Fehler
impl From<deadpool_sqlite::InteractError> for PytjaError {
    fn from(err: deadpool_sqlite::InteractError) -> Self {
        PytjaError::System(format!("Thread interaction failed: {}", err))
    }
}