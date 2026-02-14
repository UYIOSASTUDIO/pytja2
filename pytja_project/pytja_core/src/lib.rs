pub mod models;
pub mod error;
pub mod crypto;
pub mod telemetry;
pub mod repo;
pub mod drivers; // <-- NEU
pub mod config;
pub use config::AppConfig;

pub use repo::PytjaRepository;
pub use drivers::DriverManager; // <-- Die Factory
pub use error::PytjaError;
pub use models::*;