use serde::Deserialize;
use config::{Config, ConfigError, File, Environment};
use std::env;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub worker_threads: usize, // Performance Tuning
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub token_expiration_minutes: i64,
    pub require_tls: bool, // Vorbereitung für HTTPS
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub storage_type: String, // "fs" oder "s3"
    pub local_path: String,   // Für fs
    pub s3_bucket: String,    // Für s3
    pub s3_region: String,    // Für s3
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub primary_url: String, // z.B. "sqlite://pytja.db" oder "postgres://user:pass@host/db"
    pub max_connections: u32,
}

// NEU: Die fehlende Struktur für Redis
#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub run_mode: String,
    // Hier wird die neue Struktur verwendet
    pub redis: Option<RedisConfig>,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        dotenv::dotenv().ok();
        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        let s = Config::builder()
            // SERVER DEFAULTS
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 50051)?
            .set_default("server.worker_threads", 4)?

            // SECURITY DEFAULTS
            .set_default("security.jwt_secret", "CHANGE_ME_IN_PROD")?
            .set_default("security.token_expiration_minutes", 60)?
            .set_default("security.require_tls", false)?

            // DB DEFAULTS
            .set_default("database.primary_url", "sqlite://pytja.db")?
            .set_default("database.max_connections", 10)?

            // STORAGE DEFAULTS
            .set_default("storage.storage_type", "fs")?
            .set_default("storage.local_path", "./data/blobs")?
            .set_default("storage.s3_bucket", "pytja-enterprise")?
            .set_default("storage.s3_region", "eu-central-1")?

            // REDIS DEFAULT (Optional: Falls du standardmäßig localhost willst)
            // Wenn du das auskommentierst, ist redis = None, außer es steht in der .env oder .toml
            // .set_default("redis.url", "redis://127.0.0.1/")?

            .set_default("run_mode", run_mode.clone())?

            // Config Files laden
            .add_source(File::from(Path::new("config/default")).required(false))
            .add_source(File::from(Path::new(&format!("config/{}", run_mode))).required(false))

            // Environment Variables (z.B. PYTJA_REDIS__URL=redis://...)
            .add_source(Environment::with_prefix("PYTJA").separator("__"))
            .build()?;

        s.try_deserialize()
    }
}