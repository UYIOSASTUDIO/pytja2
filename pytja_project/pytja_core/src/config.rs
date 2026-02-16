use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::env;
use directories::ProjectDirs;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub primary_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub storage_type: String, // "local" or "s3"
    pub local_path: String,
    pub s3_bucket: String,
    pub s3_region: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PathsConfig {
    pub mounts_file: String,
    pub logs_dir: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub redis: Option<RedisConfig>,
    pub paths: PathsConfig,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        // Standard-Pfade ermitteln
        let default_mounts = if cfg!(target_os = "windows") {
            "mounts.json".to_string()
        } else {
            // Versuche System-Pfad, Fallback auf lokal
            "/etc/pytja/mounts.json".to_string()
        };

        let s = Config::builder()
            // 1. Defaults setzen
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 50051)?
            .set_default("database.primary_url", "sqlite://primary.db")?
            .set_default("storage.storage_type", "local")?
            .set_default("storage.local_path", "./data_storage")?
            .set_default("storage.s3_bucket", "")?
            .set_default("storage.s3_region", "us-east-1")?
            .set_default("paths.mounts_file", default_mounts)?
            .set_default("paths.logs_dir", "./logs")?

            // 2. System Config (/etc/pytja/config.toml)
            .add_source(File::with_name("/etc/pytja/config").required(false))

            // 3. Lokale Config (config.toml)
            .add_source(File::with_name("config").required(false))

            // 4. Environment-spezifische Config (config/development.toml)
            .add_source(File::with_name(&format!("config/{}", run_mode)).required(false))

            // 5. Environment Variablen (PYTJA_SERVER__PORT=9090)
            .add_source(Environment::with_prefix("PYTJA").separator("__"))

            .build()?;

        s.try_deserialize()
    }
}