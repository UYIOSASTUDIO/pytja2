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

        // FIX: Wir nutzen jetzt immer lokale Pfade als Default, um Permission-Fehler
        // in /etc/ zu vermeiden, wenn man nicht als Root läuft.
        let default_mounts = "mounts.json".to_string();
        let default_logs = "logs".to_string();

        let s = Config::builder()
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 50051)?
            .set_default("database.primary_url", "sqlite://primary.db")?
            .set_default("storage.storage_type", "local")?
            .set_default("storage.local_path", "./data_storage")?
            .set_default("storage.s3_bucket", "")?
            .set_default("storage.s3_region", "us-east-1")?
            .set_default("paths.mounts_file", default_mounts)?
            .set_default("paths.logs_dir", default_logs)?

            // Config Sources (Priorität aufsteigend)
            .add_source(File::with_name("config").required(false))
            .add_source(File::with_name(&format!("config/{}", run_mode)).required(false))
            .add_source(Environment::with_prefix("PYTJA").separator("__"))

            .build()?;

        s.try_deserialize()
    }
}