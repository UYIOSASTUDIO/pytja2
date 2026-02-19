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
    pub storage_type: String, // "fs" (oder "local") or "s3"
    pub local_path: String,
    // Enterprise Best Practice: Optionale Felder als Option<T>
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
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

// Hier ist die TlsConfig Struktur
#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub redis: Option<RedisConfig>,
    pub paths: PathsConfig,
    // Das kritische Feld für SSL/TLS
    pub tls: Option<TlsConfig>,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        // 1. Enterprise Pfad-Ermittlung (OS-spezifisch für Prod, lokal für Dev)
        let (default_mounts, default_logs, default_storage) = if let Some(proj_dirs) = ProjectDirs::from("com", "pytja", "server") {
            let data_dir = proj_dirs.data_dir();

            // Versuche Verzeichnisse zu erstellen (Silent Fail ist ok hier, da Config später greift)
            let _ = std::fs::create_dir_all(data_dir);
            let _ = std::fs::create_dir_all(data_dir.join("logs"));

            (
                data_dir.join("mounts.json").to_string_lossy().to_string(),
                data_dir.join("logs").to_string_lossy().to_string(),
                data_dir.join("storage_blobs").to_string_lossy().to_string()
            )
        } else {
            // Fallback
            ("mounts.json".to_string(), "logs".to_string(), "storage_blobs".to_string())
        };

        let s = Config::builder()
            // 2. Hardcoded Defaults (Falls Config-Datei fehlt oder unvollständig ist)
            .set_default("server.host", "0.0.0.0")?
            .set_default("server.port", 50051)?
            .set_default("database.primary_url", "sqlite://pytja.db")?

            .set_default("storage.storage_type", "fs")?
            .set_default("storage.local_path", default_storage)?
            // S3 ist optional, daher keine Defaults nötig (wird None)

            .set_default("paths.mounts_file", default_mounts)?
            .set_default("paths.logs_dir", default_logs)?

            // 3. Datei-Quellen laden
            // FIX: Wir suchen explizit im Ordner 'config/' nach 'default.toml'
            .add_source(File::with_name("config/default").required(false))

            // Environment spezifisch (z.B. config/production.toml)
            .add_source(File::with_name(&format!("config/{}", run_mode)).required(false))

            // 4. Environment Variablen (höchste Priorität)
            // z.B. PYTJA__SERVER__PORT=9000
            .add_source(Environment::with_prefix("PYTJA").separator("__"))

            .build()?;

        s.try_deserialize()
    }
}