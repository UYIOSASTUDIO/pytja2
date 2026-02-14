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
pub struct DatabaseConfig {
    pub primary_url: String, // z.B. "sqlite://pytja.db" oder "postgres://user:pass@host/db"
    pub max_connections: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub database: DatabaseConfig,
    pub run_mode: String,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        // 1. Lade .env Datei, falls vorhanden (für lokale Entwicklung)
        dotenv::dotenv().ok();

        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
        println!("Loading configuration for mode: {}", run_mode);

        let s = Config::builder()
            // --- DEFAULTS (Sichere Standardwerte) ---
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 50051)?
            .set_default("server.worker_threads", 4)?
            .set_default("security.jwt_secret", "CHANGE_ME_IN_PROD_I_AM_UNSAFE")?
            .set_default("security.token_expiration_minutes", 60)?
            .set_default("security.require_tls", false)?
            .set_default("database.primary_url", "sqlite://pytja.db")?
            .set_default("database.max_connections", 10)?
            .set_default("run_mode", run_mode.clone())?

            // --- DATEI-CONFIGS (Hierachisch) ---
            // 1. config/default.toml (Basis)
            .add_source(File::from(Path::new("config/default")).required(false))
            // 2. config/production.toml (Überschreibt Basis, wenn RUN_MODE=production)
            .add_source(File::from(Path::new(&format!("config/{}", run_mode))).required(false))

            // --- ENVIRONMENT VARIABLEN (Höchste Priorität) ---
            // Erlaubt Overrides wie: PYTJA_SERVER__PORT=8080 oder PYTJA_DATABASE__PRIMARY_URL=postgres://...
            .add_source(Environment::with_prefix("PYTJA").separator("__"))

            .build()?;

        s.try_deserialize()
    }
}