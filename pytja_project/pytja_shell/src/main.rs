use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use colored::*;
use std::io;
use std::fs;
use std::path::{Path, PathBuf}; // PathBuf hinzugefügt
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

use tracing::{info, error, warn};
use tracing_subscriber;
use tracing_appender;

use pytja_core::crypto::CryptoService;

mod terminal;
mod vfs;
mod plugins;
mod network_client;
mod identity;

use crate::terminal::Terminal;
use crate::vfs::VirtualFileSystem;
use crate::plugins::PluginManager;
use crate::network_client::PytjaClient;
use crate::identity::Identity;

const DB_PATH: &str = "pytja_local_cache.db";
const IDENTITY_DIR: &str = "usb_drive";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. LOGGING
    let file_appender = tracing_appender::rolling::daily("logs", "pytja_shell.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_thread_ids(true)
        .with_target(false)
        .init();

    info!("--- SESSION START ---");
    info!("PYTJA Shell initializing...");

    // 2. HEADER
    print!("\x1B[2J\x1B[1;1H");
    println!("{}", "PYTJA SHELL v2.0 (Enterprise Client)".green().bold());
    println!("========================================");

    // 3. IDENTITY LOAD
    let mut key_file: Option<String> = None;

    if let Ok(entries) = fs::read_dir(IDENTITY_DIR) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "pytja" {
                        key_file = Some(path.to_string_lossy().to_string());
                        break;
                    }
                }
            }
        }
    }

    if key_file.is_none() {
        error!("No Identity found in usb_drive/");
        println!("{}", "NO IDENTITY FOUND!".red().bold());
        println!("Please insert your USB Key (put .pytja file in 'usb_drive' folder).");
        return Ok(());
    }

    let key_path = key_file.unwrap();
    info!("Loading identity from: {}", key_path);

    let identity = match Identity::load(&key_path) {
        Ok(id) => id,
        Err(e) => {
            error!("Identity load failed: {:?}", e);
            println!("{} {}", "LOGIN FAILED:".red().bold(), e);
            return Ok(());
        }
    };

    let username = identity.username.clone();
    let signing_key = identity.keypair.clone();

    // 4. SERVER HANDSHAKE
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Identity Unlocked. Establishing Uplink...");
    pb.enable_steady_tick(Duration::from_millis(100));

    // FIX: Intelligente Suche nach dem Zertifikat
    let possible_paths = vec![
        PathBuf::from("server.crt"),          // Im selben Ordner (Production)
        PathBuf::from("certs/server.crt"),    // Workspace Root (Development)
        PathBuf::from("../certs/server.crt"), // Aus Subfolder gestartet
    ];

    let mut ca_cert = None;
    for p in possible_paths {
        if p.exists() {
            info!("Found server certificate at: {:?}", p);
            ca_cert = Some(fs::read_to_string(p).unwrap());
            break;
        }
    }

    if ca_cert.is_none() {
        let warning = "⚠️  WARNING: 'server.crt' not found. Connection will fail for self-signed servers.";
        warn!("{}", warning);
        // Wir zeigen das nur im Log, um die UI clean zu halten, aber hier könnte das Problem liegen.
    }

    let server_url = "https://127.0.0.1:50051".to_string();
    let key_bytes = signing_key.to_bytes().to_vec();

    // Verbindung aufbauen
    let client = match PytjaClient::connect(server_url, key_bytes, username.clone(), ca_cert).await {
        Ok(c) => c,
        Err(e) => {
            error!("Connection Init failed: {:?}", e);
            pb.finish_with_message(format!("Connection Init Failed: {}", e).red().to_string());
            return Ok(());
        }
    };

    // Uplink Check
    if let Ok(true) = client.check_uplink().await {
        info!("Uplink established.");
    } else {
        error!("Server unreachable (Ping failed)");
        // Hier geben wir dem User mehr Infos, warum es fehlschlug
        let hint = if fs::metadata("certs/server.crt").is_err() {
            " (Check certificates)"
        } else { "" };

        pb.finish_with_message(format!("Server Unreachable{}.", hint).red().to_string());
        return Ok(());
    }

    pb.set_message("Performing Cryptographic Handshake...");

    let challenge = match client.get_challenge(&username).await {
        Ok(c) => c,
        Err(e) => {
            error!("Handshake error for {}: {:?}", username, e);
            pb.finish_with_message(format!("Handshake Error: {}", e).red().to_string());
            return Ok(());
        }
    };

    let signature = CryptoService::sign_message(&signing_key, challenge.as_bytes());

    let login_resp = match client.login(&username, &challenge, signature).await {
        Ok(r) => r,
        Err(e) => {
            error!("Login RPC failed: {:?}", e);
            pb.finish_with_message(format!("Login Error: {}", e).red().to_string());
            return Ok(());
        }
    };

    if login_resp.success {
        info!("Login successful for user: {}", username);
        client.set_token(&login_resp.token).await;
        pb.finish_with_message("ACCESS GRANTED.".green().bold().to_string());
    } else {
        warn!("Login denied for user: {}. Reason: {}", username, login_resp.message);
        pb.finish_with_message(format!("Login Denied: {}", login_resp.message).red().to_string());
        return Ok(());
    }

    // 5. PLUGIN SYSTEM
    info!("Initializing Plugin System...");
    let data_dir = Path::new("data");
    if !data_dir.exists() { fs::create_dir_all(data_dir)?; }

    let mut plugin_manager = PluginManager::new("./plugins", "data");

    if let Err(e) = plugin_manager.load_and_verify_plugins() {
        error!("Plugin Security Check failed: {:?}", e);
        println!("{} {}", "PLUGIN ERROR:".red(), e);
    }

    info!("Plugins loaded count: {}", plugin_manager.list_functions().len());

    // 6. VIRTUAL FILESYSTEM & TERMINAL
    info!("Mounting VFS Cache at {}", DB_PATH);
    let vfs = VirtualFileSystem::new(username.clone(), DB_PATH).await;
    let vfs_shared = Arc::new(Mutex::new(vfs));

    println!("Starting Terminal Interface...\n");
    let mut term = Terminal::new(vfs_shared, username.clone(), plugin_manager, client);

    if let Err(e) = term.start().await {
        error!("Terminal session crashed: {:?}", e);
        println!("{} {}", "CRITICAL ERROR:".red().bold(), e);
    }

    info!("Session terminated normally.");
    println!("Session terminated.");
    Ok(())
}