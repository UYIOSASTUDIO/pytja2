use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use colored::*;
use std::io::{self, Write};
use std::fs;
use std::path::Path;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

// Logging & Tracing
use tracing::{info, error, warn};
use tracing_subscriber;
use tracing_appender;

// Krypto & Core
use pytja_core::crypto::CryptoService;

// Module
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
    // ---------------------------------------------------------
    // 1. ENTERPRISE LOGGING SETUP (Non-Blocking File IO)
    // ---------------------------------------------------------
    // Erstellt täglich rotierende Logs im Ordner "logs/"
    let file_appender = tracing_appender::rolling::daily("logs", "pytja_shell.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Initialisiert den Subscriber: Logs gehen in die Datei,
    // aber NICHT in die Konsole (damit die UI sauber bleibt).
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false) // Keine Farben im Logfile
        .with_thread_ids(true)
        .with_target(false) // Weniger Rauschen
        .init();

    info!("--- SESSION START ---");
    info!("PYTJA Shell initializing...");

    // ---------------------------------------------------------
    // 2. UI HEADER
    // ---------------------------------------------------------
    print!("\x1B[2J\x1B[1;1H"); // Clear Screen
    println!("{}", "PYTJA SHELL v2.0 (Enterprise Client)".green().bold());
    println!("========================================");

    // ---------------------------------------------------------
    // 3. IDENTITY LOAD (USB Key Simulation)
    // ---------------------------------------------------------
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
        let msg = "No Identity found in usb_drive/";
        error!("{}", msg); // Log to file
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

    // ---------------------------------------------------------
    // 4. SERVER HANDSHAKE
    // ---------------------------------------------------------
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Identity Unlocked. Establishing Uplink...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let mut client = PytjaClient::new("127.0.0.1:50051", signing_key.clone(), username.clone());

    // Uplink Check
    if let Ok(true) = client.check_uplink().await {
        info!("Uplink established.");
    } else {
        error!("Server unreachable");
        pb.finish_with_message("Server unreachable.".red().to_string());
        return Ok(());
    }

    pb.set_message("Performing Cryptographic Handshake...");

    // Challenge-Response
    let challenge = match client.get_challenge(&username).await {
        Ok(c) => c,
        Err(e) => {
            error!("Handshake error for {}: {:?}", username, e);
            pb.finish_with_message(format!("Handshake Error: {}", e).red().to_string());
            return Ok(());
        }
    };

    let signature = CryptoService::sign_message(&signing_key, challenge.as_bytes());

    let login_resp = match client.login(&username, &challenge, &signature).await {
        Ok(r) => r,
        Err(e) => {
            error!("Login RPC failed: {:?}", e);
            pb.finish_with_message(format!("Login Error: {}", e).red().to_string());
            return Ok(());
        }
    };

    if login_resp.success {
        info!("Login successful for user: {}", username);
        client.set_token(&login_resp.token);
        pb.finish_with_message("ACCESS GRANTED.".green().bold().to_string());
    } else {
        warn!("Login denied for user: {}. Reason: {}", username, login_resp.message);
        pb.finish_with_message(format!("Login Denied: {}", login_resp.message).red().to_string());
        return Ok(());
    }

    // ---------------------------------------------------------
    // 5. PLUGIN SYSTEM
    // ---------------------------------------------------------
    info!("Initializing Plugin System...");

    // Wir nutzen das Verzeichnis der Identität oder ein lokales data/ Verzeichnis für die DB
    let data_dir = Path::new("data");
    if !data_dir.exists() { fs::create_dir_all(data_dir)?; }

    let mut plugin_manager = PluginManager::new("./plugins", "data");

    // Hier passiert der Magic Moment: User wird gefragt (nur einmal!)
    if let Err(e) = plugin_manager.load_and_verify_plugins() {
        error!("Plugin Security Check failed: {:?}", e);
        println!("{} {}", "PLUGIN ERROR:".red(), e);
        // Wir starten trotzdem, aber evtl. ohne Plugins
    }

    info!("Plugins ready: {}", plugin_manager.list_functions().len());

    // ---------------------------------------------------------
    // 6. VIRTUAL FILESYSTEM & TERMINAL
    // ---------------------------------------------------------
    info!("Mounting VFS Cache at {}", DB_PATH);
    let vfs = VirtualFileSystem::new(username.clone(), DB_PATH).await;
    let vfs_shared = Arc::new(Mutex::new(vfs));

    println!("Starting Terminal Interface...\n");
    let mut term = Terminal::new(vfs_shared, username.clone(), plugin_manager, client);

    // Main Loop starten (Fehler abfangen)
    if let Err(e) = term.start().await {
        error!("Terminal session crashed: {:?}", e);
        println!("{} {}", "CRITICAL ERROR:".red().bold(), e);
    }

    info!("Session terminated normally.");
    println!("Session terminated.");
    Ok(())
}