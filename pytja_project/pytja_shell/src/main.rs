use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use colored::*;
use std::fs;
use std::path::PathBuf; // Path entfernt
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

use tracing::{info, error}; // warn entfernt
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
    // Logging Setup
    let file_appender = tracing_appender::rolling::daily("logs", "pytja_shell.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt().with_writer(non_blocking).with_ansi(false).init();

    print!("\x1B[2J\x1B[1;1H");
    println!("{}", "PYTJA SHELL v2.0 (Enterprise Client)".green().bold());
    println!("========================================");

    // Identity Laden
    let mut key_file: Option<String> = None;
    if let Ok(entries) = fs::read_dir(IDENTITY_DIR) {
        for entry in entries {
            if let Ok(e) = entry {
                let path = e.path();
                if path.extension().map_or(false, |ext| ext == "pytja") {
                    key_file = Some(path.to_string_lossy().to_string());
                    break;
                }
            }
        }
    }

    if key_file.is_none() {
        println!("{}", "NO IDENTITY FOUND!".red().bold());
        return Ok(());
    }

    let key_path = key_file.unwrap();
    println!("Identity loaded: {}", key_path.cyan());

    let identity = match Identity::load(&key_path) {
        Ok(id) => id,
        Err(e) => {
            println!("{} {}", "LOGIN FAILED:".red().bold(), e);
            return Ok(());
        }
    };

    let username = identity.username.clone();
    let signing_key = identity.keypair.clone();

    // Connection
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}").unwrap());
    pb.set_message("Connecting to Enterprise Server...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let possible_paths = vec![
        PathBuf::from("server.crt"),
        PathBuf::from("certs/server.crt"),
        PathBuf::from("../certs/server.crt"),
    ];

    let mut ca_cert = None;
    for p in possible_paths {
        if p.exists() {
            ca_cert = Some(fs::read_to_string(&p).unwrap());
            break;
        }
    }

    if ca_cert.is_none() {
        pb.finish_and_clear();
        println!("{}", "SECURITY ERROR: 'server.crt' not found.".red().bold());
        return Ok(());
    }

    // FIX: HTTPS URL
    let server_url = "https://localhost:50051".to_string();
    let key_bytes = signing_key.to_bytes().to_vec();

    let client = match PytjaClient::connect(server_url, key_bytes, username.clone(), ca_cert).await {
        Ok(c) => c,
        Err(e) => {
            pb.finish_and_clear();
            println!("{}", "CONNECTION FAILED".red().bold());
            println!("Error: {}", e);
            return Ok(());
        }
    };

    if let Ok(true) = client.check_uplink().await {
        // ok
    } else {
        pb.finish_and_clear();
        println!("{}", "SERVER UNREACHABLE".red().bold());
        return Ok(());
    }

    // Auth
    pb.set_message("Authenticating...");

    let challenge = match client.get_challenge(&username).await {
        Ok(c) => c,
        Err(e) => {
            pb.finish_with_message(format!("Handshake Error: {}", e).red().to_string());
            return Ok(());
        }
    };

    let signature = CryptoService::sign_message(&signing_key, challenge.as_bytes());

    let login_resp = match client.login(&username, &challenge, signature).await {
        Ok(r) => r,
        Err(e) => {
            pb.finish_with_message(format!("Login Error: {}", e).red().to_string());
            return Ok(());
        }
    };

    if login_resp.success {
        client.set_token(&login_resp.token).await;
        pb.finish_with_message("ACCESS GRANTED".green().bold().to_string());
    } else {
        pb.finish_with_message(format!("ACCESS DENIED: {}", login_resp.message).red().to_string());
        return Ok(());
    }

    // Plugins & VFS
    let mut plugin_manager = PluginManager::new("./plugins", "data");
    let _ = plugin_manager.load_and_verify_plugins();

    let vfs = VirtualFileSystem::new(username.clone(), DB_PATH).await;
    let vfs_shared = Arc::new(Mutex::new(vfs));

    println!("\nStarting Shell Session...");
    let mut term = Terminal::new(vfs_shared, username.clone(), plugin_manager, client);
    let _ = term.start().await;

    println!("Session terminated.");
    Ok(())
}