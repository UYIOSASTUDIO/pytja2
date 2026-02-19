use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use colored::*;
use std::io::{self, Write};
use std::fs;
use std::path::PathBuf;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

use tracing::{info, error};
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
    // 1. Logging Setup (File only)
    let file_appender = tracing_appender::rolling::daily("logs", "pytja_shell.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt().with_writer(non_blocking).with_ansi(false).init();

    // 2. UI Start
    print!("\x1B[2J\x1B[1;1H");
    println!("{}", "PYTJA SHELL v2.0 (Enterprise Client)".green().bold());
    println!("========================================");

    // 3. Identity Laden & Multi-Account Selection
    let mut available_keys = Vec::new();
    if let Ok(entries) = fs::read_dir(IDENTITY_DIR) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "pytja") {
                available_keys.push(path.to_string_lossy().to_string());
            }
        }
    }

    if available_keys.is_empty() {
        println!("{}", "NO IDENTITY FOUND!".red().bold());
        println!("Please place a .pytja file in the '{}' directory.", IDENTITY_DIR);
        return Ok(());
    }

    // MULTI-ACCOUNT AUSWAHL
    let key_path = if available_keys.len() == 1 {
        available_keys[0].clone()
    } else {
        println!("{}", "Multiple identities found. Please select an account:".cyan().bold());
        for (i, key) in available_keys.iter().enumerate() {
            println!("  [{}] {}", i + 1, key.green());
        }

        let mut selected = String::new();
        loop {
            print!("{} ", "Select number:".bold());
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if let Ok(num) = input.trim().parse::<usize>() {
                if num > 0 && num <= available_keys.len() {
                    selected = available_keys[num - 1].clone();
                    break;
                }
            }
            println!("{}", "Invalid selection. Please try again.".red());
        }
        selected
    };

    // Die Identity::load Funktion gibt selbst aus, wen sie lädt.
    let identity = match Identity::load(&key_path) {
        Ok(id) => id,
        Err(e) => {
            println!("{} {}", "LOGIN FAILED:".red().bold(), e);
            return Ok(());
        }
    };

    let username = identity.username.clone();
    let signing_key = identity.keypair.clone();

    // 4. Connection Setup (Mit Spinner)
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈✔")
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message("Locating Security Certificates...");

    let possible_paths = vec![
        PathBuf::from("server.crt"),
        PathBuf::from("certs/server.crt"),
        PathBuf::from("../certs/server.crt"),
    ];

    let mut ca_cert = None;
    let mut cert_path_str = String::new();
    for p in possible_paths {
        if p.exists() {
            ca_cert = Some(fs::read_to_string(&p).unwrap());
            cert_path_str = p.to_string_lossy().to_string();
            break;
        }
    }

    if ca_cert.is_none() {
        pb.finish_and_clear();
        println!("{}", "SECURITY ERROR: 'server.crt' not found.".red().bold());
        return Ok(());
    } else {
        pb.println(format!("{} Security: Loaded CA from {}", "✔".green(), cert_path_str.cyan()));
    }

    pb.set_message("Connecting to Enterprise Server...");

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

    // Uplink Check
    match client.check_uplink().await {
        Ok((true, version)) => {
            pb.println(format!("{} Server Uplink Established: {}", "✔".green(), version.cyan()));
        },
        _ => {
            pb.finish_and_clear();
            println!("{}", "SERVER UNREACHABLE".red().bold());
            return Ok(());
        }
    }

    pb.set_message("Authenticating...");
    tokio::time::sleep(Duration::from_millis(300)).await; // Kleines Delay für UX

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