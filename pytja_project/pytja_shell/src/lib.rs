use std::sync::Arc;
use tokio::sync::Mutex;
use colored::*;
use std::fs;
use std::path::PathBuf;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use directories::ProjectDirs;

use pytja_core::crypto::CryptoService;

mod terminal;
mod vfs;
mod plugins;
mod network_client;

use crate::terminal::Terminal;
use crate::vfs::VirtualFileSystem;
use crate::plugins::PluginManager;
use crate::network_client::PytjaClient;
use pytja_core::identity::Identity;

// Die hartcodierten Konstanten (DB_PATH und IDENTITY_DIR) wurden restlos entfernt!

pub async fn start_shell(identity_path: Option<String>) -> anyhow::Result<()> {
    // 1. Logging Setup (File only)
    let file_appender = tracing_appender::rolling::daily("logs", "pytja_shell.log");
    let (_non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // 2. UI Start
    print!("\x1B[2J\x1B[1;1H");
    println!("{}", "PYTJA SHELL v2.0 (Enterprise Client)".green().bold());
    println!("{}", "========================================".dimmed());

    // 3. Enterprise Identity Loading (Ein einziger, dynamischer Aufruf!)
    let identity = match Identity::load_or_prompt(identity_path) {
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
    tokio::time::sleep(Duration::from_millis(300)).await;

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

    // 5. Enterprise Pfad-Auflösung für lokalen Cache
    let db_path = if let Some(proj_dirs) = ProjectDirs::from("com", "pytja", "shell") {
        let data_dir = proj_dirs.data_dir();
        fs::create_dir_all(data_dir)?;
        data_dir.join("pytja_local_cache.db").to_string_lossy().to_string()
    } else {
        "pytja_local_cache.db".to_string() // Fallback
    };

    // --- 6. OS BOOT SEQUENCE (PLUGINS & DAEMONS) ---
    let mut plugin_manager = PluginManager::new("./plugins", "data");

    // Wir prüfen erst kritisch, ob es Probleme beim Laden gibt
    if let Err(e) = plugin_manager.load_and_verify_plugins() {
        eprintln!("{} Plugin system error: {}", "[WARNING]".yellow(), e);
    }

    let active_plugins = plugin_manager.list_plugins();
    if !active_plugins.is_empty() {
        println!("\n{}", "--- INITIALIZING DAEMONS ---".cyan().bold());

        for (manifest, _) in active_plugins {
            // Wir clonen den gRPC Client, da jeder Background-Daemon
            // seine eigene, thread-sichere Verbindung zum Server benötigt.
            match plugin_manager.boot_daemon(&manifest.name) {
                Ok(_) => {
                    println!("{} Service '{}' (v{}) is running in background.",
                             "[OK]".green(), manifest.name.bold(), manifest.version);
                }
                Err(e) => {
                    eprintln!("{} Failed to boot '{}' daemon: {}",
                              "[FAIL]".red(), manifest.name, e);
                }
            }
        }
        println!("{}", "----------------------------".cyan().bold());
    }

    // --- 7. FILE SYSTEM & TERMINAL START ---
    let vfs = VirtualFileSystem::new(username.clone(), &db_path).await;
    let vfs_shared = Arc::new(Mutex::new(vfs));

    println!("\nStarting Shell Session...");
    let mut term = Terminal::new(vfs_shared, username.clone(), plugin_manager, client);
    let _ = term.start().await;

    println!("Session terminated.");
    Ok(())
}