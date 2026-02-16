use anyhow::Result;
use pytja_core::crypto::CryptoService;
use std::sync::Arc;
use tokio::sync::Mutex;
use colored::*;
use rpassword::read_password;
use std::io::{self, Write};
use std::fs;
use std::path::Path;
// NEU: Für den Ladebalken
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

// Module einbinden
mod terminal;
mod vfs;
mod plugins;
mod network_client;
mod identity;

use crate::terminal::Terminal;
use crate::vfs::VirtualFileSystem;
use crate::plugins::PluginManager;
use crate::network_client::PytjaClient;

const DB_PATH: &str = "pytja_local_cache.db";
const IDENTITY_DIR: &str = "usb_drive";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. UI Header
    print!("\x1B[2J\x1B[1;1H"); // Clear Screen
    println!("{}", "PYTJA SHELL v2.0 (Enterprise Client)".green().bold());
    println!("========================================");

    // 2. Identity Load (Simulation eines Hardware-Keys)
    let mut key_file: Option<String> = None;
    let mut username = String::new();

    if let Ok(entries) = fs::read_dir(IDENTITY_DIR) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "pytja" {
                        key_file = Some(path.to_string_lossy().to_string());
                        username = path.file_stem().unwrap().to_string_lossy().to_string();
                        break;
                    }
                }
            }
        }
    }

    if key_file.is_none() {
        println!("{}", "NO IDENTITY FOUND!".red().bold());
        println!("Please insert your USB Key (put .pytja file in 'usb_drive' folder).");
        return Ok(());
    }

    let key_path = key_file.unwrap();
    println!("Identity detected: {} ({})", username.cyan().bold(), key_path);

    // 3. Password Prompt
    print!("Enter Identity Password: ");
    io::stdout().flush()?;
    let password = read_password()?;

    // --- START VISUAL FEEDBACK (SPINNER) ---
    // Wir starten den Spinner HIER, weil jetzt die Arbeit beginnt
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Decrypting Identity...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let encrypted_pem = fs::read_to_string(&key_path)?;

    // Versuche den Key zu entschlüsseln
    let signing_key = match CryptoService::decrypt_private_key_local(&encrypted_pem, &password) {
        Ok(k) => {
            pb.set_message("Identity Unlocked. Establishing Uplink...");
            k
        },
        Err(_) => {
            pb.finish_with_message("DECRYPTION FAILED.".red().to_string());
            return Ok(());
        }
    };

    // 4. Server Handshake & Login
    let mut client = PytjaClient::new("127.0.0.1:50051", signing_key.clone(), username.clone());

    // Uplink Check
    if let Ok(true) = client.check_uplink().await {
        // Alles gut
    } else {
        pb.finish_with_message("Server unreachable.".red().to_string());
        return Ok(());
    }

    pb.set_message("Performing Cryptographic Handshake...");

    // Challenge-Response Authentifizierung
    let challenge = match client.get_challenge(&username).await {
        Ok(c) => c,
        Err(e) => {
            pb.finish_with_message(format!("Handshake Error: {}", e).red().to_string());
            return Ok(());
        }
    };

    let signature = CryptoService::sign_message(&signing_key, challenge.as_bytes());

    let login_resp = match client.login(&username, &challenge, &signature).await {
        Ok(r) => r,
        Err(e) => {
            pb.finish_with_message(format!("Login Error: {}", e).red().to_string());
            return Ok(());
        }
    };

    if login_resp.success {
        client.set_token(&login_resp.token);
        // ERFOLG: Spinner beenden
        pb.finish_with_message("ACCESS GRANTED.".green().bold().to_string());
    } else {
        pb.finish_with_message(format!("Login Denied: {}", login_resp.message).red().to_string());
        return Ok(());
    }
    // --- END VISUAL FEEDBACK ---

    // 5. Plugin System Init
    println!("Loading WASM Plugins...");
    let mut plugin_manager = PluginManager::new("./plugins");

    if Path::new("./plugins").exists() {
        if let Err(e) = plugin_manager.load_plugins("./plugins") {
            println!("Plugin Warning: {}", e);
        }
    } else {
        let _ = fs::create_dir_all("./plugins");
    }
    println!("Plugins loaded: {}", plugin_manager.list_functions().len());

    // 6. Virtual File System (Local Cache)
    let vfs = VirtualFileSystem::new(username.clone(), DB_PATH).await;
    let vfs_shared = Arc::new(Mutex::new(vfs));

    // 7. Terminal Start
    println!("Starting Terminal Interface...\n");
    let mut term = Terminal::new(vfs_shared, username, plugin_manager, client);

    term.start().await?;

    println!("Session terminated.");
    Ok(())
}