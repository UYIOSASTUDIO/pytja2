use anyhow::Result;
use pytja_core::{
    // SqliteRepository HIER ENTFERNT, da es nicht mehr existiert
    crypto::CryptoService,
    models::User
};

// Module laden
mod terminal;
mod vfs;
mod plugins;
mod network_client;
mod identity;

use crate::terminal::Terminal;
use crate::vfs::VirtualFileSystem;
use crate::plugins::PluginManager;
use crate::network_client::NetworkClient;

use std::sync::{Arc, Mutex};
use colored::*;
use rpassword::read_password;
use std::io::{self, Write};
use std::fs;
use std::path::Path;

const DB_PATH: &str = "pytja_local_cache.db";
const IDENTITY_DIR: &str = "usb_drive"; // Simulierter USB Stick Pfad

#[tokio::main]
async fn main() -> Result<()> {
    // 1. UI Header
    print!("\x1B[2J\x1B[1;1H"); // Clear Screen
    println!("{}", "PYTJA SHELL v2.0 (Enterprise Client)".green().bold());
    println!("========================================");

    // 2. Identity Load (Simulation eines Hardware-Keys)
    let files = fs::read_dir(IDENTITY_DIR);
    let mut key_file: Option<String> = None;
    let mut username = String::new();

    if let Ok(entries) = files {
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

    // 3. Password Prompt (Entschlüsselung)
    print!("Enter Identity Password: ");
    io::stdout().flush()?;
    let password = read_password()?;

    let encrypted_pem = fs::read_to_string(&key_path)?;

    // Versuche den Key zu entschlüsseln
    let signing_key = match CryptoService::decrypt_private_key_local(&encrypted_pem, &password) {
        Ok(k) => k,
        Err(_) => {
            println!("{}", "ACCESS DENIED. WRONG PASSWORD.".red().bold());
            return Ok(());
        }
    };

    println!("{}", "Identity Unlocked. Connecting to Neural Link...".green());

    // 4. Server Handshake & Login
    let mut client = NetworkClient::new("http://127.0.0.1:50051".to_string()).await?;

    // Challenge anfordern
    let challenge = client.get_challenge(&username).await?;

    // Challenge signieren
    let signature = CryptoService::sign_message(&signing_key, challenge.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    // Login senden
    let login_resp = client.login(&username, &challenge, &signature_hex).await?;

    if login_resp.success {
        println!("{} Session Token acquired.", "LOGIN SUCCESSFUL.".green().bold());
        client.set_token(&login_resp.token);
    } else {
        println!("Login Failed: {}", login_resp.message.red());
        return Ok(());
    }

    // 5. Plugin System Init
    println!("Loading WASM Plugins...");
    let mut plugin_manager = PluginManager::new();
    if Path::new("./plugins").exists() {
        if let Err(e) = plugin_manager.load_plugins("./plugins") {
            println!("Plugin Warning: {}", e);
        }
    } else {
        fs::create_dir_all("./plugins")?;
    }
    println!("Plugins loaded: {}", plugin_manager.list_functions().len());

    // 6. Virtual File System (Local Cache)
    // FIX: Async Initialization wegen DriverManager
    let vfs = VirtualFileSystem::new(username.clone(), DB_PATH).await;
    let vfs_shared = Arc::new(Mutex::new(vfs));

    // 7. Terminal Start
    println!("Starting Terminal Interface...\n");
    let mut term = Terminal::new(vfs_shared, username, plugin_manager, client);

    // Hauptschleife starten
    term.start().await?;

    println!("Session terminated.");
    Ok(())
}