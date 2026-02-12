use pytja_core::{
    PytjaRepository, SqliteRepository,
    crypto::CryptoService, // WICHTIG: Wieder aktiv
};
use std::io::{self, Write};
use colored::*;
use anyhow::Result;
use std::path::Path;
use std::fs; // WICHTIG: Wieder aktiv für Datei-Zugriff
use pytja_core::telemetry;
mod network_client; // NEU
use network_client::PytjaClient; // NEU

mod terminal;
mod vfs;
mod plugins;
use plugins::PluginManager;

use terminal::Terminal;
use vfs::VirtualFileSystem;

// KONSTANTEN
const DB_PATH: &str = "pytja.db";
const KEY_DIR: &str = "usb_drive"; // WICHTIG: Wieder da!

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Telemetry starten
    let _guard = telemetry::init_telemetry("./logs", "pytja_service");
    tracing::info!("Pytja Shell booting up...");

    print!("\x1B[2J\x1B[1;1H"); // Clear Screen

    // 2. Auth Repo initialisieren
    let auth_repo = SqliteRepository::new(DB_PATH);

    // Initialisierung prüfen
    if let Err(e) = auth_repo.init() {
        tracing::error!("CRITICAL: Database init failed: {}", e);
        eprintln!("Error initializing database: {}", e);
        return Ok(());
    }

    println!("{}", "INITIALIZING SECURE LINK...".green().bold());

    // 3. Login Prozess
    println!("\n{}", "=== IDENTITY VERIFICATION ===".blue().bold());

    let username = read_input("Agent Codename: ");

    // Check ob User in DB existiert
    let user_opt = auth_repo.get_user(&username).await?;

    if user_opt.is_none() {
        println!("{}", "Access Denied: Identity unknown.".red());
        return Ok(());
    }

    let user = user_opt.unwrap();

    // --- HARD SECURITY CHECK ---

    // 1. Prüfen ob Key File existiert (Der "USB Stick")
    let key_file_path = format!("{}/{}.pytja", KEY_DIR, username);
    if !Path::new(&key_file_path).exists() {
        println!("{}", format!("Access Denied: Security Token missing ({}).", key_file_path).red());
        return Ok(());
    }

    // 2. Passwort Abfrage
    print!("Decryption Password: ");
    io::stdout().flush()?;
    let password = rpassword::read_password()?;

    // 3. Entschlüsselung & Signatur Check
    println!("{}", "[*] Verifying Credentials...".yellow());

    // A. Key laden
    let encrypted_key = fs::read_to_string(&key_file_path)?;

    // B. Versuchen zu entschlüsseln
    // Das decrypted jetzt den Ed25519 Key aus der Datei mit deinem Passwort
    let signing_key_result = CryptoService::decrypt_private_key_local(&encrypted_key, &password);

    let signing_key = match signing_key_result {
        Ok(k) => k,
        Err(_) => {
            println!("{}", "Access Denied: Invalid Password.".red().bold());
            return Ok(());
        }
    };

    // C. Challenge-Response Test
    // Wir signieren eine Nachricht und prüfen gegen den Public Key in der DB
    let challenge = b"PYTJA_SECURE_LOGIN_CHALLENGE";
    let signature = CryptoService::sign_message(&signing_key, challenge);

    let public_key_bytes = hex::decode(&user.public_key).unwrap_or_default();

    let is_valid = CryptoService::verify_signature(&user.public_key, challenge, &signature)?;

    if !is_valid {
        println!("{}", "CRITICAL ALERT: Key forgery detected!".red().bold().blink());
        return Ok(());
    }

    // --- SECURITY CHECK PASSED ---

    println!("{}", "[+] AUTHENTICATION SUCCESSFUL.".green().bold());
    println!("Welcome back, Agent {}.\n", username.cyan());

    let net_client = PytjaClient::new("127.0.0.1:50051");
    let _ = net_client.check_uplink().await;
    println!("");

    // 4. Plugins laden
    println!("{}", "[*] Initializing Module System...".yellow());
    let mut plugin_manager = PluginManager::new("../pytja_plugins");
    match plugin_manager.scan_and_load() {
        Ok(msg) => println!(" [+] {}", msg.green()),
        Err(e) => println!(" [!] Plugin Error: {}", e.to_string().red()),
    }

    // 5. System Starten
    let vfs = VirtualFileSystem::new(user.username.clone(), DB_PATH);
    let vfs_shared = std::sync::Arc::new(tokio::sync::Mutex::new(vfs));

    let term_client = PytjaClient::new("127.0.0.1:50051");

    let mut term = Terminal::new(vfs_shared, username, plugin_manager, term_client);
    term.start().await?;

    Ok(())
}

fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
    buffer.trim().to_string()
}