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
use std::sync::Arc;
use tokio::sync::Mutex;
mod network_client; // NEU
use network_client::PytjaClient; // NEU

mod terminal;
mod vfs;
mod plugins;
use plugins::PluginManager;

use terminal::Terminal;
use vfs::VirtualFileSystem;

mod identity; // NEU
use identity::IdentityManager;

// KONSTANTEN
const DB_PATH: &str = "pytja.db";
const KEY_DIR: &str = "usb_drive"; // WICHTIG: Wieder da!

#[tokio::main]
async fn main() -> Result<()> {

    let _guard = telemetry::init_telemetry("./logs", "pytja_shell.log");

    print!("\x1B[2J\x1B[1;1H"); // Clear Screen
    println!("{}", "INITIALIZING SECURE LINK V3.0 (Enterprise)".green().bold());

    // 2. IDENTITÄT LADEN (Statt lokaler DB)
    // Wir nutzen den IdentityManager, um den Key von der Platte zu laden
    let identity_mgr = IdentityManager::new();

    let signing_key = if identity_mgr.has_identity() {
        match identity_mgr.load_identity() {
            Ok(k) => k,
            Err(e) => {
                println!("{}", e.to_string().red());
                return Ok(()); // Abbruch bei falschem Passwort
            }
        }
    } else {
        match identity_mgr.create_new_identity() {
            Ok(k) => k,
            Err(e) => {
                println!("{}", e.to_string().red());
                return Ok(());
            }
        }
    };

    // Public Key berechnen (Das ist unsere ID)
    let verifying_key = signing_key.verifying_key();
    let pub_key_hex = CryptoService::pubkey_to_hex(&verifying_key);

    println!("Identity loaded. Key-ID: {}", pub_key_hex.chars().take(8).collect::<String>().dimmed());

    // 3. Username Abfrage
    // (Der Server braucht den Namen, um den gespeicherten PubKey zu finden)
    print!("👤 Enter Agent Codename: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    // 4. NETZWERK CLIENT STARTEN
    // Wir geben dem Client jetzt unseren Schlüssel mit!
    let mut client = PytjaClient::new("127.0.0.1:50051", signing_key, username.clone());

    // 5. SECURE HANDSHAKE (Der Login beim Server)
    if !client.perform_handshake().await? {
        println!("{}", "CRITICAL: Authentication failed. Server rejected identity.".red().bold());
        return Ok(());
    }

    println!("");

    // 6. Plugins laden (Deine bestehende Logik)
    println!("{}", "[*] Initializing Module System...".yellow());
    // Pfad evtl. anpassen, je nachdem wo du startest
    let mut plugin_manager = PluginManager::new("../pytja_plugins");
    match plugin_manager.scan_and_load() {
        Ok(msg) => println!(" [+] {}", msg.green()),
        Err(e) => println!(" [!] Plugin Error: {}", e.to_string().red()),
    }

    // 7. System Starten
    // Das VFS ist jetzt nur noch für Caching/Temp da, nicht mehr für Auth
    let vfs = VirtualFileSystem::new(username.clone(), DB_PATH);
    let vfs_shared = Arc::new(Mutex::new(vfs));

    // Terminal übergeben wir den authentifizierten Client
    let mut term = Terminal::new(vfs_shared, username, plugin_manager, client);
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