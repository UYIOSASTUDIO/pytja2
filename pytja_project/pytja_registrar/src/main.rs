use anyhow::Result;
use pytja_core::{SqliteRepository, PytjaRepository, User};
use pytja_core::crypto::CryptoService;
use std::io::{self, Write};
use rpassword::read_password;
use colored::*;
use std::fs;
use std::path::Path;

// Wir simulieren den USB-Stick in diesem Ordner im Projekt-Root
const KEY_STORAGE_DIR: &str = "usb_drive";

#[tokio::main]
async fn main() -> Result<()> {
    println!("{}", "PYTJA IDENTITY REGISTRAR".blue().bold());
    println!("Initialize a new HIGH-SECURITY identity.\n");

    let db_path = "pytja.db";

    // Ordner für Keys erstellen, falls nicht vorhanden
    if !Path::new(KEY_STORAGE_DIR).exists() {
        fs::create_dir(KEY_STORAGE_DIR)?;
        println!("Created Key Storage Vault at './{}'", KEY_STORAGE_DIR);
    }

    let repo = SqliteRepository::new(db_path);
    repo.init()?;

    if let Err(e) = create_identity(&repo).await {
        println!("\n{}: {}", "ERROR".red().bold(), e);
    }

    Ok(())
}

async fn create_identity(repo: &SqliteRepository) -> Result<()> {
    print!("Choose Username: ");
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    let name = name.trim().to_string();

    if name.is_empty() { return Ok(()); }

    if repo.user_exists(&name).await? {
        println!("{}", "User already exists.".yellow());
        return Ok(());
    }

    print!("Set Decryption Password: ");
    io::stdout().flush()?;
    let pass = read_password()?;

    print!("Confirm Password: ");
    io::stdout().flush()?;
    let pass_confirm = read_password()?;

    if pass != pass_confirm {
        println!("{}", "Passwords do not match.".red());
        return Ok(());
    }

    println!("\n{}", "[*] Generating Ed25519 Keypair...".yellow());

    // 1. Raw Keys generieren
    let signing_key = CryptoService::generate_keypair();

    // 2. Private Key verschlüsseln
    // WICHTIG: Wir übergeben hier 'signing_key' direkt (nicht als String/Hex)
    println!("{}", "[*] Encrypting Private Key vault...".yellow());
    let encrypted_key_pem = CryptoService::encrypt_private_key_local(&signing_key, &pass)?;

    // 3. Datei speichern ("USB Stick")
    let key_file_path = format!("{}/{}.pytja", KEY_STORAGE_DIR, name);
    fs::write(&key_file_path, encrypted_key_pem)?;
    println!(" [+] Encrypted Key saved to: {}", key_file_path.cyan());

    // 4. Public Key für die Datenbank vorbereiten (als Hex String)
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.to_bytes());

    // 5. User Objekt erstellen
    let user = User {
        username: name.clone(),
        public_key: public_key_hex, // Hier kommt der String rein
        description: Some("Admin Operator".to_string()),
        role_level: 100,
        is_active: true,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    repo.create_user(&user).await?;

    println!("\n{}", "SUCCESS!".green().bold());
    println!("Identity '{}' secured.", name.cyan());
    println!("IMPORTANT: You need the file '{}' to login!", key_file_path);

    Ok(())
}