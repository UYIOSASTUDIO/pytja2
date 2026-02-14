use anyhow::Result;
use pytja_core::{DriverManager, DatabaseType, PytjaRepository, User}; // Neue Imports
use pytja_core::crypto::CryptoService;
use std::io::{self, Write};
use rpassword::read_password;
use colored::*;
use std::fs;
use std::path::Path;
use std::sync::Arc;

const KEY_STORAGE_DIR: &str = "usb_drive";

#[tokio::main]
async fn main() -> Result<()> {
    println!("{}", "PYTJA IDENTITY REGISTRAR".blue().bold());
    println!("Initialize a new HIGH-SECURITY identity.\n");

    let db_path = "pytja.db";

    if !Path::new(KEY_STORAGE_DIR).exists() {
        fs::create_dir(KEY_STORAGE_DIR)?;
        println!("Created Key Storage Vault at './{}'", KEY_STORAGE_DIR);
    }

    // NEU: DriverManager nutzen statt direktes Repo
    let manager = DriverManager::new();

    // Async Mount!
    manager.mount("primary", db_path, DatabaseType::Sqlite).await
        .map_err(|e| anyhow::anyhow!("Failed to mount DB: {}", e))?;

    let repo = manager.get_repo("primary").expect("DB failed to load");

    // Async Init!
    repo.init().await.map_err(|e| anyhow::anyhow!("DB Init failed: {}", e))?;

    if let Err(e) = create_identity(repo).await {
        println!("\n{}: {}", "ERROR".red().bold(), e);
    }

    Ok(())
}

// Signatur geändert: Nimmt Arc<dyn PytjaRepository>
async fn create_identity(repo: Arc<dyn PytjaRepository>) -> Result<()> {
    print!("Choose Username: ");
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    let name = name.trim().to_string();

    if name.is_empty() { return Ok(()); }

    // Async Call!
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

    let signing_key = CryptoService::generate_keypair();

    println!("{}", "[*] Encrypting Private Key vault...".yellow());
    let encrypted_key_pem = CryptoService::encrypt_private_key_local(&signing_key, &pass)?;

    let key_file_path = format!("{}/{}.pytja", KEY_STORAGE_DIR, name);
    fs::write(&key_file_path, encrypted_key_pem)?;
    println!(" [+] Encrypted Key saved to: {}", key_file_path.cyan());

    let verifying_key = signing_key.verifying_key();
    let public_key_hex = CryptoService::pubkey_to_hex(&verifying_key);

    let user = User {
        username: name.clone(),
        public_key: public_key_hex,
        description: Some("Admin Operator".to_string()),
        role_level: 100,
        is_active: true,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    // Async Call!
    repo.create_user(&user).await?;

    println!("\n{}", "SUCCESS!".green().bold());
    println!("Identity '{}' secured.", name.cyan());
    println!("IMPORTANT: You need the file '{}' to login!", key_file_path);

    Ok(())
}