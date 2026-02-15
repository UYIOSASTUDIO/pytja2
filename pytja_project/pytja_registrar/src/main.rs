use anyhow::Result;
use pytja_core::{DriverManager, DatabaseType, PytjaRepository, User};
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
    println!("{}", "PYTJA IDENTITY REGISTRAR V3.0 (RBAC)".blue().bold());
    println!("Initialize a new HIGH-SECURITY ADMIN identity.\n");

    let db_path = "pytja.db";

    if !Path::new(KEY_STORAGE_DIR).exists() {
        fs::create_dir(KEY_STORAGE_DIR)?;
    }

    let manager = DriverManager::new();
    manager.mount("primary", db_path, DatabaseType::Sqlite).await
        .map_err(|e| anyhow::anyhow!("Failed to mount DB: {}", e))?;

    let repo = manager.get_repo("primary").expect("DB failed to load");
    repo.init().await.map_err(|e| anyhow::anyhow!("DB Init failed: {}", e))?;

    if let Err(e) = create_identity(repo).await {
        println!("\n{}: {}", "ERROR".red().bold(), e);
    }

    Ok(())
}

async fn create_identity(repo: Arc<dyn PytjaRepository>) -> Result<()> {
    print!("Choose Admin Username: ");
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
    let signing_key = CryptoService::generate_keypair();

    let key_file_path = format!("{}/{}.pytja", KEY_STORAGE_DIR, name);
    let encrypted_key_pem = CryptoService::encrypt_private_key_local(&signing_key, &pass)?;
    fs::write(&key_file_path, encrypted_key_pem)?;

    println!(" [+] Encrypted Key saved to: {}", key_file_path.cyan());

    let verifying_key = signing_key.verifying_key();
    let public_key_hex = CryptoService::pubkey_to_hex(&verifying_key);

    let user = User {
        username: name.clone(),
        // FIX: String -> Vec<u8> Konvertierung
        public_key: public_key_hex.into_bytes(),
        description: Some("Root Administrator".to_string()),
        role: "admin".to_string(), // Setzt die Admin-Rolle
        is_active: true,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    repo.create_user(&user).await?;

    println!("\n{}", "SUCCESS! ADMIN CREATED.".green().bold());
    Ok(())
}