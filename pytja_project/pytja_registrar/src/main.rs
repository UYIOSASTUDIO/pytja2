use anyhow::Result;
use pytja_core::repo::PytjaRepository;
use pytja_core::models::User;
use pytja_core::drivers::sqlite::SqliteDriver;
use std::fs;
use std::path::Path;
use colored::*;
use dialoguer::{Input, Password}; // Moderner als read_password

// Krypto Imports
use ed25519_dalek::{SigningKey, Signer};
use rand::{rngs::OsRng, RngCore};
use base64::{Engine as _, engine::general_purpose};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;

const KEY_STORAGE_DIR: &str = "usb_drive";

#[tokio::main]
async fn main() -> Result<()> {
    println!("{}", "PYTJA IDENTITY REGISTRAR V3.0 (Enterprise)".blue().bold());
    println!("Initialize a new HIGH-SECURITY ADMIN identity.\n");

    // 1. Ordner prüfen
    if !Path::new(KEY_STORAGE_DIR).exists() {
        fs::create_dir(KEY_STORAGE_DIR)?;
    }

    // 2. Datenbank verbinden (Async & Direkt)
    let db_path = "pytja.db";
    println!("Connecting to database: {}", db_path);

    // FIX: DriverManager durch direkten Treiber ersetzt (einfacher für CLI Tools)
    let repo = SqliteDriver::new(db_path).await
        .map_err(|e| anyhow::anyhow!("Failed to connect to DB: {}", e))?;

    repo.init().await.map_err(|e| anyhow::anyhow!("DB Init failed: {}", e))?;

    // 3. Identität erstellen
    if let Err(e) = create_identity(&repo).await {
        println!("\n{}: {}", "ERROR".red().bold(), e);
    }

    Ok(())
}

async fn create_identity(repo: &SqliteDriver) -> Result<()> {
    // A. Username abfragen
    let username: String = Input::new()
        .with_prompt("Choose Admin Username")
        .interact_text()?;

    if repo.user_exists(&username).await.unwrap_or(false) {
        println!("{}", "User already exists inside Database.".yellow());
        return Ok(());
    }

    // B. Passwort abfragen (Sicher)
    let password = Password::new()
        .with_prompt("Set Identity Password (needed for login)")
        .with_confirmation("Confirm Password", "Passwords mismatching")
        .interact()?;

    println!("\n{}", "[*] Generating Ed25519 Keypair...".yellow());

    // C. Keys generieren
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Bytes für Speicherung
    let pub_key_bytes = verifying_key.to_bytes().to_vec();
    let priv_key_bytes = signing_key.to_bytes();

    // D. Verschlüsselung (Password -> AES Key -> Encrypted Private Key)
    println!("Encrypting private key...");

    // 1. Salt
    let mut salt = [0u8; 16];
    csprng.fill_bytes(&mut salt);

    // 2. Key Derivation (PBKDF2)
    let mut derived_key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, 100_000, &mut derived_key);

    // 3. AES-GCM Encrypt
    let cipher = Aes256Gcm::new(&derived_key.into());
    let mut nonce_bytes = [0u8; 12];
    csprng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_priv_key = cipher.encrypt(nonce, priv_key_bytes.as_ref())
        .map_err(|e| anyhow::anyhow!("Crypto error: {}", e))?;

    // E. Identity File bauen
    let mut file_payload = Vec::new();
    file_payload.extend_from_slice(&salt);        // 16 Bytes Salt
    file_payload.extend_from_slice(&nonce_bytes); // 12 Bytes Nonce
    file_payload.extend_from_slice(&encrypted_priv_key); // Rest: Ciphertext

    let payload_b64 = general_purpose::STANDARD.encode(&file_payload);
    let pub_b64 = general_purpose::STANDARD.encode(&pub_key_bytes);

    let key_file_path = format!("{}/{}.pytja", KEY_STORAGE_DIR, username);

    // Format für V2 (Verschlüsselt)
    let id_content = format!(
        "PYTJA-ID-V2-ENCRYPTED\nUSER:{}\nPRIV:{}\nPUB:{}\nROLE:admin",
        username,
        payload_b64,
        pub_b64
    );

    fs::write(&key_file_path, id_content)?;
    println!(" [+] Encrypted Identity saved to: {}", key_file_path.cyan());

    // F. User in DB speichern (Fix für neue Struct Felder)
    let user = User {
        username: username.clone(),
        public_key: pub_key_bytes, // Ist schon Vec<u8>
        description: Some("Root Administrator".to_string()),
        role: "admin".to_string(),
        is_active: true,
        // FIX: Zeitstempel als f64
        created_at: chrono::Utc::now().timestamp() as f64,
        // FIX: Neues Feld Quota
        quota_limit: 0, // 0 = Unlimited
    };

    repo.create_user(&user).await
        .map_err(|e| anyhow::anyhow!("DB Save Error: {}", e))?;

    println!("\n{}", "SUCCESS! ADMIN CREATED.".green().bold());
    Ok(())
}