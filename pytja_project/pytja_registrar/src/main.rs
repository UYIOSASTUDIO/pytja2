use pytja_core::drivers::sqlite::SqliteDriver;
use pytja_core::repo::PytjaRepository;
use pytja_core::models::User;
use ed25519_dalek::{SigningKey, Signer};
use rand::{rngs::OsRng, RngCore};
use std::fs;
use std::path::Path;
use base64::{Engine as _, engine::general_purpose};
use dialoguer::{Input, Password};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("--- PYTJA IDENTITY REGISTRAR (SECURE V2) ---");

    // 1. Setup
    if !Path::new("usb_drive").exists() { fs::create_dir("usb_drive")?; }

    let db_path = "pytja.db";
    let repo = SqliteDriver::new(db_path).await?;
    repo.init().await?;

    // 2. Inputs
    let username: String = Input::new().with_prompt("Username").interact_text()?;

    // Check if user exists
    if repo.user_exists(&username).await.unwrap_or(false) {
        println!("⚠️  User '{}' already exists in DB.", username);
        // Wir machen weiter, um z.B. nur das Keyfile neu zu erstellen
    }

    let password = Password::new()
        .with_prompt("Identity Password")
        .with_confirmation("Confirm Password", "Mismatch")
        .interact()?;

    // 3. Crypto Gen
    println!("Generating keys...");
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let pub_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
    let priv_key_bytes = signing_key.to_bytes();

    // 4. Encryption (AES-256-GCM)
    // Salt (16 Bytes) + Nonce (12 Bytes)
    let mut salt = [0u8; 16];
    csprng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; 12];
    csprng.fill_bytes(&mut nonce_bytes);

    // Key Derivation
    let mut derived_key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, 100_000, &mut derived_key);

    let cipher = Aes256Gcm::new(&derived_key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_priv = cipher.encrypt(nonce, priv_key_bytes.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // 5. File Blob: Salt(16) + Nonce(12) + Ciphertext(...)
    let mut payload = Vec::new();
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&encrypted_priv);

    let priv_b64 = general_purpose::STANDARD.encode(&payload);
    let pub_b64 = general_purpose::STANDARD.encode(&pub_key_bytes);

    let filename = format!("usb_drive/{}.pytja", username);
    let content = format!("PYTJA-ID-V2-ENCRYPTED\nUSER:{}\nPRIV:{}\nPUB:{}\nROLE:admin", username, priv_b64, pub_b64);

    fs::write(&filename, content)?;
    println!("✅ Identity saved to: {}", filename);

    // 6. DB Save
    let user = User {
        username: username.clone(),
        public_key: pub_key_bytes,
        role: "admin".to_string(),
        is_active: true,
        created_at: chrono::Utc::now().timestamp() as f64,
        quota_limit: 0,
        description: Some("Admin User".into()),
    };

    // Ignore error if user exists
    let _ = repo.create_user(&user).await;
    println!("✅ User registered in Database.");

    Ok(())
}