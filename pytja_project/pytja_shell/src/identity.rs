use anyhow::{Result, Context, anyhow};
use ed25519_dalek::{SigningKey, SecretKey};
use std::fs;
use std::path::Path;
use base64::{Engine as _, engine::general_purpose};
use dialoguer::Password;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;

pub struct Identity {
    pub username: String,
    pub keypair: SigningKey,
    pub role: String,
}

impl Identity {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read identity file at {}", path))?;

        // Parsing der Key-Value Struktur
        let mut username = String::new();
        let mut priv_blob_b64 = String::new();
        let mut role = String::new();
        let mut version = "V1"; // Default Fallback

        for line in content.lines() {
            if let Some(v) = line.strip_prefix("PYTJA-ID-") {
                if v.contains("V2-ENCRYPTED") { version = "V2"; }
            }
            if let Some(v) = line.strip_prefix("USER:") { username = v.trim().to_string(); }
            if let Some(v) = line.strip_prefix("PRIV:") { priv_blob_b64 = v.trim().to_string(); }
            if let Some(v) = line.strip_prefix("ROLE:") { role = v.trim().to_string(); }
        }

        if username.is_empty() || priv_blob_b64.is_empty() {
            return Err(anyhow!("Invalid identity file format: Missing USER or PRIV field."));
        }

        println!("Identity detected: {} ({})", username, path);

        // Passwort abfragen
        let password = Password::new()
            .with_prompt("Enter Identity Password")
            .interact()?;

        // Private Key Bytes dekodieren
        let encrypted_blob = general_purpose::STANDARD.decode(&priv_blob_b64)
            .map_err(|e| anyhow!("Base64 decode failed: {}", e))?;

        let decrypted_priv_key = if version == "V2" {
            // V2 Format: [Salt: 16][Nonce: 12][Ciphertext: Rest]
            if encrypted_blob.len() < 16 + 12 {
                return Err(anyhow!("Corrupted identity file (blob too short)"));
            }

            let salt = &encrypted_blob[0..16];
            let nonce_bytes = &encrypted_blob[16..28];
            let ciphertext = &encrypted_blob[28..];

            // 1. Key Derivation (Muss exakt zum Registrar passen!)
            let mut derived_key = [0u8; 32];
            pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, 100_000, &mut derived_key);

            // 2. Entschlüsseln
            let cipher = Aes256Gcm::new(&derived_key.into());
            let nonce = Nonce::from_slice(nonce_bytes);

            cipher.decrypt(nonce, ciphertext)
                .map_err(|_| anyhow!("DECRYPTION FAILED. Wrong password?"))?
        } else {
            // Fallback V1 (einfachere/andere Logik oder gar nicht unterstützt)
            return Err(anyhow!("Legacy V1 identity format is no longer supported. Please recreate your identity with the registrar."));
        };

        // Keypair wiederherstellen
        let secret_key: [u8; 32] = decrypted_priv_key.try_into()
            .map_err(|_| anyhow!("Decrypted key has invalid length"))?;

        let signing_key = SigningKey::from_bytes(&secret_key);

        Ok(Self {
            username,
            keypair: signing_key,
            role,
        })
    }
}