use pytja_core::crypto::CryptoService;
use ed25519_dalek::SigningKey;
use anyhow::{Result, anyhow};
use std::path::PathBuf;
use colored::*;
use std::io::{self, Write};
use rpassword;

pub struct IdentityManager {
    key_path: PathBuf,
}

impl IdentityManager {
    pub fn new() -> Self {
        // Wir speichern den Key im Home-Verzeichnis des Users
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let key_path = home.join(".pytja_identity");
        Self { key_path }
    }

    pub fn has_identity(&self) -> bool {
        self.key_path.exists()
    }

    /// Lädt und entschlüsselt den Private Key
    pub fn load_identity(&self) -> Result<SigningKey> {
        println!("🔑 Identity file found at: {}", self.key_path.display());
        print!("🔓 Enter password to decrypt identity: ");
        io::stdout().flush()?;
        let password = rpassword::read_password()?;

        let encrypted_content = std::fs::read_to_string(&self.key_path)?;

        println!("{}", "Decrypting...".yellow());
        match CryptoService::decrypt_private_key_local(&encrypted_content, &password) {
            Ok(key) => {
                println!("{}", "Success! Identity loaded.".green());
                Ok(key)
            },
            Err(_) => Err(anyhow!("Decryption failed. Wrong password or corrupted file.")),
        }
    }

    /// Erstellt eine neue Identität (Interaktiv)
    pub fn create_new_identity(&self) -> Result<SigningKey> {
        println!("{}", "✨ NO IDENTITY FOUND. GENERATING NEW SECURE PROFILE...".blue().bold());

        print!("🔒 Choose a password to protect your local key: ");
        io::stdout().flush()?;
        let p1 = rpassword::read_password()?;

        print!("🔒 Confirm password: ");
        io::stdout().flush()?;
        let p2 = rpassword::read_password()?;

        if p1 != p2 {
            return Err(anyhow!("Passwords do not match."));
        }
        if p1.is_empty() {
            return Err(anyhow!("Password cannot be empty."));
        }

        println!("{}", "Generating Ed25519 Keypair...".yellow());
        let signing_key = CryptoService::generate_keypair();
        let verifying_key = signing_key.verifying_key();

        // Verschlüsseln
        let encrypted = CryptoService::encrypt_private_key_local(&signing_key, &p1)?;

        // Speichern
        std::fs::write(&self.key_path, encrypted)?;

        println!("{}", "✅ Identity saved to disk encrypted.".green());
        println!("📝 YOUR PUBLIC KEY (Give this to the admin):");
        println!("{}", CryptoService::pubkey_to_hex(&verifying_key).cyan().bold());
        println!("---------------------------------------------------");

        Ok(signing_key)
    }
}