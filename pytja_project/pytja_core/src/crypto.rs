use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
// FIX: AeadCore hinzugefügt
use aes_gcm::{aead::{Aead, AeadCore, KeyInit}, Aes256Gcm, Nonce};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

const SALT: &[u8] = b"pytja_protocol_salt_v2";
const ITERATIONS: u32 = 600_000;

pub struct CryptoService;

impl CryptoService {
    pub fn generate_keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    pub fn pubkey_to_hex(key: &VerifyingKey) -> String {
        hex::encode(key.to_bytes())
    }

    pub fn sign_message(priv_key: &SigningKey, message: &[u8]) -> String {
        let signature = priv_key.sign(message);
        BASE64.encode(signature.to_bytes())
    }

    pub fn verify_signature(pub_key_hex: &str, message: &[u8], signature_b64: &str) -> Result<bool> {
        let pub_bytes = hex::decode(pub_key_hex)?;
        let pub_key = VerifyingKey::from_bytes(&pub_bytes.try_into().map_err(|_| anyhow!("Invalid PubKey length"))?)?;

        let sig_bytes = BASE64.decode(signature_b64)?;
        let signature = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow!("Invalid Sig length"))?);

        Ok(pub_key.verify(message, &signature).is_ok())
    }

    pub fn encrypt_private_key_local(priv_key: &SigningKey, password: &str) -> Result<String> {
        let key_bytes = priv_key.to_bytes();

        let mut key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), SALT, ITERATIONS, &mut key).unwrap();
        let cipher = Aes256Gcm::new(&key.into());

        // Hier nutzen wir jetzt den importierten Trait AeadCore
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, key_bytes.as_ref()).map_err(|_| anyhow!("Encryption failed"))?;

        let mut combined = nonce.to_vec();
        combined.extend(ciphertext);
        Ok(BASE64.encode(combined))
    }

    pub fn decrypt_private_key_local(encrypted_b64: &str, password: &str) -> Result<SigningKey> {
        let data = BASE64.decode(encrypted_b64)?;
        if data.len() < 12 { return Err(anyhow!("Invalid key file format")); }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let mut key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), SALT, ITERATIONS, &mut key).unwrap();
        let cipher = Aes256Gcm::new(&key.into());

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| anyhow!("Wrong Password or Corrupted Key"))?;

        let signing_key = SigningKey::from_bytes(&plaintext.try_into().map_err(|_| anyhow!("Invalid Key Length"))?);
        Ok(signing_key)
    }

    pub fn generate_random_challenge() -> String {
        use rand::RngCore;
        let mut data = [0u8; 32]; // 32 Bytes Zufall
        OsRng.fill_bytes(&mut data);
        hex::encode(data)
    }
}