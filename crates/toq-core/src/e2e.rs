use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::prelude::*;
use sha2::{Digest, Sha512};

use crate::crypto::Keypair;
use crate::error::Error;

/// Derive an X25519 secret key from an Ed25519 keypair seed.
fn derive_x25519_secret(keypair: &Keypair) -> x25519_dalek::StaticSecret {
    let hash = Sha512::digest(keypair.seed_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    x25519_dalek::StaticSecret::from(bytes)
}

/// Derive the X25519 public key from an Ed25519 keypair.
pub fn x25519_public_key(keypair: &Keypair) -> x25519_dalek::PublicKey {
    let secret = derive_x25519_secret(keypair);
    x25519_dalek::PublicKey::from(&secret)
}

/// Perform X25519 key agreement and return a 32-byte shared secret.
fn shared_secret(
    local_keypair: &Keypair,
    remote_x25519_public: &x25519_dalek::PublicKey,
) -> [u8; 32] {
    let local_secret = derive_x25519_secret(local_keypair);
    let shared = local_secret.diffie_hellman(remote_x25519_public);
    *shared.as_bytes()
}

/// Encrypt a plaintext body using AES-256-GCM with a shared secret derived from X25519.
/// Returns (ciphertext_base64, nonce_base64).
pub fn encrypt_body(
    plaintext: &[u8],
    local_keypair: &Keypair,
    remote_x25519_public: &x25519_dalek::PublicKey,
) -> Result<(String, String), Error> {
    let key_bytes = shared_secret(local_keypair, remote_x25519_public);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| Error::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    Ok((
        BASE64_STANDARD.encode(&ciphertext),
        BASE64_STANDARD.encode(nonce_bytes),
    ))
}

/// Decrypt a ciphertext body using AES-256-GCM with a shared secret derived from X25519.
pub fn decrypt_body(
    ciphertext_b64: &str,
    nonce_b64: &str,
    local_keypair: &Keypair,
    remote_x25519_public: &x25519_dalek::PublicKey,
) -> Result<Vec<u8>, Error> {
    let key_bytes = shared_secret(local_keypair, remote_x25519_public);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| Error::Crypto(e.to_string()))?;

    let ciphertext = BASE64_STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let nonce_bytes = BASE64_STANDARD
        .decode(nonce_b64)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| Error::Crypto(e.to_string()))
}
