use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::dirs_path;
use crate::constants::{
    IDENTITY_KEY_FILE, KEYS_DIR, PEERS_FILE, TLS_CERT_FILE, TLS_KEY_FILE, TLS_SELF_SIGNED_SAN,
};
use crate::crypto::{Keypair, PublicKey};
use crate::error::Error;

/// Save an Ed25519 keypair to disk. File permissions set to owner-only.
pub fn save_keypair(keypair: &Keypair, path: &Path) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
    }
    let seed = keypair.seed_bytes();
    let encoded = BASE64_STANDARD.encode(seed);
    fs::write(path, encoded).map_err(|e| Error::Io(e.to_string()))?;
    set_permissions_owner_only(path)?;
    Ok(())
}

/// Load an Ed25519 keypair from disk.
pub fn load_keypair(path: &Path) -> Result<Keypair, Error> {
    let encoded = fs::read_to_string(path).map_err(|e| Error::Io(e.to_string()))?;
    let seed_bytes = BASE64_STANDARD
        .decode(encoded.trim())
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Keypair::from_seed(&seed_bytes)
}

/// Save a TLS certificate and private key as PEM files.
pub fn save_tls_cert(
    cert_pem: &str,
    key_pem: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), Error> {
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
    }
    fs::write(cert_path, cert_pem).map_err(|e| Error::Io(e.to_string()))?;
    fs::write(key_path, key_pem).map_err(|e| Error::Io(e.to_string()))?;
    set_permissions_owner_only(key_path)?;
    Ok(())
}

/// Load TLS certificate and key PEM from disk, convert to DER for rustls.
pub fn load_tls_cert(
    cert_path: &Path,
    key_path: &Path,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    Error,
> {
    let cert_pem = fs::read(cert_path).map_err(|e| Error::Io(e.to_string()))?;
    let key_pem = fs::read(key_path).map_err(|e| Error::Io(e.to_string()))?;

    let cert = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::Io(e.to_string()))?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| Error::Io(e.to_string()))?
        .ok_or_else(|| Error::Io("no private key found in PEM file".into()))?;

    Ok((cert, key))
}

/// Generate and save a self-signed TLS cert.
pub fn generate_and_save_tls_cert(cert_path: &Path, key_path: &Path) -> Result<(), Error> {
    let certified_key = rcgen::generate_simple_self_signed(vec![TLS_SELF_SIGNED_SAN.into()])
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.key_pair.serialize_pem();
    save_tls_cert(&cert_pem, &key_pem, cert_path, key_path)
}

/// Default path for the identity key file.
pub fn identity_key_path() -> PathBuf {
    dirs_path().join(KEYS_DIR).join(IDENTITY_KEY_FILE)
}

/// Default path for the TLS certificate PEM.
pub fn tls_cert_path() -> PathBuf {
    dirs_path().join(KEYS_DIR).join(TLS_CERT_FILE)
}

/// Default path for the TLS private key PEM.
pub fn tls_key_path() -> PathBuf {
    dirs_path().join(KEYS_DIR).join(TLS_KEY_FILE)
}

/// Default path for the peer store.
pub fn peers_path() -> PathBuf {
    dirs_path().join(PEERS_FILE)
}

/// Check if setup has been completed.
pub fn is_setup_complete() -> bool {
    crate::config::Config::default_path().exists() && identity_key_path().exists()
}

// --- Peer Store (TOFU key pinning) ---

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerStore {
    pub peers: HashMap<String, PeerRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub address: String,
    pub first_seen: String,
    pub last_seen: String,
}

impl PeerStore {
    pub fn load(path: &Path) -> Result<Self, Error> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(path).map_err(|e| Error::Io(e.to_string()))?;
        serde_json::from_str(&data).map_err(|e| Error::Io(e.to_string()))
    }

    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let data = serde_json::to_string_pretty(self).map_err(|e| Error::Io(e.to_string()))?;
        fs::write(path, data).map_err(|e| Error::Io(e.to_string()))
    }

    /// Look up a peer by public key. Returns None if unknown.
    pub fn get(&self, public_key: &PublicKey) -> Option<&PeerRecord> {
        let key_str = public_key.to_encoded();
        self.peers.get(&key_str)
    }

    /// Record or update a peer.
    pub fn upsert(&mut self, public_key: &PublicKey, address: &str) {
        let key_str = public_key.to_encoded();
        let now = crate::now_utc();
        self.peers
            .entry(key_str)
            .and_modify(|r| {
                if !address.is_empty() {
                    r.address = address.to_string();
                }
                r.last_seen = now.clone();
            })
            .or_insert(PeerRecord {
                address: address.to_string(),
                first_seen: now.clone(),
                last_seen: now,
            });
    }
}

#[cfg(unix)]
fn set_permissions_owner_only(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms).map_err(|e| Error::Io(e.to_string()))
}

#[cfg(not(unix))]
fn set_permissions_owner_only(_path: &Path) -> Result<(), Error> {
    Ok(())
}
