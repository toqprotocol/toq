use base64::prelude::*;
use ed25519_dalek::{Signer, Verifier};
use rand::rngs::OsRng;
use std::fmt;

use crate::error::Error;

const KEY_PREFIX: &str = "ed25519:";
const SIGNATURE_PREFIX: &str = "ed25519:";

pub struct Keypair {
    signing_key: ed25519_dalek::SigningKey,
}

impl Keypair {
    pub fn generate() -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.signing_key.verifying_key())
    }

    pub fn sign(&self, data: &[u8]) -> String {
        let sig = self.signing_key.sign(data);
        format!(
            "{}{}",
            SIGNATURE_PREFIX,
            BASE64_STANDARD.encode(sig.to_bytes())
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(ed25519_dalek::VerifyingKey);

impl PublicKey {
    pub fn verify(&self, data: &[u8], signature: &str) -> Result<(), Error> {
        let encoded = signature
            .strip_prefix(SIGNATURE_PREFIX)
            .ok_or_else(|| Error::Crypto("signature must start with ed25519:".into()))?;

        let bytes = BASE64_STANDARD
            .decode(encoded)
            .map_err(|e| Error::Crypto(e.to_string()))?;

        let sig =
            ed25519_dalek::Signature::from_slice(&bytes).map_err(|_| Error::InvalidSignature)?;

        self.0
            .verify(data, &sig)
            .map_err(|_| Error::InvalidSignature)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn from_encoded(s: &str) -> Result<Self, Error> {
        let encoded = s
            .strip_prefix(KEY_PREFIX)
            .ok_or_else(|| Error::Crypto("public key must start with ed25519:".into()))?;
        let bytes = BASE64_STANDARD
            .decode(encoded)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::Crypto("invalid public key length".into()))?,
        )
        .map_err(|_| Error::Crypto("invalid public key".into()))?;
        Ok(Self(key))
    }

    pub fn to_encoded(&self) -> String {
        format!(
            "{}{}",
            KEY_PREFIX,
            BASE64_STANDARD.encode(self.0.as_bytes())
        )
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_encoded())
    }
}
