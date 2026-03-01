use base64::prelude::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::crypto::{Keypair, PublicKey};
use crate::error::Error;
use crate::types::Address;

pub const MAGIC_BYTES: [u8; 4] = [0x54, 0x4F, 0x51, 0x01];
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct HandshakeResult {
    pub peer_public_key: PublicKey,
    pub peer_address: Address,
    pub session_id: String,
}

#[derive(Serialize, Deserialize)]
struct InitiatorCredentials {
    public_key: String,
    challenge: String,
    challenge_signature: String,
    address: Address,
    protocol_version: String,
    rotation_proof: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ReceiverCredentials {
    public_key: String,
    challenge: String,
    challenge_signature: String,
    address: Address,
    session_id: String,
    rotation_proof: Option<String>,
}

fn generate_challenge() -> (Vec<u8>, String) {
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let encoded = BASE64_STANDARD.encode(nonce);
    (nonce.to_vec(), encoded)
}

/// Initiator side: send magic bytes + credentials, receive and verify receiver credentials.
pub async fn initiate<S>(
    stream: &mut S,
    keypair: &Keypair,
    address: &Address,
) -> Result<HandshakeResult, Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Step 1: magic bytes
    stream
        .write_all(&MAGIC_BYTES)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Step 2: send initiator credentials
    let (challenge_bytes, challenge_b64) = generate_challenge();
    let creds = InitiatorCredentials {
        public_key: keypair.public_key().to_encoded(),
        challenge: challenge_b64,
        challenge_signature: keypair.sign(&challenge_bytes),
        address: address.clone(),
        protocol_version: "0.1".into(),
        rotation_proof: None,
    };
    write_length_prefixed(stream, &serde_json::to_vec(&creds)?).await?;

    // Step 3: receive receiver credentials
    let data = read_length_prefixed(stream).await?;
    let recv_creds: ReceiverCredentials =
        serde_json::from_slice(&data).map_err(|e| Error::InvalidEnvelope(e.to_string()))?;

    // Verify receiver
    let peer_key = PublicKey::from_encoded(&recv_creds.public_key)?;
    let recv_challenge_bytes = BASE64_STANDARD
        .decode(&recv_creds.challenge)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    peer_key.verify(&recv_challenge_bytes, &recv_creds.challenge_signature)?;

    Ok(HandshakeResult {
        peer_public_key: peer_key,
        peer_address: recv_creds.address,
        session_id: recv_creds.session_id,
    })
}

/// Receiver side: verify magic bytes + initiator credentials, send receiver credentials.
pub async fn accept<S>(
    stream: &mut S,
    keypair: &Keypair,
    address: &Address,
) -> Result<HandshakeResult, Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Step 1: verify magic bytes
    let mut magic = [0u8; 4];
    stream
        .read_exact(&mut magic)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))?;
    if magic != MAGIC_BYTES {
        return Err(Error::InvalidEnvelope("invalid magic bytes".into()));
    }

    // Step 2: receive initiator credentials
    let data = read_length_prefixed(stream).await?;
    let init_creds: InitiatorCredentials =
        serde_json::from_slice(&data).map_err(|e| Error::InvalidEnvelope(e.to_string()))?;

    // Verify initiator
    let peer_key = PublicKey::from_encoded(&init_creds.public_key)?;
    let init_challenge_bytes = BASE64_STANDARD
        .decode(&init_creds.challenge)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    peer_key.verify(&init_challenge_bytes, &init_creds.challenge_signature)?;

    // Step 3: send receiver credentials
    let (challenge_bytes, challenge_b64) = generate_challenge();
    let session_id = format!("sess-{}", Uuid::new_v4());
    let creds = ReceiverCredentials {
        public_key: keypair.public_key().to_encoded(),
        challenge: challenge_b64,
        challenge_signature: keypair.sign(&challenge_bytes),
        address: address.clone(),
        session_id: session_id.clone(),
        rotation_proof: None,
    };
    write_length_prefixed(stream, &serde_json::to_vec(&creds)?).await?;

    Ok(HandshakeResult {
        peer_public_key: peer_key,
        peer_address: init_creds.address,
        session_id,
    })
}

async fn write_length_prefixed<S>(stream: &mut S, data: &[u8]) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let len = (data.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(())
}

async fn read_length_prefixed<S>(stream: &mut S) -> Result<Vec<u8>, Error>
where
    S: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 65536 {
        return Err(Error::InvalidEnvelope("handshake payload too large".into()));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(buf)
}
