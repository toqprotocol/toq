use base64::prelude::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::constants::{MAGIC_BYTES, MAX_HANDSHAKE_PAYLOAD, PROTOCOL_VERSION, SESSION_ID_PREFIX};
use crate::crypto::{Keypair, PublicKey};
use crate::error::Error;
use crate::framing;
use crate::types::Address;

#[derive(Debug)]
pub struct HandshakeResult {
    pub peer_public_key: PublicKey,
    pub peer_address: Address,
    pub session_id: String,
    pub rotation_proof: Option<String>,
    pub target_agent: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct InitiatorCredentials {
    public_key: String,
    challenge: String,
    challenge_signature: String,
    address: Address,
    protocol_version: String,
    rotation_proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_agent: Option<String>,
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
    target_agent: Option<&str>,
) -> Result<HandshakeResult, Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Step 1: magic bytes
    stream
        .write_all(&MAGIC_BYTES)
        .await
        .map_err(|e| Error::Io(e.to_string()))?;

    // Step 2: send initiator credentials
    let (challenge_bytes, challenge_b64) = generate_challenge();
    let creds = InitiatorCredentials {
        public_key: keypair.public_key().to_encoded(),
        challenge: challenge_b64,
        challenge_signature: keypair.sign(&challenge_bytes),
        address: address.clone(),
        protocol_version: PROTOCOL_VERSION.into(),
        rotation_proof: None,
        target_agent: target_agent.map(String::from),
    };
    framing::write_length_prefixed(stream, &serde_json::to_vec(&creds)?).await?;

    // Step 3: receive receiver credentials
    let data = framing::read_length_prefixed(stream, MAX_HANDSHAKE_PAYLOAD).await?;
    let recv_creds: ReceiverCredentials =
        serde_json::from_slice(&data).map_err(|e| Error::InvalidEnvelope(e.to_string()))?;

    // Verify receiver
    let peer_key = PublicKey::from_encoded(&recv_creds.public_key)?;
    let recv_challenge_bytes = BASE64_STANDARD
        .decode(&recv_creds.challenge)
        .map_err(|e| Error::Io(e.to_string()))?;
    peer_key.verify(&recv_challenge_bytes, &recv_creds.challenge_signature)?;

    Ok(HandshakeResult {
        peer_public_key: peer_key,
        peer_address: recv_creds.address,
        session_id: recv_creds.session_id,
        rotation_proof: recv_creds.rotation_proof,
        target_agent: target_agent.map(String::from),
    })
}

/// Receiver side: verify magic bytes + initiator credentials, send receiver credentials.
/// If blocked_keys is provided, rejects initiators whose key is in the set.
pub async fn accept<S>(
    stream: &mut S,
    keypair: &Keypair,
    address: &Address,
    blocked_keys: Option<&std::collections::HashSet<[u8; 32]>>,
) -> Result<HandshakeResult, Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Step 1: verify magic bytes
    let mut magic = [0u8; 4];
    stream
        .read_exact(&mut magic)
        .await
        .map_err(|e| Error::Io(e.to_string()))?;
    if magic != MAGIC_BYTES {
        return Err(Error::InvalidEnvelope("invalid magic bytes".into()));
    }

    // Step 2: receive initiator credentials
    let data = framing::read_length_prefixed(stream, MAX_HANDSHAKE_PAYLOAD).await?;
    let init_creds: InitiatorCredentials =
        serde_json::from_slice(&data).map_err(|e| Error::InvalidEnvelope(e.to_string()))?;

    // Verify initiator
    let peer_key = PublicKey::from_encoded(&init_creds.public_key)?;
    let init_challenge_bytes = BASE64_STANDARD
        .decode(&init_creds.challenge)
        .map_err(|e| Error::Io(e.to_string()))?;
    peer_key.verify(&init_challenge_bytes, &init_creds.challenge_signature)?;

    // Check blocklist before revealing our identity
    if blocked_keys.is_some_and(|blocked| blocked.contains(peer_key.as_bytes())) {
        return Err(Error::InvalidEnvelope("blocked".into()));
    }

    // Validate target agent name if provided
    if let Some(ref target) = init_creds.target_agent {
        if target != &address.agent_name {
            return Err(Error::InvalidEnvelope(format!(
                "agent '{}' not found on this endpoint (this is '{}')",
                target, address.agent_name,
            )));
        }
    }

    // Step 3: send receiver credentials
    let (challenge_bytes, challenge_b64) = generate_challenge();
    let session_id = format!("{}{}", SESSION_ID_PREFIX, Uuid::new_v4());
    let creds = ReceiverCredentials {
        public_key: keypair.public_key().to_encoded(),
        challenge: challenge_b64,
        challenge_signature: keypair.sign(&challenge_bytes),
        address: address.clone(),
        session_id: session_id.clone(),
        rotation_proof: None,
    };
    framing::write_length_prefixed(stream, &serde_json::to_vec(&creds)?).await?;

    Ok(HandshakeResult {
        peer_public_key: peer_key,
        peer_address: init_creds.address,
        session_id,
        rotation_proof: init_creds.rotation_proof,
        target_agent: init_creds.target_agent,
    })
}
