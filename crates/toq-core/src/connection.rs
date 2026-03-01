use serde_json::json;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::constants::PROTOCOL_VERSION;
use crate::crypto::Keypair;
use crate::envelope::Envelope;
use crate::error::Error;
use crate::framing;
use crate::types::{Address, MessageType};

/// Connection state machine per spec Section 8.1.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionState {
    Connecting,
    Handshake,
    Negotiating,
    CardExchange,
    Active,
    Closed,
}

/// Build and send a heartbeat envelope.
pub async fn send_heartbeat<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    sequence: u64,
) -> Result<Uuid, Error>
where
    S: AsyncWriteExt + Unpin,
{
    let id = Uuid::new_v4();
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id,
        msg_type: MessageType::Heartbeat,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence,
        timestamp: now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: None,
    };
    framing::send_envelope(stream, &mut envelope, keypair).await?;
    Ok(id)
}

/// Build and send a heartbeat ack envelope.
pub async fn send_heartbeat_ack<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    reply_to_id: &Uuid,
    sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::HeartbeatAck,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: Some(reply_to_id.to_string()),
        sequence,
        timestamp: now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: None,
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}

/// Build and send a graceful disconnect envelope.
pub async fn send_disconnect<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::SessionDisconnect,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence,
        timestamp: now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: None,
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}

/// Build and send a session resume envelope.
pub async fn send_session_resume<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    session_id: &str,
    last_received_sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::SessionResume,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence: 0,
        timestamp: now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: Some(json!({
            "session_id": session_id,
            "last_received_sequence": last_received_sequence,
        })),
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}

fn now_utc() -> String {
    "2026-01-01T00:00:00Z".to_string()
}
