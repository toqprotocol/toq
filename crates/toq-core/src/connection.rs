use serde_json::json;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::constants::PROTOCOL_VERSION;
use crate::crypto::Keypair;
use crate::envelope::Envelope;
use crate::error::Error;
use crate::framing;
use crate::types::{Address, MessageType};

/// Connection state machine.
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
        timestamp: crate::now_utc(),
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
        timestamp: crate::now_utc(),
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
        timestamp: crate::now_utc(),
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
        timestamp: crate::now_utc(),
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

/// Build and send a system.error envelope.
pub async fn send_system_error<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    code: &str,
    message: &str,
    related_id: Option<&str>,
    sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let mut body = json!({ "code": code, "message": message });
    if let Some(rid) = related_id {
        body["related_id"] = json!(rid);
    }
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::SystemError,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence,
        timestamp: crate::now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: Some(body),
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}

/// Build and send a system.backpressure envelope.
pub async fn send_backpressure<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    retry_after: u32,
    sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::Backpressure,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence,
        timestamp: crate::now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: Some(json!({ "retry_after": retry_after })),
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}

/// Build and send a system.backpressure.clear envelope.
pub async fn send_backpressure_clear<S>(
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
        msg_type: MessageType::BackpressureClear,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence,
        timestamp: crate::now_utc(),
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

/// Build and send a system.key_rotation envelope.
pub async fn send_key_rotation<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    new_public_key: &str,
    rotation_proof: &str,
    sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::KeyRotation,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence,
        timestamp: crate::now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: Some(json!({
            "new_public_key": new_public_key,
            "rotation_proof": rotation_proof,
        })),
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}

/// Build and send a system.key_rotation.ack envelope.
pub async fn send_key_rotation_ack<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    accepted: bool,
    sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::KeyRotationAck,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence,
        timestamp: crate::now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: Some(json!({ "accepted": accepted })),
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}

/// Build and send an approval.request envelope.
pub async fn send_approval_request<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    message: Option<&str>,
    sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let body = message.map(|m| json!({ "message": m }));
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::ApprovalRequest,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence,
        timestamp: crate::now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body,
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}

/// Build and send an approval.granted envelope.
pub async fn send_approval_granted<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    message: Option<&str>,
    sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let body = message.map(|m| json!({ "message": m }));
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::ApprovalGranted,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence,
        timestamp: crate::now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body,
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}

/// Build and send an approval.denied envelope.
pub async fn send_approval_denied<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    reason: Option<&str>,
    sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let body = reason.map(|r| json!({ "reason": r }));
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::ApprovalDenied,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence,
        timestamp: crate::now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body,
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}
