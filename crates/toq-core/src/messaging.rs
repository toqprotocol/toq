use serde_json::Value;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::constants::PROTOCOL_VERSION;
use crate::crypto::Keypair;
use crate::envelope::Envelope;
use crate::error::Error;
use crate::framing;
use crate::types::{Address, MessageType, Priority};

/// Parameters for sending a message.
pub struct SendParams<'a> {
    pub from: &'a Address,
    pub to: &'a [Address],
    pub sequence: u64,
    pub body: Option<Value>,
    pub thread_id: Option<String>,
    pub reply_to: Option<String>,
    pub priority: Option<Priority>,
    pub content_type: Option<String>,
    pub ttl: Option<u64>,
}

/// Build and send a message.send envelope. Returns the message ID.
pub async fn send_message<S>(
    stream: &mut S,
    keypair: &Keypair,
    params: SendParams<'_>,
) -> Result<Uuid, Error>
where
    S: AsyncWriteExt + Unpin,
{
    let id = Uuid::new_v4();
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id,
        msg_type: MessageType::MessageSend,
        from: params.from.clone(),
        to: params.to.to_vec(),
        thread_id: params.thread_id,
        reply_to: params.reply_to,
        sequence: params.sequence,
        timestamp: crate::now_utc(),
        priority: params.priority,
        content_type: params.content_type,
        ttl: params.ttl,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: params.body,
    };
    envelope.check_self_message()?;
    framing::send_envelope(stream, &mut envelope, keypair).await?;
    Ok(id)
}

/// Build and send a message.ack envelope.
pub async fn send_ack<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    ack_id: &Uuid,
    sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::MessageAck,
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
        body: Some(serde_json::json!({ "ack_id": ack_id.to_string() })),
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}

/// Build and send a message.cancel envelope.
pub async fn send_cancel<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    cancel_id: &Uuid,
    sequence: u64,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::MessageCancel,
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
        body: Some(serde_json::json!({ "cancel_id": cancel_id.to_string() })),
    };
    framing::send_envelope(stream, &mut envelope, keypair).await
}
