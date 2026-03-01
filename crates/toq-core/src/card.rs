use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::constants::{DEFAULT_MAX_MESSAGE_SIZE, MAX_CARD_SIZE, PROTOCOL_VERSION};
use crate::crypto::{Keypair, PublicKey};
use crate::envelope::Envelope;
use crate::error::Error;
use crate::framing;
use crate::types::{Address, MessageType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub public_key: String,
    pub protocol_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub accept_files: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_message_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_mode: Option<String>,
}

impl AgentCard {
    /// Validate a received card against the peer's handshake public key.
    pub fn validate(&self, handshake_key: &PublicKey) -> Result<(), Error> {
        if self.name.is_empty() {
            return Err(Error::InvalidEnvelope("agent card name is empty".into()));
        }
        let card_key = PublicKey::from_encoded(&self.public_key)?;
        if card_key != *handshake_key {
            return Err(Error::InvalidEnvelope(
                "card public key does not match handshake key".into(),
            ));
        }
        let size = serde_json::to_vec(self)
            .map_err(|e| Error::InvalidEnvelope(e.to_string()))?
            .len();
        if size > MAX_CARD_SIZE {
            return Err(Error::MessageTooLarge {
                size,
                max: MAX_CARD_SIZE,
            });
        }
        Ok(())
    }
}

/// Exchange agent cards. Both sides send and receive simultaneously.
/// Returns the peer's validated agent card.
pub async fn exchange<S>(
    stream: &mut S,
    keypair: &Keypair,
    peer_key: &PublicKey,
    from: &Address,
    to: &Address,
    local_card: &AgentCard,
    sequence: u64,
) -> Result<AgentCard, Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Send our card
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::CardExchange,
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
        body: Some(serde_json::to_value(local_card)?),
    };
    framing::send_envelope(stream, &mut envelope, keypair).await?;

    // Receive peer's card
    let peer_envelope = framing::recv_envelope(stream, peer_key, DEFAULT_MAX_MESSAGE_SIZE).await?;

    if peer_envelope.msg_type != MessageType::CardExchange {
        return Err(Error::InvalidEnvelope("expected card.exchange".into()));
    }

    let body = peer_envelope
        .body
        .ok_or_else(|| Error::InvalidEnvelope("missing card body".into()))?;

    let peer_card: AgentCard =
        serde_json::from_value(body).map_err(|e| Error::InvalidEnvelope(e.to_string()))?;

    peer_card.validate(peer_key)?;

    Ok(peer_card)
}
