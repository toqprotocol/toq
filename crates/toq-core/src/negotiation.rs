use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::constants::{DEFAULT_MAX_MESSAGE_SIZE, PROTOCOL_VERSION};
use crate::crypto::{Keypair, PublicKey};
use crate::envelope::Envelope;
use crate::error::Error;
use crate::framing;
use crate::types::{Address, MessageType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Features {
    #[serde(default)]
    pub streaming: bool,
    #[serde(default)]
    pub compression: Vec<String>,
    #[serde(default)]
    pub e2e_encryption: bool,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            streaming: true,
            compression: vec![],
            e2e_encryption: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NegotiatedFeatures {
    pub version: String,
    pub streaming: bool,
    pub compression: Option<String>,
    pub e2e_encryption: bool,
}

/// Initiator: send negotiate.request, receive negotiate.response or negotiate.reject.
pub async fn request<S>(
    stream: &mut S,
    keypair: &Keypair,
    peer_key: &PublicKey,
    from: &Address,
    to: &Address,
    local_features: &Features,
) -> Result<NegotiatedFeatures, Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::NegotiateRequest,
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
            "supported_versions": [PROTOCOL_VERSION],
            "features": local_features,
        })),
    };
    framing::send_envelope(stream, &mut envelope, keypair).await?;

    let response = framing::recv_envelope(stream, peer_key, DEFAULT_MAX_MESSAGE_SIZE).await?;

    match response.msg_type {
        MessageType::NegotiateResponse => {
            let body = response
                .body
                .ok_or_else(|| Error::InvalidEnvelope("missing negotiation body".into()))?;
            let version = body["selected_version"]
                .as_str()
                .ok_or_else(|| Error::InvalidEnvelope("missing selected_version".into()))?
                .to_string();
            let features: Features =
                serde_json::from_value(body["features"].clone()).unwrap_or_default();
            Ok(NegotiatedFeatures {
                version,
                streaming: features.streaming,
                compression: features.compression.into_iter().next(),
                e2e_encryption: features.e2e_encryption,
            })
        }
        MessageType::NegotiateReject => {
            let reason = response
                .body
                .and_then(|b| b["reason"].as_str().map(String::from))
                .unwrap_or_else(|| "unknown".into());
            Err(Error::InvalidEnvelope(format!(
                "negotiation rejected: {reason}"
            )))
        }
        MessageType::ApprovalRequest => {
            let reason = response
                .body
                .and_then(|b| b["message"].as_str().map(String::from))
                .unwrap_or_else(|| "your connection request is pending review".into());
            Err(Error::InvalidEnvelope(format!(
                "connection pending approval: {reason}"
            )))
        }
        _ => Err(Error::InvalidEnvelope("unexpected message type".into())),
    }
}

/// Receiver: receive negotiate.request, send negotiate.response.
pub async fn respond<S>(
    stream: &mut S,
    keypair: &Keypair,
    peer_key: &PublicKey,
    from: &Address,
    to: &Address,
    local_features: &Features,
) -> Result<NegotiatedFeatures, Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let req = framing::recv_envelope(stream, peer_key, DEFAULT_MAX_MESSAGE_SIZE).await?;

    if req.msg_type != MessageType::NegotiateRequest {
        return Err(Error::InvalidEnvelope("expected negotiate.request".into()));
    }

    let body = req
        .body
        .ok_or_else(|| Error::InvalidEnvelope("missing negotiation body".into()))?;

    // Check version compatibility
    let supported: Vec<String> =
        serde_json::from_value(body["supported_versions"].clone()).unwrap_or_default();
    if !supported.contains(&PROTOCOL_VERSION.to_string()) {
        let mut reject = Envelope {
            version: PROTOCOL_VERSION.into(),
            id: Uuid::new_v4(),
            msg_type: MessageType::NegotiateReject,
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
                "reason": "no_compatible_version",
                "supported_versions": [PROTOCOL_VERSION],
            })),
        };
        framing::send_envelope(stream, &mut reject, keypair).await?;
        return Err(Error::InvalidEnvelope("no compatible version".into()));
    }

    // Compute feature intersection
    let peer_features: Features =
        serde_json::from_value(body["features"].clone()).unwrap_or_default();
    let agreed_streaming = local_features.streaming && peer_features.streaming;
    let agreed_compression = local_features
        .compression
        .iter()
        .find(|c| peer_features.compression.contains(c))
        .cloned();
    let agreed_e2e = local_features.e2e_encryption && peer_features.e2e_encryption;

    let negotiated = NegotiatedFeatures {
        version: PROTOCOL_VERSION.into(),
        streaming: agreed_streaming,
        compression: agreed_compression.clone(),
        e2e_encryption: agreed_e2e,
    };

    let mut response = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::NegotiateResponse,
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
            "selected_version": PROTOCOL_VERSION,
            "features": {
                "streaming": agreed_streaming,
                "compression": agreed_compression,
                "e2e_encryption": agreed_e2e,
            },
        })),
    };
    framing::send_envelope(stream, &mut response, keypair).await?;

    Ok(negotiated)
}
