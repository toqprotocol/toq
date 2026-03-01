use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Adapter types for local agent communication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterType {
    Http,
    Stdin,
    Sdk,
    Unix,
    Grpc,
}

/// Message delivered to the local agent.
/// Protocol-internal fields (sequence, signature, version) are stripped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    pub id: String,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

/// Response from the local agent back to the toq process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

impl AgentMessage {
    /// Convert an Envelope into an AgentMessage by stripping protocol fields.
    pub fn from_envelope(envelope: &crate::envelope::Envelope) -> Self {
        Self {
            id: envelope.id.to_string(),
            msg_type: serde_json::to_value(&envelope.msg_type)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            from: envelope.from.to_string(),
            thread_id: envelope.thread_id.clone(),
            reply_to: envelope.reply_to.clone(),
            content_type: envelope.content_type.clone(),
            body: envelope.body.clone(),
        }
    }
}
