use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

use crate::constants::DEFAULT_PORT;
use crate::error::Error;

// --- Address ---

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    pub host: String,
    pub port: u16,
    pub agent_name: String,
}

impl Address {
    pub fn new(host: impl Into<String>, agent_name: impl Into<String>) -> Result<Self, Error> {
        let agent_name = agent_name.into();
        validate_agent_name(&agent_name)?;
        Ok(Self {
            host: host.into(),
            port: DEFAULT_PORT,
            agent_name,
        })
    }

    pub fn with_port(
        host: impl Into<String>,
        port: u16,
        agent_name: impl Into<String>,
    ) -> Result<Self, Error> {
        let agent_name = agent_name.into();
        validate_agent_name(&agent_name)?;
        Ok(Self {
            host: host.into(),
            port,
            agent_name,
        })
    }
}

fn validate_agent_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::InvalidAddress("agent name cannot be empty".into()));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(Error::InvalidAddress(
            "agent name must not start or end with hyphen".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Error::InvalidAddress(
            "agent name must contain only lowercase ASCII, digits, and hyphens".into(),
        ));
    }
    Ok(())
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == DEFAULT_PORT {
            write!(f, "toq://{}/{}", self.host, self.agent_name)
        } else {
            write!(f, "toq://{}:{}/{}", self.host, self.port, self.agent_name)
        }
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("toq://")
            .ok_or_else(|| Error::InvalidAddress("must start with toq://".into()))?;

        let (host_port, agent_name) = rest
            .rsplit_once('/')
            .ok_or_else(|| Error::InvalidAddress("missing agent name".into()))?;

        validate_agent_name(agent_name)?;

        let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                (h.to_string(), port)
            } else {
                (host_port.to_string(), DEFAULT_PORT)
            }
        } else {
            (host_port.to_string(), DEFAULT_PORT)
        };

        if host.is_empty() {
            return Err(Error::InvalidAddress("host cannot be empty".into()));
        }

        Ok(Self {
            host,
            port,
            agent_name: agent_name.to_string(),
        })
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// --- MessageType ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MessageType {
    // Handshake
    #[serde(rename = "handshake.init")]
    HandshakeInit,
    #[serde(rename = "handshake.response")]
    HandshakeResponse,
    #[serde(rename = "handshake.reject")]
    HandshakeReject,

    // Negotiation
    #[serde(rename = "negotiate.request")]
    NegotiateRequest,
    #[serde(rename = "negotiate.response")]
    NegotiateResponse,
    #[serde(rename = "negotiate.reject")]
    NegotiateReject,

    // Session
    #[serde(rename = "session.resume")]
    SessionResume,
    #[serde(rename = "session.disconnect")]
    SessionDisconnect,

    // Approval
    #[serde(rename = "approval.request")]
    ApprovalRequest,
    #[serde(rename = "approval.granted")]
    ApprovalGranted,
    #[serde(rename = "approval.denied")]
    ApprovalDenied,

    // Messaging
    #[serde(rename = "message.send")]
    MessageSend,
    #[serde(rename = "message.ack")]
    MessageAck,
    #[serde(rename = "message.cancel")]
    MessageCancel,

    // Streaming
    #[serde(rename = "message.stream.chunk")]
    StreamChunk,
    #[serde(rename = "message.stream.end")]
    StreamEnd,

    // Thread lifecycle
    #[serde(rename = "thread.close")]
    ThreadClose,

    // System
    #[serde(rename = "system.heartbeat")]
    Heartbeat,
    #[serde(rename = "system.heartbeat.ack")]
    HeartbeatAck,
    #[serde(rename = "system.backpressure")]
    Backpressure,
    #[serde(rename = "system.backpressure.clear")]
    BackpressureClear,
    #[serde(rename = "system.error")]
    SystemError,
    #[serde(rename = "system.key_rotation")]
    KeyRotation,
    #[serde(rename = "system.key_rotation.ack")]
    KeyRotationAck,

    // Card
    #[serde(rename = "card.exchange")]
    CardExchange,
}

// --- Priority ---

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    #[default]
    Normal,
    Urgent,
}
