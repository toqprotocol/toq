use serde::{Deserialize, Serialize};

/// Severity of a protocol error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Fatal,
    NonFatal,
    Silent,
}

/// All 22 protocol error codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    #[serde(rename = "invalid_signature")]
    InvalidSignature,
    #[serde(rename = "protocol_violation")]
    ProtocolViolation,
    #[serde(rename = "version_not_supported")]
    VersionNotSupported,
    #[serde(rename = "invalid_envelope")]
    InvalidEnvelope,
    #[serde(rename = "duplicate_message")]
    DuplicateMessage,
    #[serde(rename = "sequence_violation")]
    SequenceViolation,
    #[serde(rename = "message_too_large")]
    MessageTooLarge,
    #[serde(rename = "unsupported_content_type")]
    UnsupportedContentType,
    #[serde(rename = "ttl_expired")]
    TtlExpired,
    #[serde(rename = "agent_unavailable")]
    AgentUnavailable,
    #[serde(rename = "resource_exhausted")]
    ResourceExhausted,
    #[serde(rename = "stream_not_found")]
    StreamNotFound,
    #[serde(rename = "self_message")]
    SelfMessage,
    #[serde(rename = "blocked")]
    Blocked,
    #[serde(rename = "approval_denied")]
    ApprovalDenied,
    #[serde(rename = "approval_timeout")]
    ApprovalTimeout,
    #[serde(rename = "session_expired")]
    SessionExpired,
    #[serde(rename = "card_too_large")]
    CardTooLarge,
    #[serde(rename = "card_key_mismatch")]
    CardKeyMismatch,
    #[serde(rename = "compression_not_negotiated")]
    CompressionNotNegotiated,
    #[serde(rename = "key_rotation_invalid")]
    KeyRotationInvalid,
    #[serde(rename = "executable_content_blocked")]
    ExecutableContentBlocked,
}

impl ErrorCode {
    pub fn severity(&self) -> Severity {
        match self {
            Self::InvalidSignature
            | Self::ProtocolViolation
            | Self::VersionNotSupported
            | Self::CardTooLarge
            | Self::CardKeyMismatch => Severity::Fatal,
            Self::Blocked => Severity::Silent,
            _ => Severity::NonFatal,
        }
    }

    pub fn is_fatal(&self) -> bool {
        self.severity() == Severity::Fatal
    }
}
