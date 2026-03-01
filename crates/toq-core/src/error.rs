use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("blocked content type: {0}")]
    BlockedContentType(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(String),
}
