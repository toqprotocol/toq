use std::time::Duration;

/// Protocol version string.
pub const PROTOCOL_VERSION: &str = "0.1";

/// Default port for toq endpoints.
pub const DEFAULT_PORT: u16 = 9009;

/// Magic bytes sent at the start of every toq connection: ASCII "TOQ" + version byte 0x01.
pub const MAGIC_BYTES: [u8; 4] = [0x54, 0x4F, 0x51, 0x01];

/// Prefix for Ed25519 public keys and signatures in wire format.
pub const ED25519_PREFIX: &str = "ed25519:";

/// Default maximum envelope size in bytes (1 MB).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1_048_576;

/// Maximum number of recipients per envelope.
pub const MAX_RECIPIENTS: usize = 100;

/// Maximum handshake payload size in bytes (64 KB).
pub const MAX_HANDSHAKE_PAYLOAD: usize = 65536;

/// Handshake timeout.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Negotiation timeout.
pub const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Heartbeat interval.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Heartbeat timeout (3 missed beats).
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

/// Maximum agent card size in bytes (64 KB).
pub const MAX_CARD_SIZE: usize = 65536;

/// Session resume window.
pub const SESSION_RESUME_TIMEOUT: Duration = Duration::from_secs(300);

/// Graceful shutdown timeout.
pub const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);

/// MIME types that MUST be rejected by the toq process.
pub const BLOCKED_CONTENT_TYPES: &[&str] = &[
    "application/x-executable",
    "application/x-msdos-program",
    "application/x-msdownload",
    "application/x-sharedlib",
    "application/vnd.microsoft.portable-executable",
];
