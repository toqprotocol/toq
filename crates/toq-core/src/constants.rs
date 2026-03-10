use std::time::Duration;

/// Protocol version string.
pub const PROTOCOL_VERSION: &str = "0.1";

/// Default port for toq endpoints.
pub const DEFAULT_PORT: u16 = 9009;
pub const DEFAULT_API_PORT: u16 = 9010;

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

/// Ack timeout before retry.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum retry attempts before marking a message as undeliverable.
pub const MAX_RETRIES: usize = 5;

/// Retry delays (exponential backoff).
pub const RETRY_DELAYS: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
];

/// Deduplication window for message IDs.
pub const DEDUP_WINDOW: Duration = Duration::from_secs(300);

/// Maximum pending approval requests.
pub const MAX_PENDING_APPROVALS: usize = 100;

/// Maximum backpressure retry_after value in seconds.
pub const MAX_BACKPRESSURE_RETRY_AFTER: u32 = 60;

/// Default new connections per IP per second.
pub const DEFAULT_CONNECTIONS_PER_IP_PER_SEC: usize = 10;

/// Default messages per connection per second.
pub const DEFAULT_MESSAGES_PER_CONNECTION_PER_SEC: usize = 100;

/// Default maximum concurrent connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1000;

/// Default maximum concurrent threads per connection.
pub const DEFAULT_MAX_THREADS_PER_CONNECTION: usize = 100;

/// Default message queue depth.
pub const DEFAULT_MESSAGE_QUEUE_DEPTH: usize = 10000;

/// Key rotation grace period.
pub const KEY_ROTATION_GRACE_PERIOD: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Recommended key rotation interval.
pub const KEY_ROTATION_RECOMMENDED_DAYS: u32 = 90;

/// Default thread inactivity cleanup period.
pub const THREAD_CLEANUP_DAYS: u32 = 30;

/// Default log retention period.
pub const LOG_RETENTION_DAYS: u32 = 30;

/// Default maximum log size in MB.
pub const LOG_MAX_SIZE_MB: u32 = 500;

/// Health check timeout for local agent adapter.
pub const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Subdirectory for key storage within ~/.toq/.
pub const KEYS_DIR: &str = "keys";

/// Filename for the Ed25519 identity key.
pub const IDENTITY_KEY_FILE: &str = "identity.key";

/// Filename for the TLS certificate PEM.
pub const TLS_CERT_FILE: &str = "tls_cert.pem";

/// Filename for the TLS private key PEM.
pub const TLS_KEY_FILE: &str = "tls_key.pem";

/// Filename for the peer store.
pub const PEERS_FILE: &str = "peers.json";

/// Default SAN for self-signed TLS certificates.
pub const TLS_SELF_SIGNED_SAN: &str = "localhost";

/// Default bind address for the listener.
pub const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0";

/// Default content type for application messages.
pub const DEFAULT_CONTENT_TYPE: &str = "application/json";

/// Default maximum file size in bytes (10 MB).
pub const DEFAULT_MAX_FILE_SIZE: usize = 10_485_760;

/// Default zstd compression level.
pub const ZSTD_COMPRESSION_LEVEL: i32 = 3;

/// Adapter response timeout for stdin adapter.
pub const ADAPTER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// The toq data directory name.
pub const TOQ_DIR_NAME: &str = ".toq";

/// Config filename.
pub const CONFIG_FILE: &str = "config.toml";

/// Session ID prefix.
pub const SESSION_ID_PREFIX: &str = "sess-";

/// Subdirectory for logs within ~/.toq/.
pub const LOGS_DIR: &str = "logs";

/// Subdirectory for handler logs within ~/.toq/logs/.
pub const HANDLER_LOGS_DIR: &str = "handlers";

/// Log filename.
pub const LOG_FILE: &str = "toq.log";

/// PID filename.
pub const PID_FILE: &str = "toq.pid";

/// State filename for status reporting.
pub const STATE_FILE: &str = "state.json";

/// DNS service prefix for toq TXT record queries.
pub const DNS_SERVICE_PREFIX: &str = "_toq._tcp.";

/// Protocol identifier in DNS TXT records.
pub const DNS_PROTOCOL_ID: &str = "toq1";

/// Recommended DNS TTL in seconds.
pub const DNS_RECOMMENDED_TTL: u32 = 300;

/// mDNS service type for local discovery.
pub const MDNS_SERVICE_TYPE: &str = "_toq._tcp.local.";

/// MIME types that MUST be rejected by the toq process.
pub const BLOCKED_CONTENT_TYPES: &[&str] = &[
    "application/x-executable",
    "application/x-msdos-program",
    "application/x-msdownload",
    "application/x-sharedlib",
    "application/vnd.microsoft.portable-executable",
];
