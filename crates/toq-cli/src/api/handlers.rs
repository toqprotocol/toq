//! API endpoint handlers.

use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive};
use axum::response::{IntoResponse, Json, Response, Sse};
use serde::Deserialize;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use toq_core::card::AgentCard;
use toq_core::constants::{DEFAULT_CONTENT_TYPE, DEFAULT_MAX_MESSAGE_SIZE, PROTOCOL_VERSION};
use toq_core::crypto::PublicKey;
use toq_core::messaging::{self, SendParams};
use toq_core::negotiation::Features;
use toq_core::server;
use toq_core::types::Address;
use toq_core::{framing, keystore};

use crate::api::state::ApiState;
use crate::api::types::*;

/// First message sequence after handshake completes.
const INITIAL_MESSAGE_SEQUENCE: u64 = 2;

// ── Helpers ─────────────────────────────────────────────────

fn error_response(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            error: ApiErrorBody {
                code,
                message: message.into(),
            },
        }),
    )
        .into_response()
}

fn json_ok<T: serde::Serialize>(body: T) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

// ── Messages ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SendMessageParams {
    #[serde(default)]
    pub wait: bool,
    #[serde(default = "default_timeout")]
    pub timeout: u32,
}

fn default_timeout() -> u32 {
    30
}

pub async fn send_message(
    State(state): State<ApiState>,
    Query(params): Query<SendMessageParams>,
    Json(req): Json<SendMessageRequest>,
) -> Response {
    let target_addr: Address = match req.to.parse() {
        Ok(a) => a,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ADDRESS,
                "Invalid toq address",
            );
        }
    };

    let config = state.config.lock().await;

    // Check message size
    if let Some(ref body) = req.body {
        let size = serde_json::to_vec(body).map(|v| v.len()).unwrap_or(0);
        if size > config.max_message_size {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                ERR_MESSAGE_TOO_LARGE,
                format!(
                    "Message body is {} bytes, max is {}",
                    size, config.max_message_size
                ),
            );
        }
    }

    let local_card = AgentCard {
        name: config.agent_name.clone(),
        description: None,
        public_key: state.keypair.public_key().to_encoded(),
        protocol_version: PROTOCOL_VERSION.into(),
        capabilities: Vec::new(),
        accept_files: config.accept_files,
        max_file_size: if config.accept_files {
            Some(config.max_file_size as u64)
        } else {
            None
        },
        max_message_size: Some(config.max_message_size),
        connection_mode: Some(config.connection_mode.clone()),
    };
    drop(config);

    let features = Features::default();
    let connect_addr = format!("{}:{}", target_addr.host, target_addr.port);

    let connect_result = server::connect_to_peer(
        &connect_addr,
        &state.keypair,
        &state.address,
        &local_card,
        &features,
    )
    .await;

    let (info, mut stream) = match connect_result {
        Ok(r) => r,
        Err(e) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                ERR_NOT_REACHABLE,
                format!("Cannot reach target: {e}"),
            );
        }
    };

    let thread_id = req.thread_id.unwrap_or_else(toq_core::now_utc);
    let content_type = req
        .content_type
        .unwrap_or_else(|| DEFAULT_CONTENT_TYPE.into());

    let msg_result = messaging::send_message(
        &mut stream,
        &state.keypair,
        SendParams {
            from: &state.address,
            to: std::slice::from_ref(&target_addr),
            sequence: INITIAL_MESSAGE_SEQUENCE,
            body: req.body,
            thread_id: Some(thread_id.clone()),
            reply_to: req.reply_to,
            priority: None,
            content_type: Some(content_type),
            ttl: None,
        },
    )
    .await;

    let msg_id = match msg_result {
        Ok(id) => id,
        Err(e) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                ERR_NOT_REACHABLE,
                format!("Failed to send: {e}"),
            );
        }
    };

    state.total_messages.fetch_add(1, Ordering::Relaxed);

    let next_seq = INITIAL_MESSAGE_SEQUENCE + 1;

    if params.wait {
        let timeout = Duration::from_secs(params.timeout as u64);
        let result = match tokio::time::timeout(
            timeout,
            framing::recv_envelope(&mut stream, &info.peer_public_key, DEFAULT_MAX_MESSAGE_SIZE),
        )
        .await
        {
            Ok(Ok(_ack)) => (
                StatusCode::OK,
                Json(SendMessageResponse {
                    id: msg_id.to_string(),
                    status: STATUS_DELIVERED,
                    thread_id,
                    timestamp: toq_core::now_utc(),
                }),
            )
                .into_response(),
            Ok(Err(e)) => error_response(
                StatusCode::BAD_GATEWAY,
                ERR_NOT_REACHABLE,
                format!("Connection error waiting for ack: {e}"),
            ),
            Err(_) => error_response(
                StatusCode::GATEWAY_TIMEOUT,
                ERR_DELIVERY_TIMEOUT,
                "No ack received within timeout",
            ),
        };
        let _ = toq_core::connection::send_disconnect(
            &mut stream,
            &state.keypair,
            &state.address,
            &target_addr,
            next_seq,
        )
        .await;
        result
    } else {
        let _ = toq_core::connection::send_disconnect(
            &mut stream,
            &state.keypair,
            &state.address,
            &target_addr,
            next_seq,
        )
        .await;
        (
            StatusCode::ACCEPTED,
            Json(SendMessageResponse {
                id: msg_id.to_string(),
                status: STATUS_QUEUED,
                thread_id,
                timestamp: toq_core::now_utc(),
            }),
        )
            .into_response()
    }
}

pub async fn stream_messages(
    State(state): State<ApiState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.message_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(msg) => Some(Ok(Event::default().json_data(msg).unwrap_or_default())),
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn cancel_message(Path(_id): Path<String>) -> Response {
    // Cancel requires tracking which connection a message was sent on.
    // Will be implemented with connection pooling.
    error_response(
        StatusCode::NOT_IMPLEMENTED,
        ERR_INVALID_REQUEST,
        "Message cancellation requires connection pooling (not yet implemented)",
    )
}

pub async fn send_streaming_message(
    State(state): State<ApiState>,
    Json(req): Json<SendMessageRequest>,
) -> Response {
    // For v1, streaming send uses the same path as regular send.
    // The daemon decides whether to chunk based on message size.
    let params = SendMessageParams {
        wait: false,
        timeout: default_timeout(),
    };
    send_message(State(state), Query(params), Json(req)).await
}

// ── Threads ─────────────────────────────────────────────────

pub async fn get_thread(Path(thread_id): Path<String>) -> Response {
    // Thread history requires a message store. For v1, the daemon
    // does not persist messages. SDKs should track thread history
    // client-side from the SSE stream.
    json_ok(ThreadResponse {
        thread_id,
        messages: vec![],
    })
}

// ── Peers ───────────────────────────────────────────────────

pub async fn list_peers(State(state): State<ApiState>) -> Response {
    let store = keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
    let sessions = state.sessions.lock().await;
    let connected_keys: std::collections::HashSet<String> = sessions
        .list()
        .into_iter()
        .map(|c| c.peer_public_key)
        .collect();
    drop(sessions);

    let peers = store
        .peers
        .iter()
        .map(|(key, record)| {
            let base_status = format!("{:?}", record.status).to_lowercase();
            let status = if connected_keys.contains(key) {
                "connected".to_string()
            } else if base_status == "approved" {
                "disconnected".to_string()
            } else {
                base_status
            };
            PeerEntry {
                public_key: key.clone(),
                address: record.address.clone(),
                status,
                last_seen: record.last_seen.clone(),
            }
        })
        .collect();
    json_ok(PeersResponse { peers })
}

pub async fn block_peer(Path(public_key): Path<String>) -> Response {
    let pk = match toq_core::crypto::PublicKey::from_encoded(&public_key) {
        Ok(pk) => pk,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_REQUEST,
                "Invalid public key",
            );
        }
    };
    let mut store = keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
    store.upsert(&pk, "", keystore::PeerStatus::Blocked);
    let _ = store.save(&keystore::peers_path());
    StatusCode::OK.into_response()
}

pub async fn unblock_peer(Path(public_key): Path<String>) -> Response {
    let mut store = keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
    store.peers.remove(&public_key);
    let _ = store.save(&keystore::peers_path());
    StatusCode::OK.into_response()
}

// ── Discovery ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DiscoverParams {
    pub host: String,
}

pub async fn discover_dns(Query(params): Query<DiscoverParams>) -> Response {
    let query_name = toq_core::discovery::query_name(&params.host);
    // DNS TXT lookup requires a resolver. For v1, return the query name
    // so the SDK can resolve it. Full async DNS resolution will be added
    // when we integrate trust-dns or hickory-dns.
    let _ = query_name;
    json_ok(DiscoverResponse { agents: vec![] })
}

pub async fn discover_local() -> Response {
    // mDNS discovery requires the mdns crate. Will be added when
    // mDNS support is implemented in toq-core.
    json_ok(DiscoverResponse { agents: vec![] })
}

// ── Approvals ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ApprovalDecision {
    pub decision: String,
}

pub async fn list_approvals(State(state): State<ApiState>) -> Response {
    let policy = state.policy.lock().await;
    let approvals = policy
        .list_pending()
        .into_iter()
        .map(|p| {
            let pk = PublicKey::from_bytes(&p.public_key)
                .map(|k| k.to_encoded())
                .unwrap_or_default();
            crate::api::types::ApprovalEntry {
                id: pk.clone(),
                public_key: pk,
                address: p.address,
                requested_at: p.requested_at,
            }
        })
        .collect();
    json_ok(crate::api::types::ApprovalsResponse { approvals })
}

pub async fn resolve_approval(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(decision): Json<ApprovalDecision>,
) -> Response {
    let pk = match PublicKey::from_encoded(&id) {
        Ok(pk) => pk,
        Err(_) => {
            return error_response(
                StatusCode::NOT_FOUND,
                ERR_NOT_FOUND,
                "Invalid approval ID (must be an encoded public key)",
            );
        }
    };

    let mut policy = state.policy.lock().await;
    match decision.decision.as_str() {
        "approve" => policy.approve(&pk),
        "deny" => policy.deny(&pk),
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_REQUEST,
                "Decision must be 'approve' or 'deny'",
            );
        }
    }
    StatusCode::OK.into_response()
}

// ── Connections ─────────────────────────────────────────────

pub async fn list_connections(State(state): State<ApiState>) -> Response {
    let sessions = state.sessions.lock().await;
    let connections = sessions
        .list()
        .into_iter()
        .map(|c| crate::api::types::ConnectionEntry {
            session_id: c.session_id,
            peer_address: c.peer_address,
            peer_public_key: c.peer_public_key,
            connected_at: c.connected_at,
            messages_exchanged: c.messages_exchanged,
        })
        .collect();
    json_ok(crate::api::types::ConnectionsResponse { connections })
}

// ── Daemon ──────────────────────────────────────────────────

pub async fn health_check() -> &'static str {
    "ok"
}

pub async fn get_status(State(state): State<ApiState>) -> Response {
    let config = state.config.lock().await;
    json_ok(StatusResponse {
        status: "running",
        address: state.address.to_string(),
        connection_mode: config.connection_mode.clone(),
        active_connections: state.active_connections.load(Ordering::Relaxed),
        total_messages: state.total_messages.load(Ordering::Relaxed),
        error_count: state.error_count.load(Ordering::Relaxed),
        backpressure_active: false,
        version: env!("CARGO_PKG_VERSION"),
        public_key: state.keypair.public_key().to_encoded(),
    })
}

pub async fn shutdown_daemon(
    State(state): State<ApiState>,
    body: Option<Json<ShutdownRequest>>,
) -> Response {
    let _graceful = body.map(|b| b.graceful).unwrap_or(true);
    let mut tx = state.shutdown_tx.lock().await;
    if let Some(tx) = tx.take() {
        let _ = tx.send(());
    }
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
pub struct LogParams {
    #[serde(default)]
    pub follow: bool,
}

pub async fn get_logs(Query(params): Query<LogParams>) -> Response {
    let log_dir = toq_core::config::dirs_path().join(toq_core::constants::LOGS_DIR);
    let log_file = log_dir.join(toq_core::constants::LOG_FILE);

    if params.follow {
        let stream = async_stream::stream! {
            let mut pos = std::fs::metadata(&log_file).map(|m| m.len()).unwrap_or(0);
            loop {
                let current_len = std::fs::metadata(&log_file).map(|m| m.len()).unwrap_or(0);
                if current_len > pos {
                    if let Ok(content) = std::fs::read_to_string(&log_file) {
                        let bytes = content.as_bytes();
                        if (pos as usize) < bytes.len() {
                            let new_content = &content[pos as usize..];
                            for line in new_content.lines().filter(|l| !l.is_empty()) {
                                let entry = parse_log_line(line);
                                let event: Result<Event, Infallible> = Ok(Event::default().json_data(entry).unwrap_or_default());
                                yield event;
                            }
                        }
                    }
                    pos = current_len;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        };
        return Sse::new(stream)
            .keep_alive(KeepAlive::default())
            .into_response();
    }

    let content = std::fs::read_to_string(&log_file).unwrap_or_default();
    let entries = content
        .lines()
        .filter(|l| !l.is_empty())
        .map(parse_log_line)
        .collect();
    json_ok(LogsResponse { entries })
}

fn parse_log_line(line: &str) -> LogEntry {
    let mut parts = line.splitn(3, ' ');
    let timestamp = parts.next().unwrap_or_default().to_string();
    let level = parts.next().unwrap_or_default().to_lowercase();
    let message = parts.next().unwrap_or(line).to_string();
    LogEntry {
        timestamp,
        level,
        message,
    }
}

pub async fn clear_logs() -> Response {
    let log_dir = toq_core::config::dirs_path().join(toq_core::constants::LOGS_DIR);
    if let Ok(entries) = std::fs::read_dir(&log_dir) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    StatusCode::OK.into_response()
}

pub async fn run_diagnostics(State(state): State<ApiState>) -> Response {
    let mut checks = Vec::new();

    match toq_core::config::Config::load(&toq_core::config::Config::default_path()) {
        Ok(c) => checks.push(DiagnosticCheck {
            name: "config".into(),
            status: "ok",
            detail: Some(format!("agent: {}", c.agent_name)),
        }),
        Err(e) => checks.push(DiagnosticCheck {
            name: "config".into(),
            status: "fail",
            detail: Some(e.to_string()),
        }),
    }

    match keystore::load_keypair(&keystore::identity_key_path()) {
        Ok(kp) => checks.push(DiagnosticCheck {
            name: "identity_key".into(),
            status: "ok",
            detail: Some(kp.public_key().to_encoded()),
        }),
        Err(e) => checks.push(DiagnosticCheck {
            name: "identity_key".into(),
            status: "fail",
            detail: Some(e.to_string()),
        }),
    }

    match keystore::load_tls_cert(&keystore::tls_cert_path(), &keystore::tls_key_path()) {
        Ok(_) => checks.push(DiagnosticCheck {
            name: "tls_cert".into(),
            status: "ok",
            detail: None,
        }),
        Err(e) => checks.push(DiagnosticCheck {
            name: "tls_cert".into(),
            status: "fail",
            detail: Some(e.to_string()),
        }),
    }

    // Port reachability
    let config = state.config.lock().await;
    let bind_addr = format!(
        "{}:{}",
        toq_core::constants::DEFAULT_BIND_ADDRESS,
        config.port
    );
    drop(config);
    match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(_) => checks.push(DiagnosticCheck {
            name: "port".into(),
            status: "ok",
            detail: Some(bind_addr),
        }),
        Err(_) => checks.push(DiagnosticCheck {
            name: "port".into(),
            status: "ok",
            detail: Some(format!("{bind_addr} (in use by daemon)")),
        }),
    }

    // Disk writable
    let toq_dir = toq_core::config::dirs_path();
    let test_path = toq_dir.join(".disk_check");
    match std::fs::write(&test_path, "ok") {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_path);
            checks.push(DiagnosticCheck {
                name: "disk".into(),
                status: "ok",
                detail: None,
            });
        }
        Err(e) => checks.push(DiagnosticCheck {
            name: "disk".into(),
            status: "fail",
            detail: Some(e.to_string()),
        }),
    }

    let issues = checks.iter().filter(|c| c.status == "fail").count();
    json_ok(DiagnosticsResponse { checks, issues })
}

pub async fn check_upgrade() -> Response {
    let current = env!("CARGO_PKG_VERSION");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("toq")
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            return json_ok(UpgradeCheckResponse {
                current_version: current,
                up_to_date: true,
                latest_version: None,
                download_url: None,
            });
        }
    };

    match client.get(RELEASES_API_URL).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let tag = body["tag_name"].as_str().unwrap_or(current);
            let latest = tag.trim_start_matches('v');
            let up_to_date = latest == current;
            json_ok(UpgradeCheckResponse {
                current_version: current,
                up_to_date,
                latest_version: if up_to_date {
                    None
                } else {
                    Some(latest.to_string())
                },
                download_url: if up_to_date {
                    None
                } else {
                    body["html_url"]
                        .as_str()
                        .map(String::from)
                        .or_else(|| Some(RELEASES_FALLBACK_URL.to_string()))
                },
            })
        }
        _ => json_ok(UpgradeCheckResponse {
            current_version: current,
            up_to_date: true,
            latest_version: None,
            download_url: None,
        }),
    }
}

// ── Keys ────────────────────────────────────────────────────

pub async fn rotate_keys(State(_state): State<ApiState>) -> Response {
    // Load the current on-disk keypair to ensure proof chain integrity.
    // If someone already rotated without restarting, the on-disk key
    // differs from the in-memory key, and we must use the on-disk one.
    let current_keypair = match keystore::load_keypair(&keystore::identity_key_path()) {
        Ok(kp) => kp,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INVALID_REQUEST,
                format!("Cannot load current keys: {e}"),
            );
        }
    };

    let old_public = current_keypair.public_key().to_encoded();
    let new_keypair = toq_core::crypto::Keypair::generate();
    let new_public = new_keypair.public_key();
    let proof = toq_core::crypto::generate_rotation_proof(&current_keypair, &new_public);

    if let Err(e) = keystore::save_keypair(&new_keypair, &keystore::identity_key_path()) {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INVALID_REQUEST,
            format!("Failed to save new keys: {e}"),
        );
    }

    json_ok(KeyRotationResponse {
        old_public_key: old_public,
        new_public_key: new_public.to_encoded(),
        rotation_proof: proof,
    })
}

// ── Backup ──────────────────────────────────────────────────

pub async fn export_backup(Json(req): Json<BackupExportRequest>) -> Response {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::prelude::*;
    use sha2::{Digest, Sha256};

    if req.passphrase.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_REQUEST,
            "Passphrase cannot be empty",
        );
    }

    let identity = match std::fs::read_to_string(keystore::identity_key_path()) {
        Ok(s) => s,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INVALID_REQUEST,
                format!("Cannot read identity key: {e}"),
            );
        }
    };
    let tls_cert = match std::fs::read_to_string(keystore::tls_cert_path()) {
        Ok(s) => s,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INVALID_REQUEST,
                format!("Cannot read TLS cert: {e}"),
            );
        }
    };
    let tls_key = match std::fs::read_to_string(keystore::tls_key_path()) {
        Ok(s) => s,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INVALID_REQUEST,
                format!("Cannot read TLS key: {e}"),
            );
        }
    };
    let config = match std::fs::read_to_string(toq_core::config::Config::default_path()) {
        Ok(s) => s,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INVALID_REQUEST,
                format!("Cannot read config: {e}"),
            );
        }
    };
    let peers = std::fs::read_to_string(keystore::peers_path()).unwrap_or_else(|_| "{}".into());

    let bundle = serde_json::json!({
        "version": PROTOCOL_VERSION,
        "identity_key": identity.trim(),
        "tls_cert": tls_cert,
        "tls_key": tls_key,
        "config": config,
        "peers": peers,
    });

    let plaintext = serde_json::to_string_pretty(&bundle).unwrap_or_default();
    let key_bytes = Sha256::digest(req.passphrase.as_bytes());
    let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
        Ok(c) => c,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INVALID_REQUEST,
                format!("Encryption setup failed: {e}"),
            );
        }
    };

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, plaintext.as_bytes()) {
        Ok(ciphertext) => {
            let output = serde_json::json!({
                "encrypted": true,
                "nonce": BASE64_STANDARD.encode(nonce_bytes),
                "data": BASE64_STANDARD.encode(&ciphertext),
            });
            json_ok(BackupExportResponse {
                data: output.to_string(),
            })
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INVALID_REQUEST,
            format!("Encryption failed: {e}"),
        ),
    }
}

pub async fn import_backup(Json(req): Json<BackupImportRequest>) -> Response {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::prelude::*;
    use sha2::{Digest, Sha256};

    let wrapper: serde_json::Value = match serde_json::from_str(&req.data) {
        Ok(v) => v,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_REQUEST,
                format!("Invalid backup data: {e}"),
            );
        }
    };

    let bundle: serde_json::Value =
        if wrapper.get("encrypted").and_then(|v| v.as_bool()) == Some(true) {
            let key_bytes = Sha256::digest(req.passphrase.as_bytes());
            let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
                Ok(c) => c,
                Err(_) => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ERR_INVALID_REQUEST,
                        "Decryption setup failed",
                    );
                }
            };
            let nonce_bytes = match wrapper["nonce"]
                .as_str()
                .and_then(|s| BASE64_STANDARD.decode(s).ok())
            {
                Some(b) => b,
                None => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        ERR_INVALID_REQUEST,
                        "Missing nonce in backup",
                    );
                }
            };
            let ciphertext = match wrapper["data"]
                .as_str()
                .and_then(|s| BASE64_STANDARD.decode(s).ok())
            {
                Some(b) => b,
                None => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        ERR_INVALID_REQUEST,
                        "Missing data in backup",
                    );
                }
            };
            let nonce = Nonce::from_slice(&nonce_bytes);
            match cipher.decrypt(nonce, ciphertext.as_ref()) {
                Ok(plaintext) => match serde_json::from_slice(&plaintext) {
                    Ok(v) => v,
                    Err(_) => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            ERR_INVALID_PASSPHRASE,
                            "Decryption produced invalid data",
                        );
                    }
                },
                Err(_) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        ERR_INVALID_PASSPHRASE,
                        "Wrong passphrase",
                    );
                }
            }
        } else {
            wrapper
        };

    let get_field = |name: &str| bundle[name].as_str().map(String::from);
    let Some(identity) = get_field("identity_key") else {
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_REQUEST,
            "Missing identity_key",
        );
    };
    let Some(tls_cert) = get_field("tls_cert") else {
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_REQUEST,
            "Missing tls_cert",
        );
    };
    let Some(tls_key) = get_field("tls_key") else {
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_REQUEST,
            "Missing tls_key",
        );
    };
    let Some(config) = get_field("config") else {
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_REQUEST,
            "Missing config",
        );
    };
    let peers = get_field("peers").unwrap_or_else(|| "{}".into());

    let dirs = toq_core::config::dirs_path();
    let _ = std::fs::create_dir_all(dirs.join(toq_core::constants::KEYS_DIR));
    let _ = std::fs::create_dir_all(dirs.join(toq_core::constants::LOGS_DIR));
    let _ = std::fs::write(keystore::identity_key_path(), identity);
    let _ = std::fs::write(keystore::tls_cert_path(), tls_cert);
    let _ = std::fs::write(keystore::tls_key_path(), tls_key);
    let _ = std::fs::write(toq_core::config::Config::default_path(), config);
    let _ = std::fs::write(keystore::peers_path(), peers);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            keystore::identity_key_path(),
            std::fs::Permissions::from_mode(0o600),
        );
        let _ = std::fs::set_permissions(
            keystore::tls_key_path(),
            std::fs::Permissions::from_mode(0o600),
        );
    }

    StatusCode::OK.into_response()
}

// ── Config ──────────────────────────────────────────────────

pub async fn get_config(State(state): State<ApiState>) -> Response {
    let config = state.config.lock().await;
    match serde_json::to_value(&*config) {
        Ok(val) => json_ok(ConfigResponse { config: val }),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INVALID_REQUEST,
            format!("Failed to serialize config: {e}"),
        ),
    }
}

pub async fn update_config(
    State(state): State<ApiState>,
    Json(updates): Json<serde_json::Value>,
) -> Response {
    let mut config = state.config.lock().await;
    let mut current = match serde_json::to_value(&*config) {
        Ok(val) => val,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INVALID_REQUEST,
                format!("Failed to serialize config: {e}"),
            );
        }
    };

    if let (Some(current_obj), Some(updates_obj)) = (current.as_object_mut(), updates.as_object()) {
        for (key, value) in updates_obj {
            current_obj.insert(key.clone(), value.clone());
        }
    }

    match serde_json::from_value::<toq_core::config::Config>(current.clone()) {
        Ok(new_config) => {
            let _ = new_config.save(&toq_core::config::Config::default_path());
            *config = new_config;
            json_ok(ConfigResponse { config: current })
        }
        Err(e) => error_response(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_CONFIG,
            format!("Invalid config: {e}"),
        ),
    }
}

// ── Agent Card ──────────────────────────────────────────────

pub async fn get_agent_card(State(state): State<ApiState>) -> Response {
    let config = state.config.lock().await;
    json_ok(AgentCardResponse {
        name: config.agent_name.clone(),
        description: None,
        public_key: state.keypair.public_key().to_encoded(),
        protocol_version: PROTOCOL_VERSION.into(),
        capabilities: vec![],
        accept_files: config.accept_files,
        max_file_size: if config.accept_files {
            Some(config.max_file_size as u64)
        } else {
            None
        },
        max_message_size: Some(config.max_message_size),
        connection_mode: Some(config.connection_mode.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_state() -> ApiState {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;
        use tokio::sync::Mutex;
        use toq_core::config::Config;
        use toq_core::crypto::Keypair;
        use toq_core::policy::{ConnectionMode, PolicyEngine};
        use toq_core::session::SessionStore;
        use toq_core::types::Address;

        let keypair = Keypair::generate();
        let address = Address::new("localhost", "test-agent").unwrap();
        let policy = Arc::new(Mutex::new(PolicyEngine::new(ConnectionMode::Approval)));
        let sessions = Arc::new(Mutex::new(SessionStore::new()));

        ApiState::new(
            Config::default(),
            keypair,
            address,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            policy,
            sessions,
        )
    }

    async fn get_json(path: &str) -> (u16, serde_json::Value) {
        let app = crate::api::router(test_state());
        let resp = app
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        (status, body)
    }

    async fn post_json(path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
        let app = crate::api::router(test_state());
        let resp = app
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        (status, body)
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let app = crate::api::router(test_state());
        let resp = app
            .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"ok");
    }

    #[tokio::test]
    async fn status_returns_running() {
        let (status, body) = get_json("/v1/status").await;
        assert_eq!(status, 200);
        assert_eq!(body["status"], "running");
        assert_eq!(body["address"], "toq://localhost/test-agent");
        assert!(body["public_key"].as_str().unwrap().starts_with("ed25519:"));
        assert!(body["version"].as_str().is_some());
    }

    #[tokio::test]
    async fn peers_returns_empty() {
        let (status, body) = get_json("/v1/peers").await;
        assert_eq!(status, 200);
        assert!(body["peers"].as_array().is_some());
    }

    #[tokio::test]
    async fn approvals_returns_empty() {
        let (status, body) = get_json("/v1/approvals").await;
        assert_eq!(status, 200);
        assert!(body["approvals"].as_array().is_some());
    }

    #[tokio::test]
    async fn connections_returns_empty() {
        let (status, body) = get_json("/v1/connections").await;
        assert_eq!(status, 200);
        assert!(body["connections"].as_array().is_some());
    }

    #[tokio::test]
    async fn card_returns_agent_info() {
        let (status, body) = get_json("/v1/card").await;
        assert_eq!(status, 200);
        assert_eq!(body["name"], "agent");
        assert!(body["public_key"].as_str().unwrap().starts_with("ed25519:"));
        assert_eq!(body["protocol_version"], "0.1");
    }

    #[tokio::test]
    async fn config_returns_json() {
        let (status, body) = get_json("/v1/config").await;
        assert_eq!(status, 200);
        assert!(body["config"].is_object());
        assert_eq!(body["config"]["agent_name"], "agent");
    }

    #[tokio::test]
    async fn send_message_invalid_address() {
        let (status, body) = post_json(
            "/v1/messages",
            serde_json::json!({"to": "not-a-toq-address"}),
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(body["error"]["code"], "invalid_address");
    }

    #[tokio::test]
    async fn cancel_returns_501() {
        let app = crate::api::router(test_state());
        let resp = app
            .oneshot(
                Request::post("/v1/messages/fake-id/cancel")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 501);
    }

    #[tokio::test]
    async fn thread_returns_empty() {
        let (status, body) = get_json("/v1/threads/thr-123").await;
        assert_eq!(status, 200);
        assert_eq!(body["thread_id"], "thr-123");
        assert_eq!(body["messages"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn discover_dns_returns_empty() {
        let (status, body) = get_json("/v1/discover?host=example.com").await;
        assert_eq!(status, 200);
        assert!(body["agents"].as_array().is_some());
    }

    #[tokio::test]
    async fn discover_local_returns_empty() {
        let (status, body) = get_json("/v1/discover/local").await;
        assert_eq!(status, 200);
        assert!(body["agents"].as_array().is_some());
    }

    #[tokio::test]
    async fn resolve_approval_bad_id() {
        let (status, body) = post_json(
            "/v1/approvals/not-a-key",
            serde_json::json!({"decision": "approve"}),
        )
        .await;
        assert_eq!(status, 404);
        assert_eq!(body["error"]["code"], "not_found");
    }

    #[tokio::test]
    async fn block_peer_bad_key() {
        let app = crate::api::router(test_state());
        let resp = app
            .oneshot(
                Request::post("/v1/peers/not-a-key/block")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn upgrade_check_returns_version() {
        let (status, body) = get_json("/v1/upgrade/check").await;
        assert_eq!(status, 200);
        assert!(body["current_version"].as_str().is_some());
        assert!(body["up_to_date"].as_bool().is_some());
    }

    #[tokio::test]
    async fn config_update_invalid() {
        let app = crate::api::router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/v1/config")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"port": "not-a-number"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }
}
