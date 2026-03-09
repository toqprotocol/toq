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
    let is_single = req.to.is_single();
    let recipients = req.to.into_vec();

    if recipients.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_REQUEST,
            "No recipients specified",
        );
    }

    // Parse all addresses upfront
    let mut targets: Vec<Address> = Vec::with_capacity(recipients.len());
    for r in &recipients {
        match r.parse::<Address>() {
            Ok(a) => targets.push(a),
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    ERR_INVALID_ADDRESS,
                    format!("Invalid toq address: {r}"),
                );
            }
        }
    }

    let keypair = state.keypair.read().await;
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
        public_key: keypair.public_key().to_encoded(),
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

    let has_explicit_thread = req.thread_id.is_some();
    let thread_id = req
        .thread_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let content_type = req
        .content_type
        .unwrap_or_else(|| DEFAULT_CONTENT_TYPE.into());
    let features = Features::default();
    let msg_type = if req.close_thread {
        Some(toq_core::types::MessageType::ThreadClose)
    } else {
        None
    };

    // Single recipient: preserve existing behavior and response shape
    if is_single {
        return send_to_single(
            &state,
            &keypair,
            &local_card,
            &features,
            SingleSendParams {
                target_addr: targets.remove(0),
                thread_id,
                content_type,
                body: req.body,
                reply_to: req.reply_to,
                msg_type,
                close_thread: req.close_thread,
            },
            &params,
        )
        .await;
    }

    // Multiple recipients: each gets an independent 1:1 thread
    let mut handles = Vec::with_capacity(targets.len());
    for target in targets {
        let kp = keypair.clone();
        let card = local_card.clone();
        let feats = features.clone();
        let state2 = state.clone();
        let tid = if has_explicit_thread {
            thread_id.clone()
        } else {
            uuid::Uuid::new_v4().to_string()
        };
        let ct = content_type.clone();
        let body = req.body.clone();
        let reply = req.reply_to.clone();
        let mt = msg_type.clone();
        handles.push(tokio::spawn(async move {
            let addr_str = target.to_string();
            let connect_addr = format!("{}:{}", target.host, target.port);
            let conn =
                server::connect_to_peer(&connect_addr, &kp, &state2.address, &card, &feats).await;
            let (info, mut stream) = match conn {
                Ok(r) => r,
                Err(e) => {
                    return MultiSendResult {
                        to: addr_str,
                        id: String::new(),
                        thread_id: tid,
                        status: STATUS_FAILED,
                        error: Some(format!("Cannot reach target: {e}")),
                    };
                }
            };
            let result = messaging::send_message(
                &mut stream,
                &kp,
                SendParams {
                    from: &state2.address,
                    to: std::slice::from_ref(&target),
                    sequence: INITIAL_MESSAGE_SEQUENCE,
                    body,
                    thread_id: Some(tid.clone()),
                    reply_to: reply,
                    priority: None,
                    content_type: Some(ct),
                    ttl: None,
                    msg_type: mt,
                },
            )
            .await;
            let msg_id = match result {
                Ok(id) => id,
                Err(e) => {
                    return MultiSendResult {
                        to: addr_str,
                        id: String::new(),
                        thread_id: tid,
                        status: STATUS_FAILED,
                        error: Some(format!("Failed to send: {e}")),
                    };
                }
            };
            state2.messages_out.fetch_add(1, Ordering::Relaxed);
            let next_seq = INITIAL_MESSAGE_SEQUENCE + 1;
            let _ = toq_core::connection::send_disconnect(
                &mut stream,
                &kp,
                &state2.address,
                &target,
                next_seq,
            )
            .await;
            let _ = framing::recv_envelope(
                &mut stream,
                &info.peer_public_key,
                DEFAULT_MAX_MESSAGE_SIZE,
            )
            .await;
            MultiSendResult {
                to: addr_str,
                id: msg_id.to_string(),
                thread_id: tid,
                status: STATUS_QUEUED,
                error: None,
            }
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        match h.await {
            Ok(r) => results.push(r),
            Err(_) => results.push(MultiSendResult {
                to: String::new(),
                id: String::new(),
                thread_id: String::new(),
                status: STATUS_FAILED,
                error: Some("Internal error".into()),
            }),
        }
    }

    // Broadcast each successful send on local SSE
    let msg_type_str = if req.close_thread {
        "thread.close"
    } else {
        "message.send"
    };
    for r in &results {
        if r.status == STATUS_DELIVERED || r.status == STATUS_QUEUED {
            let _ = state.message_tx.send(IncomingMessage {
                id: r.id.clone(),
                msg_type: msg_type_str.into(),
                from: state.address.to_string(),
                body: req.body.clone(),
                thread_id: Some(r.thread_id.clone()),
                reply_to: req.reply_to.clone(),
                content_type: Some(content_type.clone()),
                timestamp: toq_core::now_utc(),
            });
        }
    }

    (
        StatusCode::OK,
        Json(MultiSendResponse {
            results,
            timestamp: toq_core::now_utc(),
        }),
    )
        .into_response()
}

struct SingleSendParams {
    target_addr: Address,
    thread_id: String,
    content_type: String,
    body: Option<serde_json::Value>,
    reply_to: Option<String>,
    msg_type: Option<toq_core::types::MessageType>,
    close_thread: bool,
}

async fn send_to_single(
    state: &ApiState,
    keypair: &toq_core::crypto::Keypair,
    local_card: &AgentCard,
    features: &Features,
    p: SingleSendParams,
    params: &SendMessageParams,
) -> Response {
    let connect_addr = format!("{}:{}", p.target_addr.host, p.target_addr.port);
    let connect_result =
        server::connect_to_peer(&connect_addr, keypair, &state.address, local_card, features).await;

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

    let body_for_sse = p.body.clone();
    let reply_to_for_sse = p.reply_to.clone();
    let content_type_for_sse = p.content_type.clone();

    let msg_result = messaging::send_message(
        &mut stream,
        keypair,
        SendParams {
            from: &state.address,
            to: std::slice::from_ref(&p.target_addr),
            sequence: INITIAL_MESSAGE_SEQUENCE,
            body: p.body,
            thread_id: Some(p.thread_id.clone()),
            reply_to: p.reply_to,
            priority: None,
            content_type: Some(p.content_type),
            ttl: None,
            msg_type: p.msg_type,
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

    state.messages_out.fetch_add(1, Ordering::Relaxed);

    // Broadcast outgoing message on local SSE
    let _ = state.message_tx.send(IncomingMessage {
        id: msg_id.to_string(),
        msg_type: if p.close_thread {
            "thread.close"
        } else {
            "message.send"
        }
        .into(),
        from: state.address.to_string(),
        body: body_for_sse,
        thread_id: Some(p.thread_id.clone()),
        reply_to: reply_to_for_sse,
        content_type: Some(content_type_for_sse),
        timestamp: toq_core::now_utc(),
    });

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
                    thread_id: p.thread_id,
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
            keypair,
            &state.address,
            &p.target_addr,
            next_seq,
        )
        .await;
        result
    } else {
        let _ = toq_core::connection::send_disconnect(
            &mut stream,
            keypair,
            &state.address,
            &p.target_addr,
            next_seq,
        )
        .await;
        (
            StatusCode::ACCEPTED,
            Json(SendMessageResponse {
                id: msg_id.to_string(),
                status: STATUS_QUEUED,
                thread_id: p.thread_id,
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

// ── Stream API ──────────────────────────────────────────────

pub async fn stream_start(
    State(state): State<ApiState>,
    Json(req): Json<StreamStartRequest>,
) -> Response {
    let keypair = state.keypair.read().await;
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
    let local_card = AgentCard {
        name: config.agent_name.clone(),
        description: None,
        public_key: keypair.public_key().to_encoded(),
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

    let features = toq_core::negotiation::Features::default();
    let connect_addr = format!("{}:{}", target_addr.host, target_addr.port);

    let connect_result = server::connect_to_peer(
        &connect_addr,
        &keypair,
        &state.address,
        &local_card,
        &features,
    )
    .await;

    let (info, stream) = match connect_result {
        Ok(r) => r,
        Err(e) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                ERR_NOT_REACHABLE,
                format!("Cannot reach target: {e}"),
            );
        }
    };

    let stream_id = uuid::Uuid::new_v4().to_string();
    let thread_id = req
        .thread_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    state.active_streams.lock().await.insert(
        stream_id.clone(),
        crate::api::state::ActiveStream {
            stream,
            peer_address: info.peer_address,
            peer_public_key: info.peer_public_key,
            sequence: INITIAL_MESSAGE_SEQUENCE,
            thread_id: Some(thread_id.clone()),
        },
    );

    json_ok(StreamStartResponse {
        stream_id,
        thread_id,
    })
}

pub async fn stream_chunk(
    State(state): State<ApiState>,
    Json(req): Json<StreamChunkRequest>,
) -> Response {
    let keypair = state.keypair.read().await;
    let mut streams = state.active_streams.lock().await;
    let active = match streams.get_mut(&req.stream_id) {
        Some(s) => s,
        None => {
            return error_response(StatusCode::NOT_FOUND, ERR_NOT_FOUND, "Stream not found");
        }
    };

    let result = toq_core::streaming::send_chunk(
        &mut active.stream,
        &keypair,
        toq_core::streaming::ChunkParams {
            from: &state.address,
            to: &active.peer_address,
            stream_id: &req.stream_id,
            data: serde_json::json!({"text": req.text}),
            sequence: active.sequence,
            thread_id: active.thread_id.clone(),
            content_type: None,
        },
    )
    .await;

    match result {
        Ok(id) => {
            active.sequence += 1;
            // Read ACK to prevent TCP deadlock: receiver's send_ack blocks
            // if our receive buffer is full, which blocks recv_envelope,
            // which means no more chunks get processed.
            let _ = framing::recv_envelope(
                &mut active.stream,
                &active.peer_public_key,
                DEFAULT_MAX_MESSAGE_SIZE,
            )
            .await;
            json_ok(StreamChunkResponse {
                chunk_id: id.to_string(),
            })
        }
        Err(e) => {
            streams.remove(&req.stream_id);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_NOT_REACHABLE,
                format!("Failed to send chunk: {e}"),
            )
        }
    }
}

pub async fn stream_end(
    State(state): State<ApiState>,
    Json(req): Json<StreamEndRequest>,
) -> Response {
    let keypair = state.keypair.read().await;
    let mut streams = state.active_streams.lock().await;
    let active = match streams.remove(&req.stream_id) {
        Some(s) => s,
        None => {
            return error_response(StatusCode::NOT_FOUND, ERR_NOT_FOUND, "Stream not found");
        }
    };
    drop(streams);

    let data = req.text.map(|t| serde_json::json!({"text": t}));
    let mut stream = active.stream;
    let mut seq = active.sequence;

    let result = toq_core::streaming::send_end(
        &mut stream,
        &keypair,
        &state.address,
        &active.peer_address,
        &req.stream_id,
        data,
        seq,
        active.thread_id.clone(),
    )
    .await;

    let end_id = match result {
        Ok(id) => id,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_NOT_REACHABLE,
                format!("Failed to end stream: {e}"),
            );
        }
    };
    seq += 1;

    // +1 for StreamEnd ACK
    let mut acks_expected = 1;

    if req.close_thread {
        let _ = toq_core::messaging::send_message(
            &mut stream,
            &keypair,
            toq_core::messaging::SendParams {
                from: &state.address,
                to: std::slice::from_ref(&active.peer_address),
                sequence: seq,
                body: None,
                thread_id: active.thread_id.clone(),
                reply_to: None,
                priority: None,
                content_type: None,
                ttl: None,
                msg_type: Some(toq_core::types::MessageType::ThreadClose),
            },
        )
        .await;
        acks_expected += 1;
    }

    // Broadcast stream end on local SSE
    let _ = state.message_tx.send(IncomingMessage {
        id: end_id.to_string(),
        msg_type: if req.close_thread {
            "thread.close"
        } else {
            "message.stream.end"
        }
        .into(),
        from: state.address.to_string(),
        body: None,
        thread_id: active.thread_id,
        reply_to: None,
        content_type: None,
        timestamp: toq_core::now_utc(),
    });

    // Drain all pending ACKs before dropping the connection.
    // This confirms the receiver processed every message.
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..acks_expected {
            if framing::recv_envelope(
                &mut stream,
                &active.peer_public_key,
                DEFAULT_MAX_MESSAGE_SIZE,
            )
            .await
            .is_err()
            {
                break;
            }
        }
    })
    .await;

    json_ok(StreamChunkResponse {
        chunk_id: end_id.to_string(),
    })
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

pub async fn block_peer(State(state): State<ApiState>, Path(public_key): Path<String>) -> Response {
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
    state
        .policy
        .lock()
        .await
        .block(toq_core::policy::PermissionRule::Key(
            pk.as_bytes().to_vec(),
        ));
    StatusCode::OK.into_response()
}

pub async fn unblock_peer(
    State(state): State<ApiState>,
    Path(public_key): Path<String>,
) -> Response {
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
    store.peers.remove(&public_key);
    let _ = store.save(&keystore::peers_path());
    state
        .policy
        .lock()
        .await
        .unblock(&toq_core::policy::PermissionRule::Key(
            pk.as_bytes().to_vec(),
        ));
    StatusCode::OK.into_response()
}

// ── Rule-based permissions ──────────────────────────────────

#[derive(Deserialize)]
pub struct RuleBody {
    pub key: Option<String>,
    pub from: Option<String>,
}

fn parse_rule(
    body: &RuleBody,
) -> Result<toq_core::policy::PermissionRule, (StatusCode, &'static str, &'static str)> {
    use toq_core::policy::PermissionRule;
    if let Some(addr) = &body.from {
        return Ok(PermissionRule::Address(addr.clone()));
    }
    if let Some(k) = &body.key {
        match toq_core::crypto::PublicKey::from_encoded(k) {
            Ok(pk) => return Ok(PermissionRule::Key(pk.as_bytes().to_vec())),
            Err(_) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    ERR_INVALID_REQUEST,
                    "Invalid public key",
                ));
            }
        }
    }
    Err((
        StatusCode::BAD_REQUEST,
        ERR_INVALID_REQUEST,
        "Specify 'key' or 'from'",
    ))
}

pub async fn block_rule(State(state): State<ApiState>, Json(body): Json<RuleBody>) -> Response {
    let rule = match parse_rule(&body) {
        Ok(r) => r,
        Err((status, code, msg)) => return error_response(status, code, msg),
    };
    // Persist key-based rules to PeerStore
    if let toq_core::policy::PermissionRule::Key(ref kb) = rule
        && let Some(pk) = toq_core::crypto::PublicKey::from_bytes(kb)
    {
        let mut store = keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
        store.upsert(&pk, "", keystore::PeerStatus::Blocked);
        let _ = store.save(&keystore::peers_path());
    }
    state.policy.lock().await.block(rule);
    StatusCode::OK.into_response()
}

pub async fn unblock_rule(State(state): State<ApiState>, Json(body): Json<RuleBody>) -> Response {
    let rule = match parse_rule(&body) {
        Ok(r) => r,
        Err((status, code, msg)) => return error_response(status, code, msg),
    };
    if let toq_core::policy::PermissionRule::Key(ref kb) = rule
        && let Some(pk) = toq_core::crypto::PublicKey::from_bytes(kb)
    {
        let mut store = keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
        store.peers.remove(&pk.to_encoded());
        let _ = store.save(&keystore::peers_path());
    }
    state.policy.lock().await.unblock(&rule);
    StatusCode::OK.into_response()
}

pub async fn approve_rule(State(state): State<ApiState>, Json(body): Json<RuleBody>) -> Response {
    let rule = match parse_rule(&body) {
        Ok(r) => r,
        Err((status, code, msg)) => return error_response(status, code, msg),
    };
    if let toq_core::policy::PermissionRule::Key(ref kb) = rule
        && let Some(pk) = toq_core::crypto::PublicKey::from_bytes(kb)
    {
        let mut store = keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
        store.upsert(&pk, "", keystore::PeerStatus::Approved);
        let _ = store.save(&keystore::peers_path());
    }
    state.policy.lock().await.approve(rule);
    StatusCode::OK.into_response()
}

pub async fn revoke_rule(State(state): State<ApiState>, Json(body): Json<RuleBody>) -> Response {
    let rule = match parse_rule(&body) {
        Ok(r) => r,
        Err((status, code, msg)) => return error_response(status, code, msg),
    };
    if let toq_core::policy::PermissionRule::Key(ref kb) = rule
        && let Some(pk) = toq_core::crypto::PublicKey::from_bytes(kb)
    {
        let mut store = keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
        store.peers.remove(&pk.to_encoded());
        let _ = store.save(&keystore::peers_path());
    }
    state.policy.lock().await.revoke(&rule);
    StatusCode::OK.into_response()
}

pub async fn list_permissions(State(state): State<ApiState>) -> Response {
    use toq_core::policy::PermissionRule;

    let policy = state.policy.lock().await;
    let format_rule = |r: &PermissionRule| match r {
        PermissionRule::Key(kb) => {
            let val = toq_core::crypto::PublicKey::from_bytes(kb)
                .map(|pk| pk.to_encoded())
                .unwrap_or_else(|| "invalid".into());
            serde_json::json!({"type": "key", "value": val})
        }
        PermissionRule::Address(addr) => {
            serde_json::json!({"type": "address", "value": addr})
        }
    };

    let approved: Vec<_> = policy.list_approved().iter().map(format_rule).collect();
    let blocked: Vec<_> = policy.list_blocked().iter().map(format_rule).collect();

    json_ok(serde_json::json!({
        "approved": approved,
        "blocked": blocked,
    }))
}

#[derive(Deserialize)]
pub struct PingBody {
    pub address: String,
}

pub async fn ping_agent(State(state): State<ApiState>, Json(body): Json<PingBody>) -> Response {
    use toq_core::server;

    let target: Address = match body.address.parse() {
        Ok(a) => a,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_REQUEST,
                "Invalid toq address",
            );
        }
    };

    let keypair = match keystore::load_keypair(&keystore::identity_key_path()) {
        Ok(kp) => kp,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Failed to load keypair",
            );
        }
    };

    let config = state.config.lock().await;
    let address = match Address::new(&config.host, &config.agent_name) {
        Ok(a) => a,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Invalid local address",
            );
        }
    };
    let card = super::super::load_card(&config, &keypair);
    let features = Features::default();
    drop(config);

    let connect_addr = format!("{}:{}", target.host, target.port);
    match server::connect_to_peer(&connect_addr, &keypair, &address, &card, &features).await {
        Ok((info, _stream)) => {
            let peer_key = info.peer_public_key.to_encoded();
            let agent_name = info.peer_card.name.clone();
            json_ok(serde_json::json!({
                "agent_name": agent_name,
                "address": body.address,
                "public_key": peer_key,
                "reachable": true,
            }))
        }
        Err(e) => {
            let msg = format!("{e}");
            // Connection failed but we might have gotten the key during handshake
            json_ok(serde_json::json!({
                "agent_name": target.agent_name,
                "address": body.address,
                "public_key": null,
                "reachable": false,
                "error": msg,
            }))
        }
    }
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
        "approve" => {
            let address = policy
                .list_pending()
                .iter()
                .find(|p| {
                    PublicKey::from_bytes(&p.public_key)
                        .map(|k| k.to_encoded() == id)
                        .unwrap_or(false)
                })
                .map(|p| p.address.clone())
                .unwrap_or_default();
            policy.approve_pending(&pk);
            let mut store = keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
            store.upsert(&pk, &address, keystore::PeerStatus::Approved);
            let _ = store.save(&keystore::peers_path());
        }
        "deny" => {
            policy.deny(&pk);
            let mut store = keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
            let is_pending = store
                .get(&pk)
                .map(|r| r.status == keystore::PeerStatus::Pending)
                .unwrap_or(false);
            if is_pending {
                store.peers.remove(&id);
                let _ = store.save(&keystore::peers_path());
            }
        }
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

pub async fn revoke_approval(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
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
    policy.revoke(&toq_core::policy::PermissionRule::Key(
        pk.as_bytes().to_vec(),
    ));

    let mut store = keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
    store.peers.remove(&id);
    let _ = store.save(&keystore::peers_path());

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

pub async fn message_history(
    State(state): State<ApiState>,
    Query(params): Query<crate::api::types::HistoryQuery>,
) -> Response {
    let config = state.config.lock().await;
    let max = config.message_history_limit.unwrap_or(1000);
    drop(config);
    let limit = params.limit.unwrap_or(50).min(max);
    let history = state.history.lock().await;
    let messages = history.query(limit, params.from.as_deref(), params.since.as_deref());
    json_ok(crate::api::types::HistoryResponse { messages })
}

pub async fn health_check() -> &'static str {
    "ok"
}

pub async fn get_status(State(state): State<ApiState>) -> Response {
    let config = state.config.lock().await;
    let keypair = state.keypair.read().await;
    json_ok(StatusResponse {
        status: "running",
        address: state.address.to_string(),
        connection_mode: config.connection_mode.clone(),
        active_connections: state.active_connections.load(Ordering::Relaxed),
        messages_in: state.messages_in.load(Ordering::Relaxed),
        messages_out: state.messages_out.load(Ordering::Relaxed),
        error_count: state.error_count.load(Ordering::Relaxed),
        backpressure_active: false,
        version: env!("CARGO_PKG_VERSION"),
        public_key: keypair.public_key().to_encoded(),
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

pub async fn rotate_keys(State(state): State<ApiState>) -> Response {
    let current_keypair = state.keypair.read().await;
    let old_public = current_keypair.public_key().to_encoded();
    let new_keypair = toq_core::crypto::Keypair::generate();
    let new_public = new_keypair.public_key();
    let proof = toq_core::crypto::generate_rotation_proof(&current_keypair, &new_public);
    drop(current_keypair);

    if let Err(e) = keystore::save_keypair(&new_keypair, &keystore::identity_key_path()) {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INVALID_REQUEST,
            format!("Failed to save new keys: {e}"),
        );
    }

    // Update in-memory keypair so all subsequent requests use the new key
    *state.keypair.write().await = new_keypair;

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
    let keypair = state.keypair.read().await;
    json_ok(AgentCardResponse {
        name: config.agent_name.clone(),
        description: None,
        public_key: keypair.public_key().to_encoded(),
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

        ApiState::new(crate::api::state::ApiStateParams {
            config: Config::default(),
            keypair,
            address,
            active_connections: Arc::new(AtomicUsize::new(0)),
            messages_in: Arc::new(AtomicUsize::new(0)),
            messages_out: Arc::new(AtomicUsize::new(0)),
            error_count: Arc::new(AtomicUsize::new(0)),
            policy,
            sessions,
        })
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

    /// URL-encode a public key for use in API paths.
    fn url_encode(s: &str) -> String {
        s.replace('%', "%25")
            .replace('/', "%2F")
            .replace(':', "%3A")
            .replace('+', "%2B")
            .replace('=', "%3D")
    }

    #[tokio::test]
    async fn block_peer_updates_policy() {
        let state = test_state();
        let kp = toq_core::crypto::Keypair::generate();
        let encoded = url_encode(&kp.public_key().to_encoded());

        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::post(format!("/v1/peers/{encoded}/block"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let policy = state.policy.lock().await;
        assert!(policy.is_blocked(&kp.public_key()));
    }

    #[tokio::test]
    async fn unblock_peer_updates_policy() {
        let state = test_state();
        let kp = toq_core::crypto::Keypair::generate();
        let encoded = url_encode(&kp.public_key().to_encoded());

        state
            .policy
            .lock()
            .await
            .block(toq_core::policy::PermissionRule::Key(
                kp.public_key().as_bytes().to_vec(),
            ));
        assert!(state.policy.lock().await.is_blocked(&kp.public_key()));

        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::delete(format!("/v1/peers/{encoded}/block"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        assert!(!state.policy.lock().await.is_blocked(&kp.public_key()));
    }

    #[tokio::test]
    async fn approve_updates_policy() {
        let state = test_state();
        let kp = toq_core::crypto::Keypair::generate();
        let encoded = url_encode(&kp.public_key().to_encoded());

        state
            .policy
            .lock()
            .await
            .add_pending(&kp.public_key(), "toq://test/peer");

        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::post(format!("/v1/approvals/{encoded}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"decision":"approve"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let policy = state.policy.lock().await;
        assert_eq!(policy.pending_count(), 0);
        assert_eq!(
            policy.check(&kp.public_key(), "toq://test/peer"),
            toq_core::policy::PolicyDecision::Accept
        );
    }

    #[tokio::test]
    async fn deny_updates_policy() {
        let state = test_state();
        let kp = toq_core::crypto::Keypair::generate();
        let encoded = url_encode(&kp.public_key().to_encoded());

        state
            .policy
            .lock()
            .await
            .add_pending(&kp.public_key(), "toq://test/peer");

        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::post(format!("/v1/approvals/{encoded}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"decision":"deny"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        assert_eq!(state.policy.lock().await.pending_count(), 0);
    }

    #[tokio::test]
    async fn approve_in_allowlist_mode() {
        use toq_core::policy::{ConnectionMode, PolicyDecision, PolicyEngine};

        let kp = toq_core::crypto::Keypair::generate();
        let encoded = url_encode(&kp.public_key().to_encoded());

        let state = test_state();
        *state.policy.lock().await = PolicyEngine::new(ConnectionMode::Allowlist);

        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::post(format!("/v1/approvals/{encoded}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"decision":"approve"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        assert_eq!(
            state
                .policy
                .lock()
                .await
                .check(&kp.public_key(), "toq://test/peer"),
            PolicyDecision::Accept
        );
    }

    #[tokio::test]
    async fn unblock_invalid_key_returns_400() {
        let app = crate::api::router(test_state());
        let resp = app
            .oneshot(
                Request::delete("/v1/peers/not-a-valid-key/block")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn deny_invalid_decision() {
        let kp = toq_core::crypto::Keypair::generate();
        let encoded = url_encode(&kp.public_key().to_encoded());

        let app = crate::api::router(test_state());
        let resp = app
            .oneshot(
                Request::post(format!("/v1/approvals/{encoded}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"decision":"maybe"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn block_then_check_rejects() {
        let state = test_state();
        let kp = toq_core::crypto::Keypair::generate();
        let encoded = url_encode(&kp.public_key().to_encoded());

        // Approve first
        state.policy.lock().await.approve_pending(&kp.public_key());
        assert_eq!(
            state
                .policy
                .lock()
                .await
                .check(&kp.public_key(), "toq://test/peer"),
            toq_core::policy::PolicyDecision::Accept
        );

        // Block via API
        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::post(format!("/v1/peers/{encoded}/block"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Now rejected
        assert_eq!(
            state
                .policy
                .lock()
                .await
                .check(&kp.public_key(), "toq://test/peer"),
            toq_core::policy::PolicyDecision::Reject
        );
    }

    #[tokio::test]
    async fn approvals_lists_pending() {
        let state = test_state();
        let kp = toq_core::crypto::Keypair::generate();
        state
            .policy
            .lock()
            .await
            .add_pending(&kp.public_key(), "toq://test/peer");

        let (status, body) = {
            let app = crate::api::router(state.clone());
            let resp = app
                .oneshot(Request::get("/v1/approvals").body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status().as_u16();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            (status, body)
        };
        assert_eq!(status, 200);
        let approvals = body["approvals"].as_array().unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0]["address"], "toq://test/peer");
    }

    #[tokio::test]
    async fn deny_nonexistent_key_noop() {
        let state = test_state();
        let kp = toq_core::crypto::Keypair::generate();
        let encoded = url_encode(&kp.public_key().to_encoded());

        // No pending, no approved, no blocked - just a random key
        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::post(format!("/v1/approvals/{encoded}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"decision":"deny"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(state.policy.lock().await.pending_count(), 0);
    }

    #[tokio::test]
    async fn unblock_then_check_pending() {
        let state = test_state();
        let kp = toq_core::crypto::Keypair::generate();
        let encoded = url_encode(&kp.public_key().to_encoded());

        // Approve, then block, then unblock
        state.policy.lock().await.approve_pending(&kp.public_key());
        state
            .policy
            .lock()
            .await
            .block(toq_core::policy::PermissionRule::Key(
                kp.public_key().as_bytes().to_vec(),
            ));

        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::delete(format!("/v1/peers/{encoded}/block"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // After unblock, not approved anymore, goes to PendingApproval
        assert_eq!(
            state
                .policy
                .lock()
                .await
                .check(&kp.public_key(), "toq://test/peer"),
            toq_core::policy::PolicyDecision::PendingApproval
        );
    }

    #[tokio::test]
    async fn block_rule_by_address() {
        let state = test_state();
        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::post("/v1/block")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"from":"toq://evil.com/*"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(state.policy.lock().await.list_blocked().len(), 1);
    }

    #[tokio::test]
    async fn approve_rule_by_address() {
        let state = test_state();
        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::post("/v1/approve")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"from":"toq://trusted.com/*"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(state.policy.lock().await.list_approved().len(), 1);
    }

    #[tokio::test]
    async fn approve_rule_by_key() {
        let state = test_state();
        let kp = toq_core::crypto::Keypair::generate();
        let body = serde_json::json!({"key": kp.public_key().to_encoded()});
        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::post("/v1/approve")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            state
                .policy
                .lock()
                .await
                .check(&kp.public_key(), "toq://any/addr"),
            toq_core::policy::PolicyDecision::Accept
        );
    }

    #[tokio::test]
    async fn revoke_rule_removes_access() {
        let state = test_state();
        // Approve first
        let app = crate::api::router(state.clone());
        let _ = app
            .oneshot(
                Request::post("/v1/approve")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"from":"toq://host/*"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(state.policy.lock().await.list_approved().len(), 1);

        // Revoke
        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::post("/v1/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"from":"toq://host/*"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(state.policy.lock().await.list_approved().len(), 0);
    }

    #[tokio::test]
    async fn unblock_rule_removes_block() {
        let state = test_state();
        let app = crate::api::router(state.clone());
        let _ = app
            .oneshot(
                Request::post("/v1/block")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"from":"toq://bad.com/*"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(state.policy.lock().await.list_blocked().len(), 1);

        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(
                Request::delete("/v1/block")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"from":"toq://bad.com/*"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(state.policy.lock().await.list_blocked().len(), 0);
    }

    #[tokio::test]
    async fn list_permissions_returns_rules() {
        let state = test_state();
        state
            .policy
            .lock()
            .await
            .approve(toq_core::policy::PermissionRule::Address(
                "toq://host/*".into(),
            ));
        state
            .policy
            .lock()
            .await
            .block(toq_core::policy::PermissionRule::Address(
                "toq://evil.com/*".into(),
            ));

        let app = crate::api::router(state.clone());
        let resp = app
            .oneshot(Request::get("/v1/permissions").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["approved"].as_array().unwrap().len(), 1);
        assert_eq!(body["blocked"].as_array().unwrap().len(), 1);
        assert_eq!(body["approved"][0]["type"], "address");
        assert_eq!(body["approved"][0]["value"], "toq://host/*");
    }

    #[tokio::test]
    async fn rule_missing_key_and_from_returns_400() {
        let app = crate::api::router(test_state());
        let resp = app
            .oneshot(
                Request::post("/v1/block")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }
}
