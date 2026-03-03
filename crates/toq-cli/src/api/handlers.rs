//! API endpoint handlers.

use std::sync::atomic::Ordering;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};

use toq_core::constants::PROTOCOL_VERSION;

use crate::api::state::ApiState;
use crate::api::types::*;

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

pub async fn get_logs() -> Response {
    let log_dir = toq_core::config::dirs_path().join(toq_core::constants::LOGS_DIR);
    let log_file = log_dir.join(toq_core::constants::LOG_FILE);

    let content = std::fs::read_to_string(&log_file).unwrap_or_default();
    let entries: Vec<LogEntry> = content
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| LogEntry {
            timestamp: String::new(),
            level: String::new(),
            message: line.to_string(),
        })
        .collect();

    json_ok(LogsResponse { entries })
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

pub async fn run_diagnostics() -> Response {
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

    match toq_core::keystore::load_keypair(&toq_core::keystore::identity_key_path()) {
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

    match toq_core::keystore::load_tls_cert(
        &toq_core::keystore::tls_cert_path(),
        &toq_core::keystore::tls_key_path(),
    ) {
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

    let issues = checks.iter().filter(|c| c.status == "fail").count();
    json_ok(DiagnosticsResponse { checks, issues })
}

// ── Peers ───────────────────────────────────────────────────

pub async fn list_peers() -> Response {
    let store =
        toq_core::keystore::PeerStore::load(&toq_core::keystore::peers_path()).unwrap_or_default();

    let peers = store
        .peers
        .iter()
        .map(|(key, record)| PeerEntry {
            public_key: key.clone(),
            address: record.address.clone(),
            status: format!("{:?}", record.status).to_lowercase(),
            last_seen: record.last_seen.clone(),
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

    let mut store =
        toq_core::keystore::PeerStore::load(&toq_core::keystore::peers_path()).unwrap_or_default();
    store.upsert(&pk, "", toq_core::keystore::PeerStatus::Blocked);
    let _ = store.save(&toq_core::keystore::peers_path());

    StatusCode::OK.into_response()
}

pub async fn unblock_peer(Path(public_key): Path<String>) -> Response {
    let mut store =
        toq_core::keystore::PeerStore::load(&toq_core::keystore::peers_path()).unwrap_or_default();
    store.peers.remove(&public_key);
    let _ = store.save(&toq_core::keystore::peers_path());

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

// ── Keys ────────────────────────────────────────────────────

pub async fn rotate_keys(State(state): State<ApiState>) -> Response {
    let old_public = state.keypair.public_key().to_encoded();
    let new_keypair = toq_core::crypto::Keypair::generate();
    let new_public = new_keypair.public_key();
    let proof = toq_core::crypto::generate_rotation_proof(&state.keypair, &new_public);

    if let Err(e) =
        toq_core::keystore::save_keypair(&new_keypair, &toq_core::keystore::identity_key_path())
    {
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
