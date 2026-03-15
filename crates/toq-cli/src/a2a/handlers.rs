//! A2A HTTP handlers for the daemon.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use std::sync::atomic::Ordering;
use subtle::ConstantTimeEq;

use super::task_store::TaskStore;
use super::types::*;
use crate::api::state::ApiState;
use crate::api::types::IncomingMessage;

const TASK_ID_PREFIX: &str = "task-";
const CONTEXT_ID_PREFIX: &str = "ctx-";
const A2A_REPLY_TIMEOUT_SECS: u64 = 30;
const A2A_CLIENT_FROM: &str = "a2a-client";

/// JSON-RPC method names per A2A spec section 9.4.
const METHOD_SEND_MESSAGE: &str = "SendMessage";
const METHOD_STREAM_MESSAGE: &str = "SendStreamingMessage";
const METHOD_GET_TASK: &str = "GetTask";
const METHOD_LIST_TASKS: &str = "ListTasks";
const METHOD_CANCEL_TASK: &str = "CancelTask";
const METHOD_SUBSCRIBE_TASK: &str = "SubscribeToTask";

/// A2A-specific state.
#[derive(Clone)]
pub struct A2aState {
    pub task_store: TaskStore,
    task_counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl A2aState {
    pub fn new() -> Self {
        Self {
            task_store: TaskStore::new(),
            task_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    fn next_task_id(&self) -> String {
        let n = self.task_counter.fetch_add(1, Ordering::Relaxed);
        format!("{TASK_ID_PREFIX}{n}")
    }
}

/// Bearer token auth middleware for A2A routes.
pub async fn auth_middleware(
    State(state): State<ApiState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let config = state.config.lock().await;
    let expected = match &config.a2a_api_key {
        Some(key) if !key.is_empty() => key.clone(),
        _ => {
            drop(config);
            return next.run(req).await;
        }
    };
    drop(config);

    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if auth.strip_prefix("Bearer ").is_some_and(|token| {
        token.len() == expected.len() && token.as_bytes().ct_eq(expected.as_bytes()).into()
    }) {
        return next.run(req).await;
    }

    let resp = JsonRpcResponse {
        jsonrpc: JSONRPC_VERSION.into(),
        id: serde_json::json!(null),
        result: None,
        error: Some(JsonRpcError {
            code: ERROR_INVALID_REQUEST,
            message: "Unauthorized".into(),
        }),
    };
    tracing::warn!("a2a: rejected unauthorized request");
    (StatusCode::UNAUTHORIZED, Json(resp)).into_response()
}

pub async fn agent_card_handler(State(state): State<ApiState>) -> Json<AgentCard> {
    let config = state.config.lock().await;
    let address = state.address.clone();

    let url = config
        .a2a_public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}/a2a", address.host, address.port));

    let name = format!("{} (toq)", config.agent_name);
    let description = format!("toq agent '{}' with A2A compatibility", config.agent_name);

    let mut security_schemes = None;
    let mut security_requirements = None;

    if config.a2a_api_key.is_some() {
        let mut schemes = std::collections::HashMap::new();
        schemes.insert(
            "bearer".into(),
            SecurityScheme {
                http_auth_security_scheme: Some(HttpAuthSecurityScheme {
                    description: Some("Bearer token authentication".into()),
                    scheme: "bearer".into(),
                }),
            },
        );
        security_schemes = Some(schemes);

        let mut req = std::collections::HashMap::new();
        req.insert("bearer".into(), vec![]);
        security_requirements = Some(vec![req]);
    }

    Json(AgentCard {
        protocol_version: A2A_PROTOCOL_VERSION.into(),
        name,
        description,
        url: url.clone(),
        supported_interfaces: vec![AgentInterface {
            url,
            protocol_binding: "JSONRPC".into(),
            protocol_version: A2A_PROTOCOL_VERSION.into(),
        }],
        provider: Some(AgentProvider {
            url: "https://github.com/toqprotocol".into(),
            organization: "toq protocol".into(),
        }),
        version: env!("CARGO_PKG_VERSION").into(),
        capabilities: AgentCapabilities {
            streaming: Some(true),
            push_notifications: Some(false),
        },
        security_schemes,
        security_requirements,
        default_input_modes: vec!["text/plain".into()],
        default_output_modes: vec!["text/plain".into()],
        skills: vec![AgentSkill {
            id: "default".into(),
            name: config.agent_name.clone(),
            description: "toq agent with A2A compatibility".into(),
            tags: vec!["toq".into(), "a2a".into()],
        }],
    })
}

pub async fn jsonrpc_handler(
    State(state): State<ApiState>,
    Json(req): Json<JsonRpcRequest>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    if req.jsonrpc != JSONRPC_VERSION {
        return error_response(req.id, ERROR_INVALID_REQUEST, "Invalid JSON-RPC version")
            .into_response();
    }

    // Detect protocol version from method name style.
    // v0.3 uses slash-style (message/send), v1.0 uses PascalCase (SendMessage).
    let is_v03 = req.method.contains('/');

    match req.method.as_str() {
        METHOD_SEND_MESSAGE | METHOD_SEND_MESSAGE_V03 => {
            tracing::info!("a2a: SendMessage (id={})", req.id);
            handle_send_message(state, req.id, req.params, is_v03)
                .await
                .into_response()
        }
        METHOD_STREAM_MESSAGE | METHOD_STREAM_MESSAGE_V03 => {
            tracing::info!("a2a: SendStreamingMessage (id={})", req.id);
            handle_stream_message(state, req.id, req.params, is_v03).await
        }
        METHOD_GET_TASK | METHOD_GET_TASK_V03 => {
            tracing::debug!("a2a: GetTask (id={})", req.id);
            handle_get_task(state, req.id, req.params, is_v03).into_response()
        }
        METHOD_LIST_TASKS | METHOD_LIST_TASKS_V03 => {
            tracing::debug!("a2a: ListTasks (id={})", req.id);
            handle_list_tasks(state, req.id, req.params, is_v03).into_response()
        }
        METHOD_CANCEL_TASK | METHOD_CANCEL_TASK_V03 => {
            tracing::info!("a2a: CancelTask (id={})", req.id);
            handle_cancel_task(state, req.id, req.params, is_v03).into_response()
        }
        METHOD_SUBSCRIBE_TASK | METHOD_SUBSCRIBE_TASK_V03 => {
            tracing::info!("a2a: SubscribeToTask (id={})", req.id);
            handle_subscribe_task(state, req.id, req.params, is_v03).await
        }
        _ => {
            tracing::warn!("a2a: unknown method '{}' (id={})", req.method, req.id);
            error_response(req.id, ERROR_METHOD_NOT_FOUND, "Method not found").into_response()
        }
    }
}

async fn handle_send_message(
    state: ApiState,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
    is_v03: bool,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let params = match params {
        Some(p) => p,
        None => return error_response(id, ERROR_INVALID_PARAMS, "Missing params"),
    };

    let req: SendMessageRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => return error_response(id, ERROR_INVALID_PARAMS, &format!("Invalid params: {e}")),
    };

    let body_text = req
        .message
        .parts
        .iter()
        .filter_map(|p| p.text.as_deref())
        .collect::<Vec<_>>()
        .join("");

    if body_text.is_empty() {
        return error_response(
            id,
            ERROR_CONTENT_TYPE_NOT_SUPPORTED,
            "Only text parts are supported",
        );
    }

    let a2a = state.a2a.clone();
    let task_id = a2a.next_task_id();
    let context_id = req
        .message
        .context_id
        .clone()
        .unwrap_or_else(|| format!("{CONTEXT_ID_PREFIX}{task_id}"));
    let thread_id = context_id.clone();

    // Create task in submitted state
    let task = Task {
        id: task_id.clone(),
        context_id,
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: Some(toq_core::now_utc()),
        },
        artifacts: None,
        history: Some(vec![req.message]),
    };
    if !a2a.task_store.insert(task) {
        return error_response(id, ERROR_TASK_QUEUE_FULL, "Task queue is full");
    }

    // Register reply channel keyed by thread_id
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    state
        .a2a_reply_channels
        .lock()
        .await
        .insert(thread_id.clone(), tx);

    // Dispatch as incoming message to handler manager
    let incoming = IncomingMessage {
        id: uuid::Uuid::new_v4().to_string(),
        msg_type: "message.send".into(),
        from: A2A_CLIENT_FROM.into(),
        body: Some(serde_json::json!({"text": body_text})),
        thread_id: Some(thread_id.clone()),
        reply_to: None,
        content_type: Some("application/json".into()),
        timestamp: toq_core::now_utc(),
    };

    state.history.lock().await.push(&incoming);
    state.handler_manager.lock().await.dispatch(&incoming, None);
    let _ = state.message_tx.send(incoming);

    // Wait for handler reply
    let reply_text = match tokio::time::timeout(
        std::time::Duration::from_secs(A2A_REPLY_TIMEOUT_SECS),
        rx,
    )
    .await
    {
        Ok(Ok(text)) => text,
        _ => {
            state.a2a_reply_channels.lock().await.remove(&thread_id);
            a2a.task_store.update_state(&task_id, TaskState::Failed);
            return error_response(id, ERROR_INTERNAL, "Handler did not respond in time");
        }
    };

    match a2a.task_store.complete_with_text(&task_id, &reply_text) {
        Some(completed) => match serde_json::to_value(completed) {
            Ok(v) => success_response_v03(id, v, is_v03),
            Err(e) => error_response(id, ERROR_INTERNAL, &format!("Serialization error: {e}")),
        },
        None => error_response(
            id,
            ERROR_TASK_NOT_FOUND,
            "Task disappeared during processing",
        ),
    }
}

fn handle_get_task(
    state: ApiState,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
    is_v03: bool,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let params = match params {
        Some(p) => p,
        None => return error_response(id, ERROR_INVALID_PARAMS, "Missing params"),
    };

    let req: GetTaskRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => return error_response(id, ERROR_INVALID_PARAMS, &format!("Invalid params: {e}")),
    };

    match state.a2a.task_store.get(&req.id) {
        Some(task) => match serde_json::to_value(task) {
            Ok(v) => success_response_v03(id, v, is_v03),
            Err(e) => error_response(id, ERROR_INTERNAL, &format!("Serialization error: {e}")),
        },
        None => error_response(id, ERROR_TASK_NOT_FOUND, "Task not found"),
    }
}

fn handle_cancel_task(
    state: ApiState,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
    is_v03: bool,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let params = match params {
        Some(p) => p,
        None => return error_response(id, ERROR_INVALID_PARAMS, "Missing params"),
    };

    let req: CancelTaskRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => return error_response(id, ERROR_INVALID_PARAMS, &format!("Invalid params: {e}")),
    };

    match state.a2a.task_store.get(&req.id) {
        Some(task) => {
            if is_terminal(&task.status.state) {
                return error_response(
                    id,
                    ERROR_TASK_NOT_CANCELABLE,
                    "Task is already in a terminal state",
                );
            }
            match state
                .a2a
                .task_store
                .update_state(&req.id, TaskState::Canceled)
            {
                Some(updated) => match serde_json::to_value(updated) {
                    Ok(v) => success_response_v03(id, v, is_v03),
                    Err(e) => {
                        error_response(id, ERROR_INTERNAL, &format!("Serialization error: {e}"))
                    }
                },
                None => error_response(id, ERROR_TASK_NOT_CANCELABLE, "Task cannot be canceled"),
            }
        }
        None => error_response(id, ERROR_TASK_NOT_FOUND, "Task not found"),
    }
}

fn handle_list_tasks(
    state: ApiState,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
    is_v03: bool,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let req: ListTasksRequest = params
        .and_then(|p| serde_json::from_value(p).ok())
        .unwrap_or(ListTasksRequest {
            context_id: None,
            status: None,
        });

    let tasks = state
        .a2a
        .task_store
        .list(req.context_id.as_deref(), req.status.as_ref());

    match serde_json::to_value(tasks) {
        Ok(v) => success_response_v03(id, v, is_v03),
        Err(e) => error_response(id, ERROR_INTERNAL, &format!("Serialization error: {e}")),
    }
}

/// Streaming message handler. Returns SSE with task lifecycle events.
async fn handle_stream_message(
    state: ApiState,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
    is_v03: bool,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use axum::response::sse::{Event, KeepAlive, Sse};

    let params = match params {
        Some(p) => p,
        None => {
            return error_response(id.clone(), ERROR_INVALID_PARAMS, "Missing params")
                .into_response();
        }
    };

    let req: SendMessageRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            return error_response(
                id.clone(),
                ERROR_INVALID_PARAMS,
                &format!("Invalid params: {e}"),
            )
            .into_response();
        }
    };

    let body_text = req
        .message
        .parts
        .iter()
        .filter_map(|p| p.text.as_deref())
        .collect::<Vec<_>>()
        .join("");

    if body_text.is_empty() {
        return error_response(
            id.clone(),
            ERROR_CONTENT_TYPE_NOT_SUPPORTED,
            "Only text parts are supported",
        )
        .into_response();
    }

    let a2a = state.a2a.clone();
    let task_id = a2a.next_task_id();
    let context_id = req
        .message
        .context_id
        .clone()
        .unwrap_or_else(|| format!("{CONTEXT_ID_PREFIX}{task_id}"));
    let thread_id = context_id.clone();

    let task = Task {
        id: task_id.clone(),
        context_id: context_id.clone(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: Some(toq_core::now_utc()),
        },
        artifacts: None,
        history: Some(vec![req.message]),
    };
    if !a2a.task_store.insert(task.clone()) {
        return error_response(id.clone(), ERROR_TASK_QUEUE_FULL, "Task queue is full")
            .into_response();
    }

    // Register reply channel
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    state
        .a2a_reply_channels
        .lock()
        .await
        .insert(thread_id.clone(), tx);

    // Dispatch to handler
    let incoming = IncomingMessage {
        id: uuid::Uuid::new_v4().to_string(),
        msg_type: "message.send".into(),
        from: A2A_CLIENT_FROM.into(),
        body: Some(serde_json::json!({"text": body_text})),
        thread_id: Some(thread_id.clone()),
        reply_to: None,
        content_type: Some("application/json".into()),
        timestamp: toq_core::now_utc(),
    };
    state.history.lock().await.push(&incoming);
    state.handler_manager.lock().await.dispatch(&incoming, None);
    let _ = state.message_tx.send(incoming);

    // Return SSE stream
    let stream = async_stream::stream! {
        // Event 1: Task in submitted state
        let mut task_val = serde_json::to_value(&task).unwrap_or_default();
        if is_v03 { to_v03(&mut task_val); }
        let sse_resp = serde_json::json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": id,
            "result": task_val,
        });
        yield Ok::<_, std::convert::Infallible>(
            Event::default().data(sse_resp.to_string())
        );

        // Event 2: Status update to working
        a2a.task_store.update_state(&task_id, TaskState::Working);
        let mut status_evt = serde_json::to_value(TaskStatusUpdateEvent {
            task_id: task_id.clone(),
            context_id: context_id.clone(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: Some(toq_core::now_utc()),
            },
        }).unwrap_or_default();
        if is_v03 { to_v03(&mut status_evt); }
        let sse_resp = serde_json::json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": id,
            "result": status_evt,
        });
        yield Ok(Event::default().data(sse_resp.to_string()));

        // Wait for handler reply
        let reply_text = match tokio::time::timeout(
            std::time::Duration::from_secs(A2A_REPLY_TIMEOUT_SECS),
            rx,
        ).await {
            Ok(Ok(text)) => text,
            _ => {
                state.a2a_reply_channels.lock().await.remove(&thread_id);
                a2a.task_store.update_state(&task_id, TaskState::Failed);
                let mut evt = serde_json::to_value(TaskStatusUpdateEvent {
                    task_id: task_id.clone(),
                    context_id: context_id.clone(),
                    status: TaskStatus {
                        state: TaskState::Failed,
                        message: None,
                        timestamp: Some(toq_core::now_utc()),
                    },
                }).unwrap_or_default();
                if is_v03 { to_v03(&mut evt); }
                let sse_resp = serde_json::json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "id": id,
                    "result": evt,
                });
                yield Ok(Event::default().data(sse_resp.to_string()));
                return;
            }
        };

        // Event 3: Artifact with reply text
        if let Some(completed) = a2a.task_store.complete_with_text(&task_id, &reply_text) {
            if let Some(ref artifacts) = completed.artifacts {
                for artifact in artifacts {
                    let mut art_evt = serde_json::to_value(TaskArtifactUpdateEvent {
                        task_id: task_id.clone(),
                        context_id: context_id.clone(),
                        artifact: artifact.clone(),
                        last_chunk: Some(true),
                    }).unwrap_or_default();
                    if is_v03 { to_v03(&mut art_evt); }
                    let sse_resp = serde_json::json!({
                        "jsonrpc": JSONRPC_VERSION,
                        "id": id,
                        "result": art_evt,
                    });
                    yield Ok(Event::default().data(sse_resp.to_string()));
                }
            }

            // Event 4: Status update to completed
            let mut status_evt = serde_json::to_value(TaskStatusUpdateEvent {
                task_id: task_id.clone(),
                context_id: context_id.clone(),
                status: completed.status,
            }).unwrap_or_default();
            if is_v03 { to_v03(&mut status_evt); }
            let sse_resp = serde_json::json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": id,
                "result": status_evt,
            });
            yield Ok(Event::default().data(sse_resp.to_string()));
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Subscribe to an existing task's updates via SSE.
async fn handle_subscribe_task(
    state: ApiState,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
    is_v03: bool,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use axum::response::sse::{Event, KeepAlive, Sse};

    let params = match params {
        Some(p) => p,
        None => {
            return error_response(id.clone(), ERROR_INVALID_PARAMS, "Missing params")
                .into_response();
        }
    };

    let req: SubscribeTaskRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            return error_response(
                id.clone(),
                ERROR_INVALID_PARAMS,
                &format!("Invalid params: {e}"),
            )
            .into_response();
        }
    };

    let task = match state.a2a.task_store.get(&req.id) {
        Some(t) => t,
        None => {
            return error_response(id.clone(), ERROR_TASK_NOT_FOUND, "Task not found")
                .into_response();
        }
    };

    if is_terminal(&task.status.state) {
        return error_response(
            id.clone(),
            ERROR_INVALID_REQUEST,
            "Task is in a terminal state",
        )
        .into_response();
    }

    // Return current task state as a single SSE event
    let stream = async_stream::stream! {
        let mut task_val = serde_json::to_value(&task).unwrap_or_default();
        if is_v03 { to_v03(&mut task_val); }
        let sse_resp = serde_json::json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": id,
            "result": task_val,
        });
        yield Ok::<_, std::convert::Infallible>(
            Event::default().data(sse_resp.to_string())
        );
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn error_response(
    id: serde_json::Value,
    code: i32,
    message: &str,
) -> (StatusCode, Json<JsonRpcResponse>) {
    (
        StatusCode::OK,
        Json(JsonRpcResponse {
            jsonrpc: JSONRPC_VERSION.into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
            }),
        }),
    )
}

fn success_response(
    id: serde_json::Value,
    result: serde_json::Value,
) -> (StatusCode, Json<JsonRpcResponse>) {
    (
        StatusCode::OK,
        Json(JsonRpcResponse {
            jsonrpc: JSONRPC_VERSION.into(),
            id,
            result: Some(result),
            error: None,
        }),
    )
}

fn success_response_v03(
    id: serde_json::Value,
    mut result: serde_json::Value,
    is_v03: bool,
) -> (StatusCode, Json<JsonRpcResponse>) {
    if is_v03 {
        to_v03(&mut result);
    }
    success_response(id, result)
}
