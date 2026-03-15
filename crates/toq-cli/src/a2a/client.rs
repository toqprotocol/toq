//! Outbound A2A client: agent card discovery and message sending.

use super::types::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
const A2A_SEND_TIMEOUT_SECS: u64 = 30;

/// Check if a URL targets a cloud metadata or link-local address.
/// Only the local API (localhost) can trigger outbound requests, so
/// private networks are allowed (the user may have internal A2A agents).
/// Cloud metadata endpoints are blocked to prevent credential leaks.
fn is_blocked_url(url: &str) -> bool {
    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    if let Ok(std::net::IpAddr::V4(v4)) = host.parse::<std::net::IpAddr>() {
        return v4.is_link_local();
    }
    host == "metadata.google.internal" || host == "metadata.goog"
}

/// Outbound A2A client with agent card caching.
#[derive(Clone)]
pub struct A2aClient {
    http: reqwest::Client,
    card_cache: Arc<Mutex<HashMap<String, AgentCard>>>,
}

impl A2aClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(A2A_SEND_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");
        Self {
            http,
            card_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Probe a URL for an A2A agent card. Returns the card if found,
    /// None if the endpoint doesn't have one (not an A2A agent).
    pub async fn probe(&self, base_url: &str) -> Result<Option<AgentCard>, String> {
        if is_blocked_url(base_url) {
            return Err("URL targets a blocked address".into());
        }
        if let Some(card) = self
            .card_cache
            .lock()
            .ok()
            .and_then(|c| c.get(base_url).cloned())
        {
            return Ok(Some(card));
        }

        let url = format!("{}{}", base_url.trim_end_matches('/'), AGENT_CARD_PATH);
        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return Err(format!("Cannot reach {url}: {e}")),
        };

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None); // Not an A2A agent
        }
        if !resp.status().is_success() {
            return Err(format!("HTTP {} from {url}", resp.status()));
        }

        let card: AgentCard = resp
            .json()
            .await
            .map_err(|e| format!("Invalid agent card from {url}: {e}"))?;

        if let Ok(mut cache) = self.card_cache.lock() {
            cache.insert(base_url.to_string(), card.clone());
        }
        Ok(Some(card))
    }

    /// Resolve the JSON-RPC endpoint URL from an agent card.
    fn resolve_endpoint(card: &AgentCard) -> Option<String> {
        // Prefer the v0.3 top-level url field
        if !card.url.is_empty() {
            return Some(card.url.clone());
        }
        // Fall back to supportedInterfaces (v1.0)
        card.supported_interfaces
            .iter()
            .find(|i| i.protocol_binding == "JSONRPC")
            .map(|i| i.url.clone())
    }

    /// Send a text message to a remote A2A agent. Probes for the agent card
    /// first to verify it's an A2A agent and discover the endpoint.
    pub async fn send_text(
        &self,
        base_url: &str,
        text: &str,
        auth_token: Option<&str>,
    ) -> Result<SendResult, String> {
        let card = self
            .probe(base_url)
            .await?
            .ok_or_else(|| format!("No A2A agent found at {base_url} (no agent card)"))?;

        let endpoint = Self::resolve_endpoint(&card)
            .ok_or_else(|| "No JSON-RPC endpoint in agent card".to_string())?;

        if is_blocked_url(&endpoint) {
            return Err("Agent card endpoint targets a blocked address".into());
        }

        let msg = Message {
            message_id: uuid::Uuid::new_v4().to_string(),
            context_id: None,
            task_id: None,
            role: Role::User,
            parts: vec![Part::text(text)],
        };

        let rpc_req = JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.into(),
            id: serde_json::json!(1),
            method: METHOD_SEND_MESSAGE_V03.into(),
            params: Some(
                serde_json::to_value(SendMessageRequest { message: msg })
                    .map_err(|e| format!("Failed to serialize request: {e}"))?,
            ),
        };

        let mut req = self.http.post(&endpoint).json(&rpc_req);
        if let Some(token) = auth_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("Failed to send to {endpoint}: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("HTTP {} from {endpoint}", resp.status()));
        }

        let rpc_resp: JsonRpcResponse = resp
            .json()
            .await
            .map_err(|e| format!("Invalid JSON-RPC response: {e}"))?;

        if let Some(err) = rpc_resp.error {
            return Err(format!("A2A error {}: {}", err.code, err.message));
        }

        let result = rpc_resp
            .result
            .ok_or_else(|| "Missing result in response".to_string())?;

        // Extract reply text from task artifacts or message parts
        let reply_text = extract_reply_text(&result);
        let task_id = result
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let state = result
            .pointer("/status/state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(SendResult {
            task_id,
            state,
            reply_text,
        })
    }
}

pub struct SendResult {
    pub task_id: String,
    pub state: String,
    pub reply_text: Option<String>,
}

/// Extract reply text from a Task (artifacts) or Message (parts) response.
fn extract_reply_text(result: &serde_json::Value) -> Option<String> {
    // Try task artifacts first
    if let Some(artifacts) = result.get("artifacts").and_then(|a| a.as_array()) {
        for artifact in artifacts {
            if let Some(parts) = artifact.get("parts").and_then(|p| p.as_array()) {
                for part in parts {
                    if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                        return Some(text.to_string());
                    }
                }
            }
        }
    }
    // Try message parts (direct message response)
    if let Some(parts) = result.get("parts").and_then(|p| p.as_array()) {
        for part in parts {
            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                return Some(text.to_string());
            }
        }
    }
    None
}
