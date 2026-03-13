//! Anthropic provider. Reads ANTHROPIC_API_KEY from environment.

use super::{CLOSE_THREAD_TOOL_DESC, CLOSE_THREAD_TOOL_NAME, ChatMessage, LlmResponse};
use serde_json::json;

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const ENV_KEY: &str = "ANTHROPIC_API_KEY";
const API_VERSION: &str = "2023-06-01";

pub async fn call(
    model: &str,
    system_prompt: &str,
    messages: &[ChatMessage],
    include_close_tool: bool,
) -> Result<LlmResponse, String> {
    let api_key = std::env::var(ENV_KEY).map_err(|_| format!("{ENV_KEY} not set"))?;

    let msgs: Vec<serde_json::Value> = messages
        .iter()
        .map(|m| json!({"role": m.role, "content": m.content}))
        .collect();

    let mut body = json!({
        "model": model,
        "max_tokens": 4096,
        "system": system_prompt,
        "messages": msgs,
    });

    if include_close_tool {
        body["tools"] = json!([{
            "name": CLOSE_THREAD_TOOL_NAME,
            "description": CLOSE_THREAD_TOOL_DESC,
            "input_schema": {"type": "object", "properties": {}, "required": []}
        }]);
    }

    let resp = reqwest::Client::new()
        .post(API_URL)
        .header("x-api-key", &api_key)
        .header("anthropic-version", API_VERSION)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Anthropic request failed: {e}"))?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Anthropic response parse failed: {e}"))?;

    if !status.is_success() {
        let msg = resp_body["error"]["message"]
            .as_str()
            .unwrap_or("unknown error");
        return Err(format!("Anthropic API error: {msg}"));
    }

    let mut text = String::new();
    let mut close_thread = false;

    if let Some(content) = resp_body["content"].as_array() {
        for block in content {
            match block["type"].as_str() {
                Some("text") => {
                    if let Some(t) = block["text"].as_str() {
                        text.push_str(t);
                    }
                }
                Some("tool_use") => {
                    if block["name"].as_str() == Some(CLOSE_THREAD_TOOL_NAME) {
                        close_thread = true;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(LlmResponse { text, close_thread })
}
