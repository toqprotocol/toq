//! Ollama provider. Local LLM, no API key needed.

use super::{CLOSE_THREAD_TOOL_DESC, CLOSE_THREAD_TOOL_NAME, ChatMessage, LlmResponse};
use serde_json::json;

const ENV_HOST: &str = "OLLAMA_HOST";

pub async fn call(
    model: &str,
    system_prompt: &str,
    messages: &[ChatMessage],
    include_close_tool: bool,
) -> Result<LlmResponse, String> {
    let base = std::env::var(ENV_HOST).unwrap_or_else(|_| "http://localhost:11434".into());
    let url = format!("{}/v1/chat/completions", base.trim_end_matches('/'));

    let mut msgs = vec![json!({"role": "system", "content": system_prompt})];
    for m in messages {
        msgs.push(json!({"role": m.role, "content": m.content}));
    }

    let mut body = json!({
        "model": model,
        "messages": msgs,
    });

    if include_close_tool {
        body["tools"] = json!([{
            "type": "function",
            "function": {
                "name": CLOSE_THREAD_TOOL_NAME,
                "description": CLOSE_THREAD_TOOL_DESC,
                "parameters": {"type": "object", "properties": {}, "required": []}
            }
        }]);
    }

    let resp = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Ollama request failed: {e}"))?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Ollama response parse failed: {e}"))?;

    if !status.is_success() {
        let msg = resp_body["error"]["message"]
            .as_str()
            .unwrap_or("unknown error");
        return Err(format!("Ollama error: {msg}"));
    }

    let choice = &resp_body["choices"][0];
    let message = &choice["message"];

    let mut close_thread = false;
    if let Some(tool_calls) = message["tool_calls"].as_array() {
        for tc in tool_calls {
            if tc["function"]["name"].as_str() == Some(CLOSE_THREAD_TOOL_NAME) {
                close_thread = true;
            }
        }
    }

    let text = message["content"].as_str().unwrap_or("").to_string();

    Ok(LlmResponse { text, close_thread })
}
