//! OpenAI provider. Reads OPENAI_API_KEY from environment.

use super::{CLOSE_THREAD_TOOL_DESC, CLOSE_THREAD_TOOL_NAME, ChatMessage, LlmResponse};
use serde_json::json;

const API_URL: &str = "https://api.openai.com/v1/chat/completions";
const ENV_KEY: &str = "OPENAI_API_KEY";

pub async fn call(
    model: &str,
    system_prompt: &str,
    messages: &[ChatMessage],
    include_close_tool: bool,
) -> Result<LlmResponse, String> {
    let api_key = std::env::var(ENV_KEY).map_err(|_| format!("{ENV_KEY} not set"))?;

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
        .post(API_URL)
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("OpenAI request failed: {e}"))?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("OpenAI response parse failed: {e}"))?;

    if !status.is_success() {
        let msg = resp_body["error"]["message"]
            .as_str()
            .unwrap_or("unknown error");
        return Err(format!("OpenAI API error: {msg}"));
    }

    let choice = &resp_body["choices"][0];
    let message = &choice["message"];

    // Check for tool calls
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
