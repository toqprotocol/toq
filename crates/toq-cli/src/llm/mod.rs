//! LLM handler: call OpenAI, Anthropic, or Bedrock and reply through the daemon.

pub mod anthropic;
pub mod bedrock;
pub mod handler;
pub mod openai;
pub mod redact;

use serde::{Deserialize, Serialize};

/// A message in the conversation context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String, // "user" or "assistant"
    pub content: String,
}

/// Result from an LLM provider call.
pub struct LlmResponse {
    pub text: String,
    pub close_thread: bool,
}

/// The close_thread tool definition (provider-agnostic).
pub const CLOSE_THREAD_TOOL_NAME: &str = "close_thread";
pub const CLOSE_THREAD_TOOL_DESC: &str = "End the conversation when it is naturally complete";

/// Default system prompt when none is provided.
pub const DEFAULT_SYSTEM_PROMPT: &str =
    "You are an AI agent communicating via the toq protocol. Respond helpfully and concisely.";

/// Default max turns when neither --max-turns nor --auto-close is specified.
pub const DEFAULT_MAX_TURNS: usize = 10;

/// Call the appropriate provider based on handler config.
pub async fn call(
    provider: &str,
    model: &str,
    system_prompt: &str,
    messages: &[ChatMessage],
    include_close_tool: bool,
) -> Result<LlmResponse, String> {
    match provider {
        "openai" => openai::call(model, system_prompt, messages, include_close_tool).await,
        "anthropic" => anthropic::call(model, system_prompt, messages, include_close_tool).await,
        "bedrock" => bedrock::call(model, system_prompt, messages, include_close_tool).await,
        _ => Err(format!("unknown provider: {provider}")),
    }
}
