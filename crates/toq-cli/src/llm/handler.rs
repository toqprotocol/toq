//! LLM handler runtime: manages conversation state and dispatches to providers.

use crate::api::types::IncomingMessage;
use crate::llm::{self, ChatMessage, DEFAULT_MAX_TURNS, DEFAULT_SYSTEM_PROMPT};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use toq_core::config::HandlerEntry;

/// Per-thread state: conversation messages and turn count.
type ThreadState = HashMap<String, (Vec<ChatMessage>, usize)>;

/// Manages LLM handler state: per-thread conversation history and turn tracking.
pub struct LlmHandler {
    threads: Arc<Mutex<ThreadState>>,
    api_url: String,
}

impl LlmHandler {
    pub fn new(api_url: String) -> Self {
        Self {
            threads: Arc::new(Mutex::new(HashMap::new())),
            api_url,
        }
    }

    /// Clean up a closed thread.
    pub fn on_thread_close(&self, thread_id: &str) {
        let threads = self.threads.clone();
        let tid = thread_id.to_string();
        tokio::spawn(async move {
            threads.lock().await.remove(&tid);
        });
    }

    /// Dispatch an incoming message to an LLM provider and reply.
    pub fn dispatch(&self, handler: &HandlerEntry, msg: &IncomingMessage) {
        let thread_id = msg.thread_id.clone().unwrap_or_else(|| msg.id.clone());
        let from = msg.from.clone();

        let text = msg
            .body
            .as_ref()
            .and_then(|b| b.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();

        let prompt = if let Some(ref file) = handler.prompt_file {
            std::fs::read_to_string(file).unwrap_or_else(|_| DEFAULT_SYSTEM_PROMPT.to_string())
        } else {
            handler
                .prompt
                .clone()
                .unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_string())
        };

        let max_turns = handler.max_turns.unwrap_or(if handler.auto_close {
            usize::MAX
        } else {
            DEFAULT_MAX_TURNS
        });
        let auto_close = handler.auto_close;
        let provider = handler.provider.clone();
        let model = handler.model.clone();
        let api_url = self.api_url.clone();
        let handler_name = handler.name.clone();
        let threads = self.threads.clone();

        tokio::spawn(async move {
            // Build context
            let (history_snapshot, turn_count, is_last_turn) = {
                let mut guard = threads.lock().await;
                let (history, count) = guard
                    .entry(thread_id.clone())
                    .or_insert_with(|| (Vec::new(), 0));

                if *count == usize::MAX {
                    tracing::debug!("handler {handler_name}: thread {thread_id} already closed");
                    return;
                }

                history.push(ChatMessage {
                    role: "user".into(),
                    content: text,
                });
                *count += 1;
                let is_last = *count >= max_turns;
                (history.clone(), *count, is_last)
            };

            // Only offer close_thread tool after at least 2 turns of conversation
            let include_close_tool = auto_close && !is_last_turn && turn_count >= 2;

            // Append turn context to system prompt
            let full_prompt = if max_turns < usize::MAX {
                if is_last_turn {
                    format!(
                        "{prompt}\n\nThis is your final response in this conversation (turn {turn_count} of {max_turns}). Wrap up naturally."
                    )
                } else if auto_close {
                    format!(
                        "{prompt}\n\nYou are on turn {turn_count} of {max_turns} in this conversation. When the conversation has been fully explored, use the close_thread tool to end it. Do not close prematurely."
                    )
                } else {
                    format!(
                        "{prompt}\n\nYou are on turn {turn_count} of {max_turns} in this conversation."
                    )
                }
            } else if auto_close {
                format!(
                    "{prompt}\n\nWhen the conversation has been fully explored and both sides have shared their thoughts, use the close_thread tool to end it. Do not close prematurely."
                )
            } else {
                prompt.clone()
            };

            // Call LLM
            let result = llm::call(
                &provider,
                &model,
                &full_prompt,
                &history_snapshot,
                include_close_tool,
            )
            .await;

            match result {
                Ok(resp) => {
                    let (safe_text, was_redacted) = llm::redact::redact(&resp.text);
                    if was_redacted {
                        tracing::warn!(
                            "handler {handler_name}: redacted credential pattern from LLM response"
                        );
                    }

                    let close = resp.close_thread || is_last_turn;

                    // Update thread history
                    {
                        let mut guard = threads.lock().await;
                        if let Some((history, count)) = guard.get_mut(&thread_id) {
                            if !safe_text.is_empty() {
                                history.push(ChatMessage {
                                    role: "assistant".into(),
                                    content: safe_text.clone(),
                                });
                            }
                            if close {
                                *count = usize::MAX;
                            }
                        }
                    }

                    // Send reply
                    let mut body = serde_json::json!({
                        "to": from,
                        "body": {"text": safe_text},
                        "thread_id": thread_id,
                    });
                    if close {
                        body["close_thread"] = serde_json::json!(true);
                    }

                    let url = format!("{api_url}/v1/messages?wait=true");
                    match reqwest::Client::new().post(&url).json(&body).send().await {
                        Ok(r) if r.status().is_success() => {
                            tracing::info!(
                                "handler {handler_name}: replied to {from} (turn {turn_count}{})",
                                if close { ", closing" } else { "" }
                            );
                        }
                        Ok(r) => {
                            tracing::warn!(
                                "handler {handler_name}: reply failed: HTTP {}",
                                r.status()
                            );
                        }
                        Err(e) => {
                            tracing::warn!("handler {handler_name}: reply failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("handler {handler_name}: LLM call failed: {e}");
                }
            }
        });
    }
}
