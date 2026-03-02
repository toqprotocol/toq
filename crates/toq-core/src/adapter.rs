use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use crate::constants::HEALTH_CHECK_TIMEOUT;

/// Adapter types for local agent communication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterType {
    Http,
    Stdin,
    Sdk,
    Unix,
    Grpc,
}

/// Message delivered to the local agent.
/// Protocol-internal fields (sequence, signature, version) are stripped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    pub id: String,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

/// Response from the local agent back to the toq process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

impl AgentMessage {
    /// Convert an Envelope into an AgentMessage by stripping protocol fields.
    pub fn from_envelope(envelope: &crate::envelope::Envelope) -> Self {
        Self {
            id: envelope.id.to_string(),
            msg_type: serde_json::to_value(&envelope.msg_type)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            from: envelope.from.to_string(),
            thread_id: envelope.thread_id.clone(),
            reply_to: envelope.reply_to.clone(),
            content_type: envelope.content_type.clone(),
            body: envelope.body.clone(),
        }
    }
}

/// HTTP adapter: delivers messages via POST to a localhost callback URL.
pub struct HttpAdapter {
    callback_url: String,
    client: reqwest::Client,
}

impl HttpAdapter {
    pub fn new(callback_url: &str) -> Self {
        Self {
            callback_url: callback_url.to_string(),
            client: reqwest::Client::builder()
                .timeout(HEALTH_CHECK_TIMEOUT)
                .build()
                .unwrap_or_default(),
        }
    }

    pub async fn deliver(
        &self,
        message: &AgentMessage,
    ) -> Result<Option<AgentResponse>, crate::error::Error> {
        let resp = self
            .client
            .post(&self.callback_url)
            .json(message)
            .send()
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;

        if resp.status().is_success() {
            let body = resp
                .text()
                .await
                .map_err(|e| crate::error::Error::Io(e.to_string()))?;
            if body.trim().is_empty() {
                return Ok(None);
            }
            let response: AgentResponse =
                serde_json::from_str(&body).map_err(|e| crate::error::Error::Io(e.to_string()))?;
            Ok(Some(response))
        } else {
            Err(crate::error::Error::Io(format!(
                "agent returned status {}",
                resp.status()
            )))
        }
    }

    pub async fn health_check(&self) -> Result<(), crate::error::Error> {
        self.client
            .get(&self.callback_url)
            .timeout(HEALTH_CHECK_TIMEOUT)
            .send()
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        Ok(())
    }
}

/// Stdin adapter: communicates with a child process via JSON lines on stdin/stdout.
pub struct StdinAdapter {
    child: Child,
}

impl StdinAdapter {
    pub fn spawn(command: &str) -> Result<Self, crate::error::Error> {
        let child = Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        Ok(Self { child })
    }

    pub async fn deliver(
        &mut self,
        message: &AgentMessage,
    ) -> Result<Option<AgentResponse>, crate::error::Error> {
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| crate::error::Error::Io("stdin not available".into()))?;
        let stdout = self
            .child
            .stdout
            .as_mut()
            .ok_or_else(|| crate::error::Error::Io("stdout not available".into()))?;

        let mut line =
            serde_json::to_string(message).map_err(|e| crate::error::Error::Io(e.to_string()))?;
        line.push('\n');
        stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        stdin
            .flush()
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;

        let mut reader = BufReader::new(stdout);
        let mut response_line = String::new();

        match tokio::time::timeout(
            Duration::from_secs(30),
            reader.read_line(&mut response_line),
        )
        .await
        {
            Ok(Ok(0)) => Ok(None),
            Ok(Ok(_)) => {
                let trimmed = response_line.trim();
                if trimmed.is_empty() {
                    return Ok(None);
                }
                let response: AgentResponse = serde_json::from_str(trimmed)
                    .map_err(|e| crate::error::Error::Io(e.to_string()))?;
                Ok(Some(response))
            }
            Ok(Err(e)) => Err(crate::error::Error::Io(e.to_string())),
            Err(_) => Err(crate::error::Error::Io("agent response timeout".into())),
        }
    }

    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}
