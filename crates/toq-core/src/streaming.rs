use serde_json::Value;
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::constants::PROTOCOL_VERSION;
use crate::crypto::Keypair;
use crate::envelope::Envelope;
use crate::error::Error;
use crate::framing;
use crate::types::{Address, MessageType};

/// Parameters for sending a stream chunk.
pub struct ChunkParams<'a> {
    pub from: &'a Address,
    pub to: &'a Address,
    pub stream_id: &'a str,
    pub data: Value,
    pub sequence: u64,
    pub thread_id: Option<String>,
    pub content_type: Option<String>,
}

/// Send a stream chunk.
pub async fn send_chunk<S>(
    stream: &mut S,
    keypair: &Keypair,
    params: ChunkParams<'_>,
) -> Result<Uuid, Error>
where
    S: AsyncWriteExt + Unpin,
{
    let id = Uuid::new_v4();
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id,
        msg_type: MessageType::StreamChunk,
        from: params.from.clone(),
        to: vec![params.to.clone()],
        thread_id: params.thread_id,
        reply_to: None,
        sequence: params.sequence,
        timestamp: now_utc(),
        priority: None,
        content_type: params.content_type,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: Some(serde_json::json!({
            "stream_id": params.stream_id,
            "data": params.data,
        })),
    };
    framing::send_envelope(stream, &mut envelope, keypair).await?;
    Ok(id)
}

/// Send a stream end marker.
pub async fn send_end<S>(
    stream: &mut S,
    keypair: &Keypair,
    from: &Address,
    to: &Address,
    stream_id: &str,
    data: Option<Value>,
    sequence: u64,
    thread_id: Option<String>,
) -> Result<Uuid, Error>
where
    S: AsyncWriteExt + Unpin,
{
    let id = Uuid::new_v4();
    let mut body = serde_json::json!({ "stream_id": stream_id });
    if let Some(d) = data {
        body["data"] = d;
    }
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION.into(),
        id,
        msg_type: MessageType::StreamEnd,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id,
        reply_to: None,
        sequence,
        timestamp: now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: Some(body),
    };
    framing::send_envelope(stream, &mut envelope, keypair).await?;
    Ok(id)
}

/// Buffers incoming stream chunks and assembles complete streams.
pub struct StreamBuffer {
    streams: HashMap<String, Vec<(u64, Value)>>,
}

impl StreamBuffer {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// Buffer a chunk. Returns the stream_id.
    pub fn add_chunk(&mut self, stream_id: &str, sequence: u64, data: Value) {
        self.streams
            .entry(stream_id.to_string())
            .or_default()
            .push((sequence, data));
    }

    /// Complete a stream: sort chunks by sequence and return assembled data.
    /// Removes the stream from the buffer.
    pub fn complete(&mut self, stream_id: &str, final_data: Option<Value>) -> Option<Vec<Value>> {
        let mut chunks = self.streams.remove(stream_id)?;
        chunks.sort_by_key(|(seq, _)| *seq);
        let mut result: Vec<Value> = chunks.into_iter().map(|(_, data)| data).collect();
        if let Some(d) = final_data {
            result.push(d);
        }
        Some(result)
    }

    /// Cancel and discard a stream.
    pub fn cancel(&mut self, stream_id: &str) {
        self.streams.remove(stream_id);
    }

    /// Check if a stream is active.
    pub fn has_stream(&self, stream_id: &str) -> bool {
        self.streams.contains_key(stream_id)
    }
}

impl Default for StreamBuffer {
    fn default() -> Self {
        Self::new()
    }
}

fn now_utc() -> String {
    "2026-01-01T00:00:00Z".to_string()
}
