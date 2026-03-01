use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::crypto::{Keypair, PublicKey};
use crate::error::Error;
use crate::types::{Address, MessageType, Priority};

pub const DEFAULT_MAX_SIZE: usize = 1_048_576; // 1 MB

const BLOCKED_CONTENT_TYPES: &[&str] = &[
    "application/x-executable",
    "application/x-msdos-program",
    "application/x-msdownload",
    "application/x-sharedlib",
    "application/vnd.microsoft.portable-executable",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub version: String,
    pub id: Uuid,
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub from: Address,
    pub to: Vec<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    pub sequence: u64,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<String>,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e2e_nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

impl Envelope {
    /// Compute canonical JSON bytes for signing (envelope without signature field, sorted keys, no whitespace).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("signature");
        }
        Ok(canonical_json(&value).into_bytes())
    }

    /// Sign this envelope, setting the signature field.
    pub fn sign(&mut self, keypair: &Keypair) -> Result<(), Error> {
        self.signature = String::new();
        let bytes = self.canonical_bytes()?;
        self.signature = keypair.sign(&bytes);
        Ok(())
    }

    /// Verify the signature against the given public key.
    pub fn verify(&self, public_key: &PublicKey) -> Result<(), Error> {
        let bytes = self.canonical_bytes()?;
        public_key.verify(&bytes, &self.signature)
    }

    /// Validate envelope fields per spec Section 4.3.
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != "0.1" {
            return Err(Error::InvalidEnvelope("unsupported version".into()));
        }
        if self.to.is_empty() {
            return Err(Error::InvalidEnvelope(
                "to must have at least one recipient".into(),
            ));
        }
        if self.to.len() > 100 {
            return Err(Error::InvalidEnvelope(
                "to must have at most 100 recipients".into(),
            ));
        }
        if let Some(ref ct) = self.content_type {
            check_content_type(ct)?;
        }
        let size = serde_json::to_vec(self)?.len();
        if size > DEFAULT_MAX_SIZE {
            return Err(Error::MessageTooLarge {
                size,
                max: DEFAULT_MAX_SIZE,
            });
        }
        Ok(())
    }
}

fn check_content_type(ct: &str) -> Result<(), Error> {
    let lower = ct.to_ascii_lowercase();
    for blocked in BLOCKED_CONTENT_TYPES {
        if lower.starts_with(blocked) {
            return Err(Error::BlockedContentType(ct.to_string()));
        }
    }
    Ok(())
}

/// Recursively serialize a JSON Value with sorted keys and no whitespace.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", canonical_json_string(k), canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        other => serde_json::to_string(other).unwrap(),
    }
}

/// JSON-encode a string value.
fn canonical_json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}
