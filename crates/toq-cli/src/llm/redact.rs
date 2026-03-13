//! Output redaction: scan LLM responses for credential patterns before sending.

use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"sk-[a-zA-Z0-9]{20,}",             // OpenAI keys
        r"sk-ant-[a-zA-Z0-9\-]{20,}",       // Anthropic keys
        r"AKIA[A-Z0-9]{16}",                // AWS access key IDs
        r"aws_secret_access_key\s*=\s*\S+", // AWS secret in config format
        r"Bearer\s+[a-zA-Z0-9\-_.]{20,}",   // Bearer tokens
    ]
    .iter()
    .filter_map(|p| Regex::new(p).ok())
    .collect()
});

/// Redact credential patterns from text. Returns (redacted_text, was_redacted).
pub fn redact(text: &str) -> (String, bool) {
    let mut result = text.to_string();
    let mut redacted = false;
    for pat in PATTERNS.iter() {
        if pat.is_match(&result) {
            result = pat.replace_all(&result, "[REDACTED]").to_string();
            redacted = true;
        }
    }
    (result, redacted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_openai_key() {
        let (out, hit) = redact("my key is sk-abc123def456ghi789jkl012mno345");
        assert!(hit);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("sk-abc"));
    }

    #[test]
    fn redacts_aws_access_key() {
        let (out, hit) = redact("access key: AKIAIOSFODNN7EXAMPLE");
        assert!(hit);
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_bearer_token() {
        let (out, hit) = redact("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc");
        assert!(hit);
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn leaves_normal_text_alone() {
        let (out, hit) = redact("Hello, how can I help you today?");
        assert!(!hit);
        assert_eq!(out, "Hello, how can I help you today?");
    }
}
