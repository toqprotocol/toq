//! AWS Bedrock provider. Reads AWS credentials from environment or ~/.aws/credentials.

use super::{CLOSE_THREAD_TOOL_DESC, CLOSE_THREAD_TOOL_NAME, ChatMessage, LlmResponse};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const SERVICE: &str = "bedrock";
const ENV_ACCESS_KEY: &str = "AWS_ACCESS_KEY_ID";
const ENV_SECRET_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const ENV_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";
const ENV_REGION: &str = "AWS_REGION";
const DEFAULT_REGION: &str = "us-east-1";

struct AwsCreds {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
    region: String,
}

fn load_creds() -> Result<AwsCreds, String> {
    let access_key =
        std::env::var(ENV_ACCESS_KEY).map_err(|_| format!("{ENV_ACCESS_KEY} not set"))?;
    let secret_key =
        std::env::var(ENV_SECRET_KEY).map_err(|_| format!("{ENV_SECRET_KEY} not set"))?;
    let session_token = std::env::var(ENV_SESSION_TOKEN).ok();
    let region = std::env::var(ENV_REGION).unwrap_or_else(|_| DEFAULT_REGION.into());
    Ok(AwsCreds {
        access_key,
        secret_key,
        session_token,
        region,
    })
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn sign_v4(
    creds: &AwsCreds,
    method: &str,
    url: &str,
    body: &[u8],
) -> Result<Vec<(String, String)>, String> {
    let parsed: url::Url = url.parse().map_err(|e| format!("bad url: {e}"))?;
    let host = parsed.host_str().ok_or("no host")?;
    let path = parsed.path();

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let payload_hash = sha256_hex(body);

    let mut signed_headers = "content-type;host;x-amz-date".to_string();
    let mut canonical_headers =
        format!("content-type:application/json\nhost:{host}\nx-amz-date:{amz_date}\n");
    if creds.session_token.is_some() {
        signed_headers = "content-type;host;x-amz-date;x-amz-security-token".to_string();
        canonical_headers = format!(
            "content-type:application/json\nhost:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{}\n",
            creds.session_token.as_deref().unwrap_or("")
        );
    }

    let canonical_request =
        format!("{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let scope = format!("{date_stamp}/{}/{SERVICE}/aws4_request", creds.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac_sha256(
        format!("AWS4{}", creds.secret_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, creds.region.as_bytes());
    let k_service = hmac_sha256(&k_region, SERVICE.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key
    );

    let mut headers = vec![
        ("Authorization".into(), auth),
        ("x-amz-date".into(), amz_date),
        ("x-amz-content-sha256".into(), payload_hash),
        ("Content-Type".into(), "application/json".into()),
    ];
    if let Some(ref token) = creds.session_token {
        headers.push(("x-amz-security-token".into(), token.clone()));
    }

    Ok(headers)
}

pub async fn call(
    model: &str,
    system_prompt: &str,
    messages: &[ChatMessage],
    include_close_tool: bool,
) -> Result<LlmResponse, String> {
    let creds = load_creds()?;

    let msgs: Vec<serde_json::Value> = messages
        .iter()
        .map(|m| json!({"role": m.role, "content": [{"text": m.content}]}))
        .collect();

    let mut body = json!({
        "modelId": model,
        "system": [{"text": system_prompt}],
        "messages": msgs,
        "inferenceConfig": {"maxTokens": 4096},
    });

    if include_close_tool {
        body["toolConfig"] = json!({
            "tools": [{
                "toolSpec": {
                    "name": CLOSE_THREAD_TOOL_NAME,
                    "description": CLOSE_THREAD_TOOL_DESC,
                    "inputSchema": {"json": {"type": "object", "properties": {}, "required": []}}
                }
            }]
        });
    }

    let url = format!(
        "https://bedrock-runtime.{}.amazonaws.com/model/{}/converse",
        creds.region,
        urlencoding::encode(model)
    );

    let body_bytes = serde_json::to_vec(&body).map_err(|e| format!("json: {e}"))?;
    let headers = sign_v4(&creds, "POST", &url, &body_bytes)?;

    let client = reqwest::Client::new();
    let mut req = client.post(&url);
    for (k, v) in &headers {
        req = req.header(k, v);
    }
    let resp = req
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| format!("Bedrock request failed: {e}"))?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Bedrock response parse failed: {e}"))?;

    if !status.is_success() {
        let msg = resp_body["message"].as_str().unwrap_or("unknown error");
        return Err(format!("Bedrock API error: {msg}"));
    }

    let mut text = String::new();
    let mut close_thread = false;

    if let Some(content) = resp_body["output"]["message"]["content"].as_array() {
        for block in content {
            if let Some(t) = block["text"].as_str() {
                text.push_str(t);
            }
            if block.get("toolUse").is_some()
                && block["toolUse"]["name"].as_str() == Some(CLOSE_THREAD_TOOL_NAME)
            {
                close_thread = true;
            }
        }
    }

    Ok(LlmResponse { text, close_thread })
}
