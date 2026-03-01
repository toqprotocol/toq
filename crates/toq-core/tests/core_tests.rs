use toq_core::constants::*;
use toq_core::crypto::{Keypair, PublicKey};
use toq_core::envelope::Envelope;
use toq_core::error::Error;
use toq_core::types::{Address, MessageType, Priority};

use serde_json::json;
use uuid::Uuid;

// --- Address ---

#[test]
fn address_parse_default_port() {
    let addr: Address = "toq://example.com/assistant".parse().unwrap();
    assert_eq!(addr.host, "example.com");
    assert_eq!(addr.port, DEFAULT_PORT);
    assert_eq!(addr.agent_name, "assistant");
}

#[test]
fn address_parse_custom_port() {
    let addr: Address = "toq://example.com:7070/agent".parse().unwrap();
    assert_eq!(addr.host, "example.com");
    assert_eq!(addr.port, 7070);
    assert_eq!(addr.agent_name, "agent");
}

#[test]
fn address_parse_ip() {
    let addr: Address = "toq://192.168.1.50/dev-agent".parse().unwrap();
    assert_eq!(addr.host, "192.168.1.50");
    assert_eq!(addr.agent_name, "dev-agent");
}

#[test]
fn address_roundtrip() {
    let original = "toq://example.com/assistant";
    let addr: Address = original.parse().unwrap();
    assert_eq!(addr.to_string(), original);
}

#[test]
fn address_roundtrip_custom_port() {
    let original = "toq://example.com:7070/agent";
    let addr: Address = original.parse().unwrap();
    assert_eq!(addr.to_string(), original);
}

#[test]
fn address_serde_roundtrip() {
    let addr = Address::new("example.com", "assistant").unwrap();
    let json = serde_json::to_string(&addr).unwrap();
    assert_eq!(json, "\"toq://example.com/assistant\"");
    let parsed: Address = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, addr);
}

#[test]
fn address_reject_missing_scheme() {
    assert!("example.com/agent".parse::<Address>().is_err());
}

#[test]
fn address_reject_missing_agent_name() {
    assert!("toq://example.com".parse::<Address>().is_err());
}

#[test]
fn address_reject_empty_host() {
    assert!("toq:///agent".parse::<Address>().is_err());
}

#[test]
fn address_reject_uppercase() {
    assert!("toq://example.com/Agent".parse::<Address>().is_err());
}

#[test]
fn address_reject_leading_hyphen() {
    assert!("toq://example.com/-agent".parse::<Address>().is_err());
}

#[test]
fn address_reject_trailing_hyphen() {
    assert!("toq://example.com/agent-".parse::<Address>().is_err());
}

#[test]
fn address_reject_empty_name() {
    assert!(Address::new("example.com", "").is_err());
}

// --- MessageType ---

#[test]
fn message_type_serde() {
    let cases = vec![
        (MessageType::HandshakeInit, "\"handshake.init\""),
        (MessageType::MessageSend, "\"message.send\""),
        (MessageType::Heartbeat, "\"system.heartbeat\""),
        (MessageType::StreamChunk, "\"message.stream.chunk\""),
        (MessageType::CardExchange, "\"card.exchange\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(json, expected);
        let parsed: MessageType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, variant);
    }
}

// --- Priority ---

#[test]
fn priority_serde() {
    assert_eq!(
        serde_json::to_string(&Priority::Normal).unwrap(),
        "\"normal\""
    );
    assert_eq!(
        serde_json::to_string(&Priority::Urgent).unwrap(),
        "\"urgent\""
    );
}

// --- Crypto ---

#[test]
fn keypair_sign_verify() {
    let kp = Keypair::generate();
    let data = b"hello toq";
    let sig = kp.sign(data);
    assert!(sig.starts_with(ED25519_PREFIX));
    kp.public_key().verify(data, &sig).unwrap();
}

#[test]
fn verify_wrong_data_fails() {
    let kp = Keypair::generate();
    let sig = kp.sign(b"correct data");
    let result = kp.public_key().verify(b"wrong data", &sig);
    assert!(matches!(result, Err(Error::InvalidSignature)));
}

#[test]
fn verify_wrong_key_fails() {
    let kp1 = Keypair::generate();
    let kp2 = Keypair::generate();
    let sig = kp1.sign(b"data");
    let result = kp2.public_key().verify(b"data", &sig);
    assert!(matches!(result, Err(Error::InvalidSignature)));
}

#[test]
fn public_key_encode_decode_roundtrip() {
    let kp = Keypair::generate();
    let encoded = kp.public_key().to_encoded();
    assert!(encoded.starts_with(ED25519_PREFIX));
    let decoded = PublicKey::from_encoded(&encoded).unwrap();
    assert_eq!(decoded, kp.public_key());
}

#[test]
fn public_key_display() {
    let kp = Keypair::generate();
    let display = format!("{}", kp.public_key());
    assert_eq!(display, kp.public_key().to_encoded());
}

// --- Envelope ---

fn test_envelope(_keypair: &Keypair) -> Envelope {
    let from = Address::new("alice.dev", "assistant").unwrap();
    let to = Address::new("bob.dev", "agent").unwrap();
    Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::MessageSend,
        from,
        to: vec![to],
        thread_id: None,
        reply_to: None,
        sequence: 0,
        timestamp: "2026-02-28T12:00:00Z".into(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: Some(json!({"task": "test"})),
    }
}

#[test]
fn envelope_sign_verify() {
    let kp = Keypair::generate();
    let mut env = test_envelope(&kp);
    env.sign(&kp).unwrap();
    assert!(!env.signature.is_empty());
    env.verify(&kp.public_key()).unwrap();
}

#[test]
fn envelope_verify_wrong_key_fails() {
    let kp1 = Keypair::generate();
    let kp2 = Keypair::generate();
    let mut env = test_envelope(&kp1);
    env.sign(&kp1).unwrap();
    assert!(env.verify(&kp2.public_key()).is_err());
}

#[test]
fn envelope_tampered_body_fails() {
    let kp = Keypair::generate();
    let mut env = test_envelope(&kp);
    env.sign(&kp).unwrap();
    env.body = Some(json!({"task": "tampered"}));
    assert!(env.verify(&kp.public_key()).is_err());
}

#[test]
fn envelope_validate_ok() {
    let kp = Keypair::generate();
    let env = test_envelope(&kp);
    env.validate().unwrap();
}

#[test]
fn envelope_validate_bad_version() {
    let kp = Keypair::generate();
    let mut env = test_envelope(&kp);
    env.version = "9.9".into();
    assert!(env.validate().is_err());
}

#[test]
fn envelope_validate_empty_recipients() {
    let kp = Keypair::generate();
    let mut env = test_envelope(&kp);
    env.to = vec![];
    assert!(env.validate().is_err());
}

#[test]
fn envelope_validate_blocked_content_type() {
    let kp = Keypair::generate();
    let mut env = test_envelope(&kp);
    env.content_type = Some("application/x-executable".into());
    assert!(matches!(env.validate(), Err(Error::BlockedContentType(_))));
}

#[test]
fn envelope_canonical_bytes_deterministic() {
    let kp = Keypair::generate();
    let env = test_envelope(&kp);
    let bytes1 = env.canonical_bytes().unwrap();
    let bytes2 = env.canonical_bytes().unwrap();
    assert_eq!(bytes1, bytes2);
}

// --- Handshake ---

#[tokio::test]
async fn handshake_initiate_accept() {
    use toq_core::handshake;

    let (client_stream, server_stream) = tokio::io::duplex(8192);
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut server_read, mut server_write) = tokio::io::split(server_stream);

    let client_kp = Keypair::generate();
    let server_kp = Keypair::generate();
    let client_addr = Address::new("alice.dev", "assistant").unwrap();
    let server_addr = Address::new("bob.dev", "agent").unwrap();

    let client_pub = client_kp.public_key();
    let server_pub = server_kp.public_key();

    let (client_result, server_result) = tokio::join!(
        async {
            let mut stream = tokio::io::join(&mut client_read, &mut client_write);
            handshake::initiate(&mut stream, &client_kp, &client_addr).await
        },
        async {
            let mut stream = tokio::io::join(&mut server_read, &mut server_write);
            handshake::accept(&mut stream, &server_kp, &server_addr).await
        }
    );

    let client_result = client_result.unwrap();
    let server_result = server_result.unwrap();

    // Client sees server's identity
    assert_eq!(client_result.peer_public_key, server_pub);
    assert_eq!(client_result.peer_address, server_addr);
    assert!(client_result.session_id.starts_with("sess-"));

    // Server sees client's identity
    assert_eq!(server_result.peer_public_key, client_pub);
    assert_eq!(server_result.peer_address, client_addr);

    // Same session ID
    assert_eq!(client_result.session_id, server_result.session_id);
}

// --- Transport ---

#[test]
fn generate_self_signed_cert() {
    let (certs, key) = toq_core::transport::generate_self_signed_cert().unwrap();
    assert_eq!(certs.len(), 1);
    assert!(!key.secret_der().is_empty());
}

#[test]
fn server_config_from_self_signed() {
    let (certs, key) = toq_core::transport::generate_self_signed_cert().unwrap();
    let config = toq_core::transport::server_config(certs, key);
    assert!(config.is_ok());
}
