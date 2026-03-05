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
            handshake::accept(&mut stream, &server_kp, &server_addr, None).await
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

// --- Negotiation ---

#[tokio::test]
async fn negotiation_request_respond() {
    use toq_core::negotiation::{self, Features};

    let (client_stream, server_stream) = tokio::io::duplex(8192);
    let (mut cr, mut cw) = tokio::io::split(client_stream);
    let (mut sr, mut sw) = tokio::io::split(server_stream);

    let client_kp = Keypair::generate();
    let server_kp = Keypair::generate();
    let client_addr = Address::new("alice.dev", "assistant").unwrap();
    let server_addr = Address::new("bob.dev", "agent").unwrap();
    let client_pub = client_kp.public_key();
    let server_pub = server_kp.public_key();

    let features = Features::default();

    let (client_result, server_result) = tokio::join!(
        async {
            let mut stream = tokio::io::join(&mut cr, &mut cw);
            negotiation::request(
                &mut stream,
                &client_kp,
                &server_pub,
                &client_addr,
                &server_addr,
                &features,
            )
            .await
        },
        async {
            let mut stream = tokio::io::join(&mut sr, &mut sw);
            negotiation::respond(
                &mut stream,
                &server_kp,
                &client_pub,
                &server_addr,
                &client_addr,
                &features,
            )
            .await
        }
    );

    let client_result = client_result.unwrap();
    let server_result = server_result.unwrap();

    assert_eq!(client_result.version, PROTOCOL_VERSION);
    assert_eq!(server_result.version, PROTOCOL_VERSION);
    assert_eq!(client_result.streaming, server_result.streaming);
}

// --- Agent Card ---

#[tokio::test]
async fn card_exchange_roundtrip() {
    use toq_core::card::{self, AgentCard};

    let (client_stream, server_stream) = tokio::io::duplex(8192);
    let (mut cr, mut cw) = tokio::io::split(client_stream);
    let (mut sr, mut sw) = tokio::io::split(server_stream);

    let client_kp = Keypair::generate();
    let server_kp = Keypair::generate();
    let client_addr = Address::new("alice.dev", "assistant").unwrap();
    let server_addr = Address::new("bob.dev", "agent").unwrap();
    let client_pub = client_kp.public_key();
    let server_pub = server_kp.public_key();

    let client_card = AgentCard {
        name: "Alice".into(),
        description: None,
        public_key: client_kp.public_key().to_encoded(),
        protocol_version: PROTOCOL_VERSION.into(),
        capabilities: vec![],
        accept_files: false,
        max_file_size: None,
        max_message_size: None,
        connection_mode: None,
    };
    let server_card = AgentCard {
        name: "Bob".into(),
        description: None,
        public_key: server_kp.public_key().to_encoded(),
        protocol_version: PROTOCOL_VERSION.into(),
        capabilities: vec!["search".into()],
        accept_files: false,
        max_file_size: None,
        max_message_size: None,
        connection_mode: Some("approval".into()),
    };

    let (got_server_card, got_client_card) = tokio::join!(
        async {
            let mut stream = tokio::io::join(&mut cr, &mut cw);
            card::exchange(
                &mut stream,
                &client_kp,
                &server_pub,
                &client_addr,
                &server_addr,
                &client_card,
                1,
            )
            .await
        },
        async {
            let mut stream = tokio::io::join(&mut sr, &mut sw);
            card::exchange(
                &mut stream,
                &server_kp,
                &client_pub,
                &server_addr,
                &client_addr,
                &server_card,
                1,
            )
            .await
        }
    );

    let got_server_card = got_server_card.unwrap();
    let got_client_card = got_client_card.unwrap();

    assert_eq!(got_server_card.name, "Bob");
    assert_eq!(got_server_card.capabilities, vec!["search"]);
    assert_eq!(got_client_card.name, "Alice");
}

#[test]
fn card_validate_key_mismatch() {
    use toq_core::card::AgentCard;

    let kp1 = Keypair::generate();
    let kp2 = Keypair::generate();
    let card = AgentCard {
        name: "Test".into(),
        description: None,
        public_key: kp1.public_key().to_encoded(),
        protocol_version: PROTOCOL_VERSION.into(),
        capabilities: vec![],
        accept_files: false,
        max_file_size: None,
        max_message_size: None,
        connection_mode: None,
    };
    assert!(card.validate(&kp2.public_key()).is_err());
}

#[test]
fn card_validate_empty_name() {
    use toq_core::card::AgentCard;

    let kp = Keypair::generate();
    let card = AgentCard {
        name: "".into(),
        description: None,
        public_key: kp.public_key().to_encoded(),
        protocol_version: PROTOCOL_VERSION.into(),
        capabilities: vec![],
        accept_files: false,
        max_file_size: None,
        max_message_size: None,
        connection_mode: None,
    };
    assert!(card.validate(&kp.public_key()).is_err());
}

// --- Connection ---

#[test]
fn connection_state_values() {
    use toq_core::connection::ConnectionState;

    assert_ne!(ConnectionState::Active, ConnectionState::Closed);
    assert_eq!(ConnectionState::Active, ConnectionState::Active);
}

// --- Policy ---

#[test]
fn policy_open_accepts_all() {
    use toq_core::policy::*;

    let engine = PolicyEngine::new(ConnectionMode::Open);
    let kp = Keypair::generate();
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);
}

#[test]
fn policy_blocklist_overrides_open() {
    use toq_core::policy::*;

    let mut engine = PolicyEngine::new(ConnectionMode::Open);
    let kp = Keypair::generate();
    engine.block(&kp.public_key());
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Reject);
}

#[test]
fn policy_allowlist_accepts_known() {
    use toq_core::policy::*;

    let mut engine = PolicyEngine::new(ConnectionMode::Allowlist);
    let kp = Keypair::generate();
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Reject);
    engine.allow(&kp.public_key());
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);
}

#[test]
fn policy_approval_flow() {
    use toq_core::policy::*;

    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    let kp = Keypair::generate();

    // Unknown agent gets pending
    assert_eq!(
        engine.check(&kp.public_key()),
        PolicyDecision::PendingApproval
    );

    // After approval, accepted immediately
    engine.approve(&kp.public_key());
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);
}

#[test]
fn policy_approval_deny() {
    use toq_core::policy::*;

    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    let kp = Keypair::generate();
    engine.add_pending(&kp.public_key(), "toq://test/peer");
    assert_eq!(engine.pending_count(), 1);
    engine.deny(&kp.public_key());
    assert_eq!(engine.pending_count(), 0);
}

#[test]
fn policy_block_removes_from_allowlist() {
    use toq_core::policy::*;

    let mut engine = PolicyEngine::new(ConnectionMode::Allowlist);
    let kp = Keypair::generate();
    engine.allow(&kp.public_key());
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);
    engine.block(&kp.public_key());
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Reject);
}

#[test]
fn policy_unblock() {
    use toq_core::policy::*;

    let mut engine = PolicyEngine::new(ConnectionMode::Open);
    let kp = Keypair::generate();
    engine.block(&kp.public_key());
    assert!(engine.is_blocked(&kp.public_key()));
    engine.unblock(&kp.public_key());
    assert!(!engine.is_blocked(&kp.public_key()));
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);
}

// --- Replay ---

#[test]
fn sequence_tracker_accepts_increasing() {
    use toq_core::replay::SequenceTracker;

    let mut tracker = SequenceTracker::new();
    assert!(tracker.check(0));
    assert!(tracker.check(1));
    assert!(tracker.check(5));
    assert_eq!(tracker.highest(), Some(5));
}

#[test]
fn sequence_tracker_rejects_replay() {
    use toq_core::replay::SequenceTracker;

    let mut tracker = SequenceTracker::new();
    assert!(tracker.check(0));
    assert!(tracker.check(1));
    assert!(!tracker.check(1)); // replay
    assert!(!tracker.check(0)); // old
}

#[test]
fn sequence_tracker_reset() {
    use toq_core::replay::SequenceTracker;

    let mut tracker = SequenceTracker::new();
    assert!(tracker.check(0));
    assert!(tracker.check(5));
    tracker.reset(2);
    assert!(!tracker.check(2)); // at reset point
    assert!(tracker.check(3)); // above reset
}

// --- Key Rotation ---

#[test]
fn key_rotation_proof() {
    use toq_core::crypto::{generate_rotation_proof, verify_rotation_proof};

    let old_kp = Keypair::generate();
    let new_kp = Keypair::generate();

    let proof = generate_rotation_proof(&old_kp, &new_kp.public_key());
    verify_rotation_proof(&old_kp.public_key(), &new_kp.public_key(), &proof).unwrap();
}

#[test]
fn key_rotation_proof_wrong_key_fails() {
    use toq_core::crypto::{generate_rotation_proof, verify_rotation_proof};

    let old_kp = Keypair::generate();
    let new_kp = Keypair::generate();
    let wrong_kp = Keypair::generate();

    let proof = generate_rotation_proof(&old_kp, &new_kp.public_key());
    assert!(verify_rotation_proof(&wrong_kp.public_key(), &new_kp.public_key(), &proof).is_err());
}

// --- Messaging ---

#[tokio::test]
async fn send_message_and_ack() {
    use toq_core::framing;
    use toq_core::messaging::{self, SendParams};

    let (client_stream, server_stream) = tokio::io::duplex(8192);
    let (mut cr, mut cw) = tokio::io::split(client_stream);
    let (mut sr, mut sw) = tokio::io::split(server_stream);

    let sender_kp = Keypair::generate();
    let receiver_kp = Keypair::generate();
    let from = Address::new("alice.dev", "assistant").unwrap();
    let to = Address::new("bob.dev", "agent").unwrap();
    let sender_pub = sender_kp.public_key();
    let receiver_pub = receiver_kp.public_key();

    // Send message
    let msg_id = messaging::send_message(
        &mut cw,
        &sender_kp,
        SendParams {
            from: &from,
            to: std::slice::from_ref(&to),
            sequence: 1,
            body: Some(json!({"task": "hello"})),
            thread_id: Some("t1".into()),
            reply_to: None,
            priority: None,
            content_type: None,
            ttl: None,
            msg_type: None,
        },
    )
    .await
    .unwrap();

    // Receive and verify
    let envelope = framing::recv_envelope(&mut sr, &sender_pub, 1_048_576)
        .await
        .unwrap();
    assert_eq!(envelope.msg_type, MessageType::MessageSend);
    assert_eq!(envelope.thread_id.as_deref(), Some("t1"));

    // Send ack
    messaging::send_ack(&mut sw, &receiver_kp, &to, &from, &msg_id, 1)
        .await
        .unwrap();

    // Receive ack
    let ack = framing::recv_envelope(&mut cr, &receiver_pub, 1_048_576)
        .await
        .unwrap();
    assert_eq!(ack.msg_type, MessageType::MessageAck);
    let ack_body = ack.body.unwrap();
    assert_eq!(ack_body["ack_id"].as_str().unwrap(), msg_id.to_string());
}

// --- Delivery ---

#[test]
fn delivery_tracker_ack() {
    use toq_core::delivery::DeliveryTracker;

    let mut tracker = DeliveryTracker::new();
    let id = Uuid::new_v4();
    tracker.track(id);
    assert!(tracker.ack(&id));
    assert!(!tracker.ack(&id)); // already acked
}

#[test]
fn dedup_set_rejects_duplicates() {
    use toq_core::delivery::DedupSet;

    let mut dedup = DedupSet::new();
    let id = Uuid::new_v4();
    assert!(!dedup.is_duplicate(&id));
    assert!(dedup.is_duplicate(&id));
}

#[test]
fn dedup_set_allows_different_ids() {
    use toq_core::delivery::DedupSet;

    let mut dedup = DedupSet::new();
    assert!(!dedup.is_duplicate(&Uuid::new_v4()));
    assert!(!dedup.is_duplicate(&Uuid::new_v4()));
}

// --- Streaming ---

#[test]
fn stream_buffer_assemble() {
    use toq_core::streaming::StreamBuffer;

    let mut buf = StreamBuffer::new();
    buf.add_chunk("s1", 2, json!("second"));
    buf.add_chunk("s1", 1, json!("first"));

    let result = buf.complete("s1", Some(json!("final"))).unwrap();
    assert_eq!(
        result,
        vec![json!("first"), json!("second"), json!("final")]
    );
    assert!(!buf.has_stream("s1"));
}

#[test]
fn stream_buffer_cancel() {
    use toq_core::streaming::StreamBuffer;

    let mut buf = StreamBuffer::new();
    buf.add_chunk("s1", 1, json!("data"));
    assert!(buf.has_stream("s1"));
    buf.cancel("s1");
    assert!(!buf.has_stream("s1"));
}

#[tokio::test]
async fn stream_chunk_and_end() {
    use toq_core::framing;
    use toq_core::streaming::{self, ChunkParams};

    let (client_stream, server_stream) = tokio::io::duplex(8192);
    let (mut _cr, mut cw) = tokio::io::split(client_stream);
    let (mut sr, mut _sw) = tokio::io::split(server_stream);

    let kp = Keypair::generate();
    let pub_key = kp.public_key();
    let from = Address::new("alice.dev", "assistant").unwrap();
    let to = Address::new("bob.dev", "agent").unwrap();

    streaming::send_chunk(
        &mut cw,
        &kp,
        ChunkParams {
            from: &from,
            to: &to,
            stream_id: "s1",
            data: json!("part1"),
            sequence: 1,
            thread_id: None,
            content_type: None,
        },
    )
    .await
    .unwrap();

    streaming::send_end(
        &mut cw,
        &kp,
        &from,
        &to,
        "s1",
        Some(json!("part2")),
        2,
        None,
    )
    .await
    .unwrap();

    let chunk = framing::recv_envelope(&mut sr, &pub_key, 1_048_576)
        .await
        .unwrap();
    assert_eq!(chunk.msg_type, MessageType::StreamChunk);

    let end = framing::recv_envelope(&mut sr, &pub_key, 1_048_576)
        .await
        .unwrap();
    assert_eq!(end.msg_type, MessageType::StreamEnd);
}

#[tokio::test]
async fn send_and_receive_heartbeat() {
    use toq_core::connection;
    use toq_core::framing;

    let (client_stream, server_stream) = tokio::io::duplex(8192);
    let (mut cr, mut cw) = tokio::io::split(client_stream);
    let (mut sr, mut sw) = tokio::io::split(server_stream);

    let kp = Keypair::generate();
    let peer_kp = Keypair::generate();
    let from = Address::new("alice.dev", "assistant").unwrap();
    let to = Address::new("bob.dev", "agent").unwrap();
    let peer_pub = kp.public_key();

    let hb_id = connection::send_heartbeat(&mut cw, &kp, &from, &to, 10)
        .await
        .unwrap();

    let envelope = framing::recv_envelope(&mut sr, &peer_pub, 1_048_576)
        .await
        .unwrap();
    assert_eq!(envelope.msg_type, MessageType::Heartbeat);
    assert_eq!(envelope.id, hb_id);

    connection::send_heartbeat_ack(&mut sw, &peer_kp, &to, &from, &hb_id, 10)
        .await
        .unwrap();

    let ack = framing::recv_envelope(&mut cr, &peer_kp.public_key(), 1_048_576)
        .await
        .unwrap();
    assert_eq!(ack.msg_type, MessageType::HeartbeatAck);
    assert_eq!(ack.reply_to.unwrap(), hb_id.to_string());
}

#[tokio::test]
async fn send_disconnect() {
    use toq_core::connection;
    use toq_core::framing;

    let (client_stream, server_stream) = tokio::io::duplex(8192);
    let (mut _cr, mut cw) = tokio::io::split(client_stream);
    let (mut sr, mut _sw) = tokio::io::split(server_stream);

    let kp = Keypair::generate();
    let from = Address::new("alice.dev", "assistant").unwrap();
    let to = Address::new("bob.dev", "agent").unwrap();
    let pub_key = kp.public_key();

    connection::send_disconnect(&mut cw, &kp, &from, &to, 99)
        .await
        .unwrap();

    let envelope = framing::recv_envelope(&mut sr, &pub_key, 1_048_576)
        .await
        .unwrap();
    assert_eq!(envelope.msg_type, MessageType::SessionDisconnect);
    assert_eq!(envelope.sequence, 99);
}

// --- Discovery ---

#[test]
fn parse_txt_record_full() {
    use toq_core::discovery;

    let record =
        discovery::parse_txt_record("v=toq1; key=MCowBQYDK2VwAyEA; port=9009; agent=assistant")
            .unwrap();
    assert_eq!(record.agent_name, "assistant");
    assert_eq!(record.public_key_b64, "MCowBQYDK2VwAyEA");
    assert_eq!(record.port, DEFAULT_PORT);
}

#[test]
fn parse_txt_record_default_port() {
    use toq_core::discovery;

    let record = discovery::parse_txt_record("v=toq1; key=abc123; agent=helper").unwrap();
    assert_eq!(record.port, DEFAULT_PORT);
    assert_eq!(record.agent_name, "helper");
}

#[test]
fn parse_txt_record_custom_port() {
    use toq_core::discovery;

    let record = discovery::parse_txt_record("v=toq1; key=abc; port=7070; agent=bot").unwrap();
    assert_eq!(record.port, 7070);
}

#[test]
fn parse_txt_record_wrong_version() {
    use toq_core::discovery;

    assert!(discovery::parse_txt_record("v=toq2; key=abc; agent=bot").is_err());
}

#[test]
fn parse_txt_record_missing_key() {
    use toq_core::discovery;

    assert!(discovery::parse_txt_record("v=toq1; agent=bot").is_err());
}

#[test]
fn parse_txt_record_missing_agent() {
    use toq_core::discovery;

    assert!(discovery::parse_txt_record("v=toq1; key=abc").is_err());
}

#[test]
fn query_name_format() {
    use toq_core::discovery;

    assert_eq!(
        discovery::query_name("example.com"),
        "_toq._tcp.example.com"
    );
}

#[test]
fn to_discovered_agent() {
    use toq_core::discovery;

    let record =
        discovery::parse_txt_record("v=toq1; key=abc; port=7070; agent=assistant").unwrap();
    let agent = discovery::to_discovered_agent("example.com", &record).unwrap();
    assert_eq!(
        agent.address.to_string(),
        "toq://example.com:7070/assistant"
    );
    assert_eq!(agent.public_key_b64, "abc");
}

// --- Config ---

#[test]
fn config_defaults() {
    use toq_core::config::Config;

    let config = Config::default();
    assert_eq!(config.agent_name, "agent");
    assert_eq!(config.port, DEFAULT_PORT);
    assert_eq!(config.connection_mode, "approval");
    assert_eq!(config.max_message_size, 1_048_576);
    assert_eq!(config.heartbeat_interval, 30);
    assert!(!config.mdns_enabled);
}

#[test]
fn config_roundtrip_toml() {
    use toq_core::config::Config;

    let config = Config::default();
    let toml_str = toml::to_string_pretty(&config).unwrap();
    let parsed: Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.agent_name, config.agent_name);
    assert_eq!(parsed.port, config.port);
    assert_eq!(parsed.connection_mode, config.connection_mode);
}

#[test]
fn config_partial_toml() {
    use toq_core::config::Config;

    let partial = r#"
agent_name = "my-bot"
port = 7070
"#;
    let config: Config = toml::from_str(partial).unwrap();
    assert_eq!(config.agent_name, "my-bot");
    assert_eq!(config.port, 7070);
    // Everything else should be defaults
    assert_eq!(config.connection_mode, "approval");
    assert_eq!(config.heartbeat_interval, 30);
}

// --- Error Catalog ---

#[test]
fn error_code_severity() {
    use toq_core::error_catalog::{ErrorCode, Severity};

    assert_eq!(ErrorCode::InvalidSignature.severity(), Severity::Fatal);
    assert!(ErrorCode::InvalidSignature.is_fatal());
    assert_eq!(ErrorCode::DuplicateMessage.severity(), Severity::NonFatal);
    assert!(!ErrorCode::DuplicateMessage.is_fatal());
    assert_eq!(ErrorCode::Blocked.severity(), Severity::Silent);
}

#[test]
fn error_code_serde() {
    use toq_core::error_catalog::ErrorCode;

    let code = ErrorCode::AgentUnavailable;
    let json = serde_json::to_string(&code).unwrap();
    assert_eq!(json, "\"agent_unavailable\"");
    let parsed: ErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, code);
}

// --- Rate Limiting ---

#[test]
fn ratelimit_allows_under_limit() {
    use std::net::IpAddr;
    use toq_core::ratelimit::RateLimiter;

    let mut limiter = RateLimiter::new(5);
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    for _ in 0..5 {
        assert!(limiter.check(ip));
    }
    assert!(!limiter.check(ip)); // 6th should fail
}

#[test]
fn ratelimit_separate_ips() {
    use std::net::IpAddr;
    use toq_core::ratelimit::RateLimiter;

    let mut limiter = RateLimiter::new(2);
    let ip1: IpAddr = "127.0.0.1".parse().unwrap();
    let ip2: IpAddr = "127.0.0.2".parse().unwrap();
    assert!(limiter.check(ip1));
    assert!(limiter.check(ip1));
    assert!(!limiter.check(ip1));
    assert!(limiter.check(ip2)); // different IP, fresh limit
}

// --- Adapter ---

#[test]
fn agent_message_from_envelope() {
    use toq_core::adapter::AgentMessage;

    let kp = Keypair::generate();
    let mut env = test_envelope(&kp);
    env.thread_id = Some("t1".into());
    let msg = AgentMessage::from_envelope(&env);
    assert_eq!(msg.from, "toq://alice.dev/assistant");
    assert_eq!(msg.msg_type, "message.send");
    assert_eq!(msg.thread_id.as_deref(), Some("t1"));
    assert!(msg.body.is_some());
}

#[test]
fn adapter_type_serde() {
    use toq_core::adapter::AdapterType;

    let json = serde_json::to_string(&AdapterType::Http).unwrap();
    assert_eq!(json, "\"http\"");
    let parsed: AdapterType = serde_json::from_str("\"unix\"").unwrap();
    assert_eq!(parsed, AdapterType::Unix);
}

// --- Self-message prevention ---

#[tokio::test]
async fn send_message_rejects_self() {
    use toq_core::messaging::{self, SendParams};

    let (stream, _) = tokio::io::duplex(8192);
    let (mut _r, mut w) = tokio::io::split(stream);

    let kp = Keypair::generate();
    let addr = Address::new("alice.dev", "assistant").unwrap();

    let result = messaging::send_message(
        &mut w,
        &kp,
        SendParams {
            from: &addr,
            to: std::slice::from_ref(&addr),
            sequence: 1,
            body: None,
            thread_id: None,
            reply_to: None,
            priority: None,
            content_type: None,
            ttl: None,
            msg_type: None,
        },
    )
    .await;

    assert!(result.is_err());
}

// --- TTL expiry ---

#[test]
fn envelope_validate_ttl_expired() {
    let kp = Keypair::generate();
    let mut env = test_envelope(&kp);
    env.timestamp = "2020-01-01T00:00:00Z".into();
    env.ttl = Some(1);
    assert!(env.validate().is_err());
}

#[test]
fn envelope_validate_ttl_not_expired() {
    let kp = Keypair::generate();
    let mut env = test_envelope(&kp);
    env.timestamp = toq_core::now_utc();
    env.ttl = Some(3600);
    env.validate().unwrap();
}

// --- Replay prevention (recv_envelope_checked) ---

#[tokio::test]
async fn recv_envelope_checked_rejects_replay() {
    use toq_core::delivery::DedupSet;
    use toq_core::framing;
    use toq_core::replay::SequenceTracker;

    let (client_stream, server_stream) = tokio::io::duplex(8192);
    let (mut _cr, mut cw) = tokio::io::split(client_stream);
    let (mut sr, mut _sw) = tokio::io::split(server_stream);

    let kp = Keypair::generate();
    let pub_key = kp.public_key();
    let from = Address::new("alice.dev", "assistant").unwrap();
    let to = Address::new("bob.dev", "agent").unwrap();

    // Send two envelopes with same sequence (replay)
    let mut env1 = Envelope {
        version: PROTOCOL_VERSION.into(),
        id: Uuid::new_v4(),
        msg_type: MessageType::MessageSend,
        from: from.clone(),
        to: vec![to.clone()],
        thread_id: None,
        reply_to: None,
        sequence: 1,
        timestamp: toq_core::now_utc(),
        priority: None,
        content_type: None,
        ttl: None,
        compression: None,
        signature: String::new(),
        e2e_nonce: None,
        body: None,
    };
    framing::send_envelope(&mut cw, &mut env1, &kp)
        .await
        .unwrap();

    let mut env2 = env1.clone();
    env2.id = Uuid::new_v4();
    env2.sequence = 1; // same sequence = replay
    env2.signature = String::new();
    framing::send_envelope(&mut cw, &mut env2, &kp)
        .await
        .unwrap();

    let mut tracker = SequenceTracker::new();
    let mut dedup = DedupSet::new();

    // First should succeed
    let r1 = framing::recv_envelope_checked(&mut sr, &pub_key, 1_048_576, &mut tracker, &mut dedup)
        .await;
    assert!(r1.is_ok());

    // Second should fail (sequence replay)
    let r2 = framing::recv_envelope_checked(&mut sr, &pub_key, 1_048_576, &mut tracker, &mut dedup)
        .await;
    assert!(r2.is_err());
}

// --- New send functions ---

#[tokio::test]
async fn send_system_error() {
    use toq_core::connection;
    use toq_core::framing;

    let (client_stream, server_stream) = tokio::io::duplex(8192);
    let (mut _cr, mut cw) = tokio::io::split(client_stream);
    let (mut sr, mut _sw) = tokio::io::split(server_stream);

    let kp = Keypair::generate();
    let pub_key = kp.public_key();
    let from = Address::new("alice.dev", "assistant").unwrap();
    let to = Address::new("bob.dev", "agent").unwrap();

    connection::send_system_error(
        &mut cw,
        &kp,
        &from,
        &to,
        "invalid_envelope",
        "bad field",
        Some("msg-123"),
        1,
    )
    .await
    .unwrap();

    let env = framing::recv_envelope(&mut sr, &pub_key, 1_048_576)
        .await
        .unwrap();
    assert_eq!(env.msg_type, MessageType::SystemError);
    let body = env.body.unwrap();
    assert_eq!(body["code"].as_str().unwrap(), "invalid_envelope");
    assert_eq!(body["related_id"].as_str().unwrap(), "msg-123");
}

#[tokio::test]
async fn send_backpressure_and_clear() {
    use toq_core::connection;
    use toq_core::framing;

    let (client_stream, server_stream) = tokio::io::duplex(8192);
    let (mut _cr, mut cw) = tokio::io::split(client_stream);
    let (mut sr, mut _sw) = tokio::io::split(server_stream);

    let kp = Keypair::generate();
    let pub_key = kp.public_key();
    let from = Address::new("alice.dev", "assistant").unwrap();
    let to = Address::new("bob.dev", "agent").unwrap();

    connection::send_backpressure(&mut cw, &kp, &from, &to, 30, 1)
        .await
        .unwrap();
    connection::send_backpressure_clear(&mut cw, &kp, &from, &to, 2)
        .await
        .unwrap();

    let bp = framing::recv_envelope(&mut sr, &pub_key, 1_048_576)
        .await
        .unwrap();
    assert_eq!(bp.msg_type, MessageType::Backpressure);
    assert_eq!(bp.body.unwrap()["retry_after"].as_u64().unwrap(), 30);

    let clear = framing::recv_envelope(&mut sr, &pub_key, 1_048_576)
        .await
        .unwrap();
    assert_eq!(clear.msg_type, MessageType::BackpressureClear);
}

// --- E2E Encryption ---

#[test]
fn e2e_encrypt_decrypt_roundtrip() {
    use toq_core::e2e;

    let sender_kp = Keypair::generate();
    let receiver_kp = Keypair::generate();
    let receiver_x25519 = e2e::x25519_public_key(&receiver_kp);

    let plaintext = b"secret agent message";
    let (ciphertext, nonce) = e2e::encrypt_body(plaintext, &sender_kp, &receiver_x25519).unwrap();

    let sender_x25519 = e2e::x25519_public_key(&sender_kp);
    let decrypted = e2e::decrypt_body(&ciphertext, &nonce, &receiver_kp, &sender_x25519).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn e2e_wrong_key_fails() {
    use toq_core::e2e;

    let sender_kp = Keypair::generate();
    let receiver_kp = Keypair::generate();
    let wrong_kp = Keypair::generate();
    let receiver_x25519 = e2e::x25519_public_key(&receiver_kp);

    let (ciphertext, nonce) = e2e::encrypt_body(b"secret", &sender_kp, &receiver_x25519).unwrap();

    let wrong_x25519 = e2e::x25519_public_key(&wrong_kp);
    let result = e2e::decrypt_body(&ciphertext, &nonce, &receiver_kp, &wrong_x25519);
    assert!(result.is_err());
}

// --- Compression ---

#[test]
fn gzip_roundtrip() {
    use toq_core::compress;

    let data = b"hello toq protocol, this is a test of gzip compression";
    let compressed = compress::gzip_compress(data).unwrap();
    let decompressed = compress::gzip_decompress(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn zstd_roundtrip() {
    use toq_core::compress;

    let data = b"hello toq protocol, this is a test of zstd compression";
    let compressed = compress::zstd_compress(data).unwrap();
    let decompressed = compress::zstd_decompress(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

// --- Session Store ---

#[test]
fn session_register_and_resume() {
    use toq_core::session::SessionStore;

    let mut store = SessionStore::new();
    let kp = Keypair::generate();
    store.register("sess-1", &kp.public_key(), "toq://test/agent");
    store.update_sequence("sess-1", 42);

    let seq = store.validate_resume("sess-1", &kp.public_key());
    assert_eq!(seq, Some(42));
}

#[test]
fn session_resume_wrong_key() {
    use toq_core::session::SessionStore;

    let mut store = SessionStore::new();
    let kp1 = Keypair::generate();
    let kp2 = Keypair::generate();
    store.register("sess-1", &kp1.public_key(), "toq://test/agent");

    assert!(store.validate_resume("sess-1", &kp2.public_key()).is_none());
}

#[test]
fn session_duplicate_detection() {
    use toq_core::session::SessionStore;

    let mut store = SessionStore::new();
    let kp = Keypair::generate();
    store.register("sess-1", &kp.public_key(), "toq://test/agent");

    let dup = store.check_duplicate(&kp.public_key());
    assert_eq!(dup, Some("sess-1".to_string()));
}

#[test]
fn session_remove() {
    use toq_core::session::SessionStore;

    let mut store = SessionStore::new();
    let kp = Keypair::generate();
    store.register("sess-1", &kp.public_key(), "toq://test/agent");
    store.remove("sess-1");

    assert!(store.check_duplicate(&kp.public_key()).is_none());
    assert!(store.validate_resume("sess-1", &kp.public_key()).is_none());
}

// --- PolicyEngine persistence ---

#[test]
fn policy_load_empty_peer_store() {
    use toq_core::keystore::PeerStore;
    use toq_core::policy::*;

    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    let store = PeerStore::default();
    engine.load_from_peer_store(&store);
    assert_eq!(engine.pending_count(), 0);
}

#[test]
fn policy_load_blocked_peer() {
    use toq_core::keystore::{PeerStatus, PeerStore};
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp.public_key(), "toq://test/peer", PeerStatus::Blocked);

    let mut engine = PolicyEngine::new(ConnectionMode::Open);
    engine.load_from_peer_store(&store);
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Reject);
}

#[test]
fn policy_load_approved_peer() {
    use toq_core::keystore::{PeerStatus, PeerStore};
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp.public_key(), "toq://test/peer", PeerStatus::Approved);

    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.load_from_peer_store(&store);
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);
}

#[test]
fn policy_load_approved_into_allowlist() {
    use toq_core::keystore::{PeerStatus, PeerStore};
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp.public_key(), "toq://test/peer", PeerStatus::Approved);

    let mut engine = PolicyEngine::new(ConnectionMode::Allowlist);
    engine.load_from_peer_store(&store);
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);
}

#[test]
fn policy_load_pending_peer() {
    use toq_core::keystore::{PeerStatus, PeerStore};
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp.public_key(), "toq://test/peer", PeerStatus::Pending);

    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.load_from_peer_store(&store);
    assert_eq!(engine.pending_count(), 1);

    let pending = engine.list_pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].address, "toq://test/peer");
}

#[test]
fn policy_load_mixed_statuses() {
    use toq_core::keystore::{PeerStatus, PeerStore};
    use toq_core::policy::*;

    let blocked = Keypair::generate();
    let approved = Keypair::generate();
    let pending = Keypair::generate();

    let mut store = PeerStore::default();
    store.upsert(
        &blocked.public_key(),
        "toq://a/blocked",
        PeerStatus::Blocked,
    );
    store.upsert(
        &approved.public_key(),
        "toq://b/approved",
        PeerStatus::Approved,
    );
    store.upsert(
        &pending.public_key(),
        "toq://c/pending",
        PeerStatus::Pending,
    );

    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.load_from_peer_store(&store);

    assert_eq!(engine.check(&blocked.public_key()), PolicyDecision::Reject);
    assert_eq!(engine.check(&approved.public_key()), PolicyDecision::Accept);
    assert_eq!(engine.pending_count(), 1);
}

#[test]
fn policy_load_idempotent() {
    use toq_core::keystore::{PeerStatus, PeerStore};
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp.public_key(), "toq://test/peer", PeerStatus::Approved);

    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.load_from_peer_store(&store);
    engine.load_from_peer_store(&store);
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);
}

#[test]
fn policy_sync_empty_engine() {
    use toq_core::keystore::PeerStore;
    use toq_core::policy::*;

    let engine = PolicyEngine::new(ConnectionMode::Approval);
    let mut store = PeerStore::default();
    engine.sync_to_peer_store(&mut store);
    assert!(store.peers.is_empty());
}

#[test]
fn policy_sync_blocked_preserves_address() {
    use toq_core::keystore::{PeerStatus, PeerStore};
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(
        &kp.public_key(),
        "toq://original/addr",
        PeerStatus::Approved,
    );

    let mut engine = PolicyEngine::new(ConnectionMode::Open);
    engine.block(&kp.public_key());
    engine.sync_to_peer_store(&mut store);

    let record = store.get(&kp.public_key()).unwrap();
    assert_eq!(record.status, PeerStatus::Blocked);
    assert_eq!(record.address, "toq://original/addr");
}

#[test]
fn policy_sync_approved_preserves_address() {
    use toq_core::keystore::{PeerStatus, PeerStore};
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp.public_key(), "toq://original/addr", PeerStatus::Pending);

    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.approve(&kp.public_key());
    engine.sync_to_peer_store(&mut store);

    let record = store.get(&kp.public_key()).unwrap();
    assert_eq!(record.status, PeerStatus::Approved);
    assert_eq!(record.address, "toq://original/addr");
}

#[test]
fn policy_sync_pending_uses_info_address() {
    use toq_core::keystore::{PeerStatus, PeerStore};
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.add_pending(&kp.public_key(), "toq://remote/agent");

    let mut store = PeerStore::default();
    engine.sync_to_peer_store(&mut store);

    let record = store.get(&kp.public_key()).unwrap();
    assert_eq!(record.status, PeerStatus::Pending);
    assert_eq!(record.address, "toq://remote/agent");
}

#[test]
fn policy_roundtrip_load_sync() {
    use toq_core::keystore::{PeerStatus, PeerStore};
    use toq_core::policy::*;

    let blocked = Keypair::generate();
    let approved = Keypair::generate();
    let pending = Keypair::generate();

    // Build initial store
    let mut store = PeerStore::default();
    store.upsert(
        &blocked.public_key(),
        "toq://a/blocked",
        PeerStatus::Blocked,
    );
    store.upsert(
        &approved.public_key(),
        "toq://b/approved",
        PeerStatus::Approved,
    );
    store.upsert(
        &pending.public_key(),
        "toq://c/pending",
        PeerStatus::Pending,
    );

    // Load into engine
    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.load_from_peer_store(&store);

    // Sync back to a fresh store
    let mut store2 = PeerStore::default();
    engine.sync_to_peer_store(&mut store2);

    // Verify all peers present with correct status
    assert_eq!(
        store2.get(&blocked.public_key()).unwrap().status,
        PeerStatus::Blocked
    );
    assert_eq!(
        store2.get(&approved.public_key()).unwrap().status,
        PeerStatus::Approved
    );
    assert_eq!(
        store2.get(&pending.public_key()).unwrap().status,
        PeerStatus::Pending
    );
}

#[test]
fn policy_approve_adds_to_allowlist() {
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut engine = PolicyEngine::new(ConnectionMode::Allowlist);
    engine.approve(&kp.public_key());
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);
}

#[test]
fn policy_approve_removes_from_pending() {
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.add_pending(&kp.public_key(), "toq://test/peer");
    assert_eq!(engine.pending_count(), 1);
    engine.approve(&kp.public_key());
    assert_eq!(engine.pending_count(), 0);
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);
}

#[test]
fn policy_approve_not_pending_still_works() {
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.approve(&kp.public_key());
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);
    assert_eq!(engine.pending_count(), 0);
}

#[test]
fn policy_deny_not_pending_noop() {
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.deny(&kp.public_key());
    assert_eq!(engine.pending_count(), 0);
}

// --- PeerStore ---

#[test]
fn peer_store_default_empty() {
    use toq_core::keystore::PeerStore;
    let store = PeerStore::default();
    assert!(store.peers.is_empty());
}

#[test]
fn peer_store_upsert_and_get() {
    use toq_core::keystore::{PeerStatus, PeerStore};

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp.public_key(), "toq://test/peer", PeerStatus::Approved);

    let record = store.get(&kp.public_key()).unwrap();
    assert_eq!(record.address, "toq://test/peer");
    assert_eq!(record.status, PeerStatus::Approved);
}

#[test]
fn peer_store_upsert_updates_existing() {
    use toq_core::keystore::{PeerStatus, PeerStore};

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp.public_key(), "toq://old/addr", PeerStatus::Pending);
    store.upsert(&kp.public_key(), "toq://new/addr", PeerStatus::Approved);

    let record = store.get(&kp.public_key()).unwrap();
    assert_eq!(record.address, "toq://new/addr");
    assert_eq!(record.status, PeerStatus::Approved);
}

#[test]
fn peer_store_upsert_pending_does_not_overwrite_status() {
    use toq_core::keystore::{PeerStatus, PeerStore};

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp.public_key(), "toq://test/peer", PeerStatus::Approved);
    store.upsert(&kp.public_key(), "toq://test/peer", PeerStatus::Pending);

    let record = store.get(&kp.public_key()).unwrap();
    assert_eq!(record.status, PeerStatus::Approved);
}

#[test]
fn peer_store_get_missing() {
    use toq_core::keystore::PeerStore;

    let kp = Keypair::generate();
    let store = PeerStore::default();
    assert!(store.get(&kp.public_key()).is_none());
}

#[test]
fn peer_store_save_load_roundtrip() {
    use toq_core::keystore::{PeerStatus, PeerStore};

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp.public_key(), "toq://test/peer", PeerStatus::Approved);

    let dir = std::env::temp_dir().join(format!("toq-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("peers.json");

    store.save(&path).unwrap();
    let loaded = PeerStore::load(&path).unwrap();

    let record = loaded.get(&kp.public_key()).unwrap();
    assert_eq!(record.address, "toq://test/peer");
    assert_eq!(record.status, PeerStatus::Approved);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn peer_store_load_nonexistent() {
    use std::path::Path;
    use toq_core::keystore::PeerStore;

    let store = PeerStore::load(Path::new("/tmp/toq-nonexistent-file.json")).unwrap();
    assert!(store.peers.is_empty());
}

// --- PolicyEngine edge cases ---

#[test]
fn policy_load_invalid_key_skipped() {
    use toq_core::keystore::{PeerRecord, PeerStatus, PeerStore};
    use toq_core::policy::*;

    let mut store = PeerStore::default();
    store.peers.insert(
        "not-a-valid-key".to_string(),
        PeerRecord {
            address: "toq://test/peer".to_string(),
            status: PeerStatus::Approved,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T00:00:00Z".to_string(),
        },
    );

    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.load_from_peer_store(&store); // should not panic
    assert_eq!(engine.pending_count(), 0);
}

#[test]
fn policy_approval_max_pending() {
    use toq_core::policy::*;

    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    for i in 0..toq_core::constants::MAX_PENDING_APPROVALS {
        let kp = Keypair::generate();
        engine.add_pending(&kp.public_key(), &format!("toq://test/peer-{i}"));
    }

    let extra = Keypair::generate();
    assert_eq!(engine.check(&extra.public_key()), PolicyDecision::Reject);
}

#[test]
fn policy_block_removes_from_approved() {
    use toq_core::policy::*;

    let kp = Keypair::generate();
    let mut engine = PolicyEngine::new(ConnectionMode::Approval);
    engine.approve(&kp.public_key());
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Accept);

    engine.block(&kp.public_key());
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Reject);

    engine.unblock(&kp.public_key());
    // After unblock, not in approved anymore, so goes to PendingApproval
    assert_eq!(
        engine.check(&kp.public_key()),
        PolicyDecision::PendingApproval
    );
}

#[test]
fn policy_dns_verified_rejects_all() {
    use toq_core::policy::*;

    let engine = PolicyEngine::new(ConnectionMode::DnsVerified);
    let kp = Keypair::generate();
    assert_eq!(engine.check(&kp.public_key()), PolicyDecision::Reject);
}

#[test]
fn policy_mode_returns_correct() {
    use toq_core::policy::*;

    let engine = PolicyEngine::new(ConnectionMode::Allowlist);
    assert_eq!(*engine.mode(), ConnectionMode::Allowlist);
}

// --- StreamBuffer additional ---

#[test]
fn stream_buffer_out_of_order() {
    use toq_core::streaming::StreamBuffer;

    let mut buf = StreamBuffer::new();
    buf.add_chunk("s1", 3, serde_json::json!({"text": "c"}));
    buf.add_chunk("s1", 1, serde_json::json!({"text": "a"}));
    buf.add_chunk("s1", 2, serde_json::json!({"text": "b"}));

    let result = buf.complete("s1", None).unwrap();
    // Sorted by sequence
    assert_eq!(result[0]["text"], "a");
    assert_eq!(result[1]["text"], "b");
    assert_eq!(result[2]["text"], "c");
}

#[test]
fn stream_buffer_complete_with_final_data() {
    use toq_core::streaming::StreamBuffer;

    let mut buf = StreamBuffer::new();
    buf.add_chunk("s1", 1, serde_json::json!({"text": "hello "}));

    let result = buf
        .complete("s1", Some(serde_json::json!({"text": "world"})))
        .unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0]["text"], "hello ");
    assert_eq!(result[1]["text"], "world");
}

#[test]
fn stream_buffer_has_stream() {
    use toq_core::streaming::StreamBuffer;

    let mut buf = StreamBuffer::new();
    assert!(!buf.has_stream("s1"));
    buf.add_chunk("s1", 1, serde_json::json!("data"));
    assert!(buf.has_stream("s1"));
    buf.cancel("s1");
    assert!(!buf.has_stream("s1"));
}

#[test]
fn stream_buffer_complete_unknown_stream() {
    use toq_core::streaming::StreamBuffer;

    let mut buf = StreamBuffer::new();
    assert!(buf.complete("nonexistent", None).is_none());
}

#[test]
fn stream_buffer_empty_stream_end() {
    use toq_core::streaming::StreamBuffer;

    let mut buf = StreamBuffer::new();
    // End without any chunks, but with final data
    let result = buf.complete("s1", Some(serde_json::json!({"text": "only final"})));
    assert!(result.is_none()); // no stream was started
}

// --- RateLimiter additional ---

#[test]
fn ratelimit_blocks_over_limit() {
    use std::net::IpAddr;
    use toq_core::ratelimit::RateLimiter;

    let mut rl = RateLimiter::new(2);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(rl.check(ip));
    assert!(rl.check(ip));
    assert!(!rl.check(ip)); // third request blocked
}

// --- Config additional ---

#[test]
fn config_with_agent() {
    use toq_core::config::Config;

    let config = Config::default().with_agent("my-bot".into(), "allowlist".into());
    assert_eq!(config.agent_name, "my-bot");
    assert_eq!(config.connection_mode, "allowlist");
}

#[test]
fn config_with_adapter() {
    use toq_core::config::Config;

    let config = Config::default().with_adapter("unix".into());
    assert_eq!(config.adapter, "unix");
}

#[test]
fn config_load_nonexistent_returns_default() {
    use std::path::Path;
    use toq_core::config::Config;

    let config = Config::load(Path::new("/tmp/toq-nonexistent-config.toml")).unwrap();
    assert_eq!(config.agent_name, "agent");
    assert_eq!(config.connection_mode, "approval");
}

// --- DeliveryTracker additional ---

#[test]
fn delivery_tracker_ack_unknown() {
    use toq_core::delivery::DeliveryTracker;

    let mut tracker = DeliveryTracker::new();
    let unknown = uuid::Uuid::new_v4();
    assert!(!tracker.ack(&unknown)); // returns false for unknown
}

#[test]
fn delivery_tracker_multiple_pending() {
    use toq_core::delivery::DeliveryTracker;

    let mut tracker = DeliveryTracker::new();
    let id1 = uuid::Uuid::new_v4();
    let id2 = uuid::Uuid::new_v4();
    tracker.track(id1);
    tracker.track(id2);

    assert!(tracker.ack(&id1));
    assert!(!tracker.ack(&id1)); // already acked
    assert!(tracker.ack(&id2));
}

// --- PeerStore additional ---

#[test]
fn peer_store_save_load_multiple_peers() {
    use toq_core::keystore::{PeerStatus, PeerStore};

    let kp1 = Keypair::generate();
    let kp2 = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp1.public_key(), "toq://a/one", PeerStatus::Approved);
    store.upsert(&kp2.public_key(), "toq://b/two", PeerStatus::Blocked);

    let dir = std::env::temp_dir().join(format!("toq-test-multi-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("peers.json");

    store.save(&path).unwrap();
    let loaded = PeerStore::load(&path).unwrap();

    assert_eq!(loaded.peers.len(), 2);
    assert_eq!(
        loaded.get(&kp1.public_key()).unwrap().status,
        PeerStatus::Approved
    );
    assert_eq!(
        loaded.get(&kp2.public_key()).unwrap().status,
        PeerStatus::Blocked
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn peer_store_remove_peer() {
    use toq_core::keystore::{PeerStatus, PeerStore};

    let kp = Keypair::generate();
    let mut store = PeerStore::default();
    store.upsert(&kp.public_key(), "toq://test/peer", PeerStatus::Approved);
    assert!(store.get(&kp.public_key()).is_some());

    let key_str = kp.public_key().to_encoded();
    store.peers.remove(&key_str);
    assert!(store.get(&kp.public_key()).is_none());
}

// --- DeliveryTracker additional ---

#[test]
fn delivery_tracker_record_retry() {
    use toq_core::delivery::DeliveryTracker;

    let mut tracker = DeliveryTracker::new();
    let id = uuid::Uuid::new_v4();
    tracker.track(id);

    // First few retries should succeed
    assert!(tracker.record_retry(&id));
    assert!(tracker.record_retry(&id));

    // Eventually exceeds max
    for _ in 0..20 {
        tracker.record_retry(&id);
    }
    assert!(!tracker.record_retry(&id));
}

#[test]
fn delivery_tracker_record_retry_unknown() {
    use toq_core::delivery::DeliveryTracker;

    let mut tracker = DeliveryTracker::new();
    let unknown = uuid::Uuid::new_v4();
    assert!(!tracker.record_retry(&unknown));
}

#[test]
fn delivery_tracker_drain_undeliverable() {
    use toq_core::delivery::DeliveryTracker;

    let mut tracker = DeliveryTracker::new();
    let id = uuid::Uuid::new_v4();
    tracker.track(id);

    // Push past max retries
    for _ in 0..20 {
        tracker.record_retry(&id);
    }

    let failed = tracker.drain_undeliverable();
    assert!(failed.contains(&id));
    assert!(!tracker.ack(&id)); // removed
}

#[test]
fn delivery_tracker_drain_empty() {
    use toq_core::delivery::DeliveryTracker;

    let mut tracker = DeliveryTracker::new();
    let id = uuid::Uuid::new_v4();
    tracker.track(id);
    assert!(tracker.drain_undeliverable().is_empty()); // not past max retries
}

// --- DedupSet additional ---

#[test]
fn dedup_set_not_duplicate_first_time() {
    use toq_core::delivery::DedupSet;

    let mut dedup = DedupSet::new();
    let id = uuid::Uuid::new_v4();
    assert!(!dedup.is_duplicate(&id));
}

#[test]
fn dedup_set_duplicate_second_time() {
    use toq_core::delivery::DedupSet;

    let mut dedup = DedupSet::new();
    let id = uuid::Uuid::new_v4();
    assert!(!dedup.is_duplicate(&id));
    assert!(dedup.is_duplicate(&id));
}

#[test]
fn dedup_set_different_ids_not_duplicate() {
    use toq_core::delivery::DedupSet;

    let mut dedup = DedupSet::new();
    let id1 = uuid::Uuid::new_v4();
    let id2 = uuid::Uuid::new_v4();
    assert!(!dedup.is_duplicate(&id1));
    assert!(!dedup.is_duplicate(&id2));
}

// --- SessionStore additional ---

#[test]
fn session_list() {
    use toq_core::session::SessionStore;

    let mut store = SessionStore::new();
    let kp1 = Keypair::generate();
    let kp2 = Keypair::generate();
    store.register("sess-1", &kp1.public_key(), "toq://a/one");
    store.register("sess-2", &kp2.public_key(), "toq://b/two");

    let list = store.list();
    assert_eq!(list.len(), 2);
}

#[test]
fn session_update_sequence() {
    use toq_core::session::SessionStore;

    let mut store = SessionStore::new();
    let kp = Keypair::generate();
    store.register("sess-1", &kp.public_key(), "toq://test/peer");

    store.update_sequence("sess-1", 42);
    let seq = store.validate_resume("sess-1", &kp.public_key());
    assert_eq!(seq, Some(42));
}

#[test]
fn session_increment_messages() {
    use toq_core::session::SessionStore;

    let mut store = SessionStore::new();
    let kp = Keypair::generate();
    store.register("sess-1", &kp.public_key(), "toq://test/peer");

    store.increment_messages("sess-1");
    store.increment_messages("sess-1");

    let list = store.list();
    assert_eq!(list[0].messages_exchanged, 2);
}

#[test]
fn session_list_empty() {
    use toq_core::session::SessionStore;

    let store = SessionStore::new();
    assert!(store.list().is_empty());
}

#[test]
fn session_update_sequence_unknown() {
    use toq_core::session::SessionStore;

    let mut store = SessionStore::new();
    store.update_sequence("nonexistent", 10); // should not panic
}

#[test]
fn session_increment_messages_unknown() {
    use toq_core::session::SessionStore;

    let mut store = SessionStore::new();
    store.increment_messages("nonexistent"); // should not panic
}

// --- Config save/reload ---

#[test]
fn config_save_and_reload() {
    use toq_core::config::Config;

    let dir = std::env::temp_dir().join(format!("toq-test-cfg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("config.toml");

    let config = Config::default()
        .with_agent("test-bot".into(), "allowlist".into())
        .with_adapter("unix".into());
    config.save(&path).unwrap();

    let loaded = Config::load(&path).unwrap();
    assert_eq!(loaded.agent_name, "test-bot");
    assert_eq!(loaded.connection_mode, "allowlist");
    assert_eq!(loaded.adapter, "unix");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_default_path() {
    use toq_core::config::Config;

    let path = Config::default_path();
    assert!(path.ends_with(".toq/config.toml"));
}
