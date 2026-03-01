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
    engine.add_pending(&kp.public_key());
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
            to: &[to.clone()],
            sequence: 1,
            body: Some(json!({"task": "hello"})),
            thread_id: Some("t1".into()),
            reply_to: None,
            priority: None,
            content_type: None,
            ttl: None,
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
