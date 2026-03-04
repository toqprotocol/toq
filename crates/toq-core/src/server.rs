use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::card::{self, AgentCard};
use crate::connection::ConnectionState;
use crate::constants::{HANDSHAKE_TIMEOUT, NEGOTIATION_TIMEOUT};
use crate::crypto::{Keypair, PublicKey};
use crate::error::Error;
use crate::handshake;
use crate::negotiation::{self, Features, NegotiatedFeatures};
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::transport;
use crate::types::Address;

/// Connection metadata after handshake, negotiation, and card exchange.
#[derive(Debug)]
pub struct ConnectionInfo {
    pub peer_public_key: PublicKey,
    pub peer_address: Address,
    pub session_id: String,
    pub features: NegotiatedFeatures,
    pub peer_card: AgentCard,
    pub state: ConnectionState,
}

/// Bind a TCP listener on the given address (e.g., "0.0.0.0:9009").
pub async fn bind(addr: &str) -> Result<TcpListener, Error> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Io(e.to_string()))
}

/// Run the full server-side protocol flow on an accepted TCP connection.
/// Returns the connection info and the live TLS stream for continued use.
pub async fn accept_connection(
    tcp: TcpStream,
    tls_acceptor: &TlsAcceptor,
    keypair: &Keypair,
    address: &Address,
    local_card: &AgentCard,
    local_features: &Features,
    policy: Option<&mut PolicyEngine>,
) -> Result<(ConnectionInfo, tokio_rustls::server::TlsStream<TcpStream>), Error> {
    // TLS
    let mut tls_stream = transport::tls_accept(tls_acceptor, tcp).await?;

    // Handshake (with timeout)
    let hs = timeout(
        HANDSHAKE_TIMEOUT,
        handshake::accept(&mut tls_stream, keypair, address, None),
    )
    .await
    .map_err(|_| Error::Io("handshake timeout".into()))??;

    // Policy check
    if let Some(engine) = policy {
        match engine.check(&hs.peer_public_key) {
            PolicyDecision::Accept => {}
            PolicyDecision::Reject => {
                return Err(Error::InvalidEnvelope(
                    "connection rejected by policy".into(),
                ));
            }
            PolicyDecision::PendingApproval => {
                engine.add_pending(&hs.peer_public_key, &hs.peer_address.to_string());
                // Send approval.request to the initiator before returning.
                crate::connection::send_approval_request(
                    &mut tls_stream,
                    keypair,
                    address,
                    &hs.peer_address,
                    Some("Your connection request is pending review."),
                    0,
                )
                .await?;
                return Err(Error::InvalidEnvelope("connection pending approval".into()));
            }
        }
    }

    // Negotiation (with timeout)
    let features = timeout(
        NEGOTIATION_TIMEOUT,
        negotiation::respond(
            &mut tls_stream,
            keypair,
            &hs.peer_public_key,
            address,
            &hs.peer_address,
            local_features,
        ),
    )
    .await
    .map_err(|_| Error::Io("negotiation timeout".into()))??;

    // Card exchange
    let peer_card = card::exchange(
        &mut tls_stream,
        keypair,
        &hs.peer_public_key,
        address,
        &hs.peer_address,
        local_card,
        1,
    )
    .await?;

    let info = ConnectionInfo {
        peer_public_key: hs.peer_public_key,
        peer_address: hs.peer_address,
        session_id: hs.session_id,
        features,
        peer_card,
        state: ConnectionState::Active,
    };

    Ok((info, tls_stream))
}

/// Run the full client-side protocol flow.
/// Returns the connection info and the live TLS stream for continued use.
pub async fn connect_to_peer(
    target: &str,
    keypair: &Keypair,
    address: &Address,
    local_card: &AgentCard,
    local_features: &Features,
) -> Result<(ConnectionInfo, tokio_rustls::client::TlsStream<TcpStream>), Error> {
    // TCP + TLS
    let tcp = TcpStream::connect(target)
        .await
        .map_err(|e| Error::Io(e.to_string()))?;
    let client_cfg = transport::client_config();
    let mut tls_stream = transport::tls_connect(tcp, client_cfg).await?;

    // Handshake (with timeout)
    let hs = timeout(
        HANDSHAKE_TIMEOUT,
        handshake::initiate(&mut tls_stream, keypair, address),
    )
    .await
    .map_err(|_| Error::Io("handshake timeout".into()))??;

    // Negotiation (with timeout)
    let features = timeout(
        NEGOTIATION_TIMEOUT,
        negotiation::request(
            &mut tls_stream,
            keypair,
            &hs.peer_public_key,
            address,
            &hs.peer_address,
            local_features,
        ),
    )
    .await
    .map_err(|_| Error::Io("negotiation timeout".into()))??;

    // Card exchange
    let peer_card = card::exchange(
        &mut tls_stream,
        keypair,
        &hs.peer_public_key,
        address,
        &hs.peer_address,
        local_card,
        1,
    )
    .await?;

    let info = ConnectionInfo {
        peer_public_key: hs.peer_public_key,
        peer_address: hs.peer_address,
        session_id: hs.session_id,
        features,
        peer_card,
        state: ConnectionState::Active,
    };

    Ok((info, tls_stream))
}
