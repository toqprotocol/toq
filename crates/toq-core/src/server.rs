use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::card::{self, AgentCard};
use crate::connection::ConnectionState;
use crate::crypto::{Keypair, PublicKey};
use crate::error::Error;
use crate::handshake;
use crate::negotiation::{self, Features, NegotiatedFeatures};
use crate::transport;
use crate::types::Address;

/// A fully established connection after handshake, negotiation, and card exchange.
#[derive(Debug)]
pub struct EstablishedConnection {
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
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Run the full server-side protocol flow on an accepted TCP connection:
/// TLS → handshake → negotiation → card exchange → ACTIVE.
pub async fn accept_connection(
    tcp: TcpStream,
    tls_acceptor: &TlsAcceptor,
    keypair: &Keypair,
    address: &Address,
    local_card: &AgentCard,
    local_features: &Features,
) -> Result<EstablishedConnection, Error> {
    // TLS
    let mut tls_stream = transport::tls_accept(tls_acceptor, tcp).await?;

    // Handshake
    let hs = handshake::accept(&mut tls_stream, keypair, address).await?;

    // Negotiation
    let features = negotiation::respond(
        &mut tls_stream,
        keypair,
        &hs.peer_public_key,
        address,
        &hs.peer_address,
        local_features,
    )
    .await?;

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

    Ok(EstablishedConnection {
        peer_public_key: hs.peer_public_key,
        peer_address: hs.peer_address,
        session_id: hs.session_id,
        features,
        peer_card,
        state: ConnectionState::Active,
    })
}

/// Run the full client-side protocol flow:
/// TCP connect → TLS → handshake → negotiation → card exchange → ACTIVE.
pub async fn connect_to_peer(
    target: &str,
    keypair: &Keypair,
    address: &Address,
    local_card: &AgentCard,
    local_features: &Features,
) -> Result<EstablishedConnection, Error> {
    // TCP + TLS
    let tcp = TcpStream::connect(target)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let client_cfg = transport::client_config();
    let mut tls_stream = transport::tls_connect(tcp, client_cfg).await?;

    // Handshake
    let hs = handshake::initiate(&mut tls_stream, keypair, address).await?;

    // Negotiation
    let features = negotiation::request(
        &mut tls_stream,
        keypair,
        &hs.peer_public_key,
        address,
        &hs.peer_address,
        local_features,
    )
    .await?;

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

    Ok(EstablishedConnection {
        peer_public_key: hs.peer_public_key,
        peer_address: hs.peer_address,
        session_id: hs.session_id,
        features,
        peer_card,
        state: ConnectionState::Active,
    })
}
