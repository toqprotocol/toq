use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::Error;

/// Generate a self-signed TLS certificate for the toq endpoint.
pub fn generate_self_signed_cert()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Error> {
    let certified_key =
        rcgen::generate_simple_self_signed(vec![crate::constants::TLS_SELF_SIGNED_SAN.into()])
            .map_err(|e| Error::Crypto(e.to_string()))?;
    let cert_der = CertificateDer::from(certified_key.cert);
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        certified_key.key_pair.serialize_der(),
    ));
    Ok((vec![cert_der], key_der))
}

/// Build a rustls ServerConfig with the given cert and key. TLS 1.3 only.
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, Error> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(Arc::new(config))
}

/// Build a rustls ClientConfig that skips certificate verification.
/// Identity is verified at the toq protocol layer via Ed25519 keys, not TLS certs.
pub fn client_config() -> Arc<ClientConfig> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Arc::new(config)
}

/// Certificate verifier that accepts any certificate.
/// Safe because toq protocol verifies identity via Ed25519 handshake, not TLS certificates.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Create a TLS acceptor from a server config.
pub fn tls_acceptor(config: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}

/// Accept a TLS connection on a TCP stream.
pub async fn tls_accept(
    acceptor: &TlsAcceptor,
    tcp: TcpStream,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>, Error> {
    acceptor
        .accept(tcp)
        .await
        .map_err(|e| Error::Io(e.to_string()))
}

/// Connect to a peer over TLS.
pub async fn tls_connect(
    tcp: TcpStream,
    config: Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Error> {
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from(crate::constants::TLS_SELF_SIGNED_SAN)
        .map_err(|e| Error::Io(e.to_string()))?
        .to_owned();
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::Io(e.to_string()))
}

/// Check if a target host resolves to the same machine as the local host.
pub fn is_same_host(target_host: &str, local_host: &str) -> bool {
    if target_host == local_host
        || target_host == "localhost"
        || target_host == "127.0.0.1"
        || target_host == "::1"
    {
        return true;
    }

    use std::net::ToSocketAddrs;
    let resolve = |host: &str| -> Vec<std::net::IpAddr> {
        format!("{host}:0")
            .to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).collect())
            .unwrap_or_default()
    };

    let target_ips = resolve(target_host);
    let local_ips = resolve(local_host);
    target_ips.iter().any(|t| local_ips.contains(t))
}

/// Resolve a connection address, routing locally if the target is on this machine.
pub fn resolve_connect_addr(target_host: &str, target_port: u16, local_host: &str) -> String {
    let host = if is_same_host(target_host, local_host) {
        "127.0.0.1"
    } else {
        target_host
    };
    format!("{host}:{target_port}")
}

/// Resolve a target address, using DNS TXT records to find the port if not explicit.
pub async fn resolve_target_addr(target: &crate::types::Address, local_host: &str) -> String {
    let port = if !target.port_explicit && !is_ip_address(&target.host) {
        match crate::dns::lookup_agent(&target.host, &target.agent_name).await {
            Ok(Some(record)) => record.port,
            _ => target.port,
        }
    } else {
        target.port
    };
    resolve_connect_addr(&target.host, port, local_host)
}

pub fn is_ip_address(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}
