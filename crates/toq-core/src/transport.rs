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
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".into()])
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
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Connect to a peer over TLS.
pub async fn tls_connect(
    tcp: TcpStream,
    config: Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Error> {
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from("localhost")
        .map_err(|e| Error::Crypto(e.to_string()))?
        .to_owned();
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))
}
