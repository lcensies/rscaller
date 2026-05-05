use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Trait for pluggable transports.
/// Each transport provides an AsyncRead + AsyncWrite pair.
/// Future implementations: TlsTransport, ObfsTransport, etc.
#[async_trait]
pub trait Transport: Send + Sync {
    type Reader: AsyncRead + Unpin + Send;
    type Writer: AsyncWrite + Unpin + Send;

    async fn connect(addr: SocketAddr) -> Result<(Self::Reader, Self::Writer)>
    where
        Self: Sized;
}

/// Plain TCP transport (development)
pub struct TcpTransport;

#[async_trait]
impl Transport for TcpTransport {
    type Reader = tokio::io::ReadHalf<TcpStream>;
    type Writer = tokio::io::WriteHalf<TcpStream>;

    async fn connect(addr: SocketAddr) -> Result<(Self::Reader, Self::Writer)> {
        let stream = TcpStream::connect(addr).await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok((reader, writer))
    }
}

/// TLS transport (production)
pub struct TlsTransport {
    _priv: (),
}

impl TlsTransport {
    /// Create a TLS transport with a custom root cert (for self-signed certs)
    pub fn with_root_cert(_cert_der: &[u8]) -> Result<Self> {
        Ok(TlsTransport { _priv: () })
    }
}

/// TLS helpers using tokio-rustls.
/// Uses rustls with custom cert verifier for self-signed certs.
pub mod tls {
    use super::*;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use std::io::BufReader;
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;

    pub async fn connect_tls(
        addr: SocketAddr,
        server_name: &str,
        root_cert_pem: &[u8],
    ) -> Result<(
        tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>,
        tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>,
    )> {
        use rustls_pemfile::certs;

        let mut root_store = RootCertStore::empty();
        let mut reader = BufReader::new(root_cert_pem);
        for cert in certs(&mut reader) {
            root_store.add(cert?)?;
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(addr).await?;
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
        let tls_stream = connector.connect(server_name, tcp).await?;
        let (r, w) = tokio::io::split(tls_stream);
        Ok((r, w))
    }

    pub async fn accept_tls(
        stream: TcpStream,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
        use rustls_pemfile::{certs, pkcs8_private_keys};

        let certs: Vec<_> = certs(&mut BufReader::new(cert_pem))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut keys: Vec<_> = pkcs8_private_keys(&mut BufReader::new(key_pem))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        if keys.is_empty() {
            anyhow::bail!("No private keys found in key PEM");
        }

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                certs,
                rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0)),
            )?;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        Ok(acceptor.accept(stream).await?)
    }
}
