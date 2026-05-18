use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub enum Transport {
    Tcp,
    Uds,
}

#[derive(Clone, Debug)]
pub enum Encryption {
    None,
    Tls { ca_cert_pem: Vec<u8> },
}

// ── Client side ───────────────────────────────────────────────────────────────

pub async fn connect_tcp_plain(
    addr: SocketAddr,
) -> Result<(impl AsyncRead + Unpin + Send, impl AsyncWrite + Unpin + Send)> {
    let s = TcpStream::connect(addr).await?;
    let _ = s.set_nodelay(true);
    let (r, w) = tokio::io::split(s);
    Ok((r, w))
}

pub async fn connect_tcp_tls(
    addr: SocketAddr,
    server_name: &str,
    ca_cert_pem: &[u8],
) -> Result<(impl AsyncRead + Unpin + Send, impl AsyncWrite + Unpin + Send)> {
    tls::connect_tls(addr, server_name, ca_cert_pem).await
}

pub async fn connect_uds_plain(
    path: &std::path::Path,
) -> Result<(impl AsyncRead + Unpin + Send, impl AsyncWrite + Unpin + Send)> {
    let s = tokio::net::UnixStream::connect(path).await?;
    let (r, w) = tokio::io::split(s);
    Ok((r, w))
}

// ── Server side ───────────────────────────────────────────────────────────────

pub async fn accept_tls(
    stream: TcpStream,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<impl AsyncRead + Unpin + Send + AsyncWrite + Unpin + Send> {
    tls::accept_tls(stream, cert_pem, key_pem).await
}

// ── TLS helpers ───────────────────────────────────────────────────────────────

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
        let _ = tcp.set_nodelay(true);
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
        let tls = connector.connect(server_name, tcp).await?;
        let (r, w) = tokio::io::split(tls);
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

        anyhow::ensure!(!keys.is_empty(), "No private keys found");

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
