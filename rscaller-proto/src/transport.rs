use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::codec::{read_message, write_message};
use crate::types::{RelayAck, RelayHello};

// ── Rendezvous (rsserver) client side ───────────────────────────────────────

/// Where a client-side component (rsclient / rscfuse) reaches the beacon.
#[derive(Clone, Debug)]
pub enum ConnectTarget {
    /// Direct TCP to the beacon (existing topology, default).
    Direct(SocketAddr),
    /// Via rsserver rendezvous: the beacon dialed out to the server and is
    /// parked under `name`; we hello as Client and get byte-piped to it.
    Relay { server: SocketAddr, name: String, token: String },
}

/// Parse `--server [token@]host:port` plus optional `--auth` fallback into a
/// Relay target. Token in the URL wins over --auth.
pub fn parse_relay_target(
    server: &str,
    auth: Option<&str>,
    name: &str,
) -> Result<ConnectTarget> {
    let (token, host_port) = match server.split_once('@') {
        Some((t, h)) => (t.to_string(), h.to_string()),
        None => (auth.unwrap_or("").to_string(), server.to_string()),
    };
    let addr: SocketAddr = host_port
        .parse()
        .with_context(|| format!("parsing --server address {host_port:?} (want [token@]host:port)"))?;
    Ok(ConnectTarget::Relay { server: addr, name: name.to_string(), token })
}

pub type BoxedReader = Box<dyn AsyncRead + Unpin + Send>;
pub type BoxedWriter = Box<dyn AsyncWrite + Unpin + Send>;

/// Relay handshake: send hello, wait for the ack. For clients the server
/// only acks once paired with a beacon, so this doubles as "wait for
/// beacon" backpressure — hence the generous timeout.
pub async fn relay_handshake(
    stream: &mut TcpStream,
    hello: &RelayHello,
    timeout: std::time::Duration,
) -> Result<()> {
    let fut = async {
        write_message(&mut *stream, hello).await?;
        let ack: RelayAck = read_message(&mut *stream).await?;
        anyhow::ensure!(ack.ok, "relay server rejected: {}", ack.msg);
        Ok(())
    };
    tokio::time::timeout(timeout, fut)
        .await
        .context("timed out waiting for relay server (no beacon parked for this session?)")?
}

/// Connect to a beacon through a rendezvous server (relay hello as Client).
/// TCP keepalive on: idle relay links must not die silently behind NAT.
pub async fn connect_via_server(
    server: SocketAddr,
    name: &str,
    token: &str,
) -> Result<TcpStream> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_keepalive(true)?;
    let mut stream = socket.connect(server).await?;
    let _ = stream.set_nodelay(true);
    relay_handshake(
        &mut stream,
        &RelayHello::Client { name: name.to_string(), token: token.to_string() },
        std::time::Duration::from_secs(30),
    )
    .await?;
    Ok(stream)
}

/// Unified client-side connect: direct or relayed, plain or TLS.
/// TLS (when requested) always terminates at the beacon — a relay server
/// only ever sees ciphertext.
pub async fn connect(
    target: &ConnectTarget,
    use_tls: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(BoxedReader, BoxedWriter)> {
    let stream = match target {
        ConnectTarget::Direct(addr) => {
            let s = TcpStream::connect(addr).await?;
            let _ = s.set_nodelay(true);
            s
        }
        ConnectTarget::Relay { server, name, token } => {
            connect_via_server(*server, name, token).await?
        }
    };
    if use_tls {
        let ca = ca_cert_pem.context("TLS requires a CA cert")?;
        let (r, w) = tls::connect_tls_stream(stream, "rsbeacon", ca).await?;
        Ok((Box::new(r) as BoxedReader, Box::new(w) as BoxedWriter))
    } else {
        let (r, w) = tokio::io::split(stream);
        Ok((Box::new(r) as BoxedReader, Box::new(w) as BoxedWriter))
    }
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
        let tcp = TcpStream::connect(addr).await?;
        let _ = tcp.set_nodelay(true);
        connect_tls_stream(tcp, server_name, root_cert_pem).await
    }

    /// TLS handshake over an already-connected stream (e.g. a relay pipe).
    pub async fn connect_tls_stream(
        tcp: TcpStream,
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
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
        let tls = connector.connect(server_name, tcp).await?;
        let (r, w) = tokio::io::split(tls);
        Ok((r, w))
    }

    pub async fn accept_tls<T>(
        stream: T,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<tokio_rustls::server::TlsStream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
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
