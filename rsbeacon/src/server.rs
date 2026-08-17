use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::transport::relay_handshake;
use rscaller_proto::types::{RelayHello, SyscallRequest};

use crate::executor::execute_syscall;
use crate::net_backend::NetBackend;

pub async fn run_plain(addr: SocketAddr, backend: Arc<dyn NetBackend>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("rsbeacon listening (plain TCP) on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        info!("Connection from {}", peer);
        let _ = stream.set_nodelay(true);
        let backend = backend.clone();
        tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(stream);
            if let Err(e) = handle_connection(&mut reader, &mut writer, &*backend).await {
                warn!("Connection error from {}: {}", peer, e);
            }
        });
    }
}

pub async fn run_tls(
    addr: SocketAddr,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    backend: Arc<dyn NetBackend>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("rsbeacon listening (TLS) on {}", addr);

    loop {
        let (tcp_stream, peer) = listener.accept().await?;
        info!("TLS connection from {}", peer);
        let cert_pem = cert_pem.clone();
        let key_pem = key_pem.clone();
        let backend = backend.clone();
        tokio::spawn(async move {
            match rscaller_proto::transport::tls::accept_tls(tcp_stream, &cert_pem, &key_pem).await
            {
                Ok(tls_stream) => {
                    let (mut reader, mut writer) = tokio::io::split(tls_stream);
                    if let Err(e) = handle_connection(&mut reader, &mut writer, &*backend).await {
                        warn!("TLS connection error from {}: {}", peer, e);
                    }
                }
                Err(e) => error!("TLS handshake failed from {}: {}", peer, e),
            }
        });
    }
}

pub async fn run_uds(path: &str, backend: Arc<dyn NetBackend>) -> Result<()> {
    use tokio::net::UnixListener;

    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    info!("rsbeacon listening (UDS) on {}", path);

    loop {
        let (stream, _) = listener.accept().await?;
        let backend = backend.clone();
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(stream);
            if let Err(e) = handle_connection(&mut r, &mut w, &*backend).await {
                warn!("UDS connection error: {}", e);
            }
        });
    }
}

// ── Reverse mode (dial-out via rsserver) ────────────────────────────────────

/// Reverse mode: instead of listening, dial out to an rsserver and multiplex
/// all client sessions over that single connection with yamux. The server
/// opens one yamux stream per client; we serve each as a normal connection.
/// Session liveness comes from yamux (connection error/close ends the loop
/// below and triggers a redial) plus TCP keepalive on the dial-out socket.
///
/// TLS (when enabled) is accepted per yamux stream — end-to-end between
/// client and beacon; rsserver only ever relays ciphertext.
pub async fn run_reverse(
    server: SocketAddr,
    name: String,
    token: String,
    use_tls: bool,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    backend: Arc<dyn NetBackend>,
    max_streams: usize,
) -> Result<()> {
    info!(
        "rsbeacon reverse mode: dialing {} as session '{}' (tls={}, max {} streams)",
        server, name, use_tls, max_streams
    );
    loop {
        match reverse_mux_session(&server, &name, &token, use_tls, &cert_pem, &key_pem, &backend, max_streams).await
        {
            Ok(()) => info!("mux session ended, redialing"),
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("rejected") {
                    // Auth failure: redialing would loop the same failure.
                    error!("rsserver rejected this beacon (check --auth): {msg}");
                    std::process::exit(2);
                }
                warn!("reverse session failed: {msg} — redialing in 2s");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

async fn reverse_mux_session(
    server: &SocketAddr,
    name: &str,
    token: &str,
    use_tls: bool,
    cert_pem: &[u8],
    key_pem: &[u8],
    backend: &Arc<dyn NetBackend>,
    max_streams: usize,
) -> Result<()> {
    use tokio_util::compat::{FuturesAsyncWriteCompatExt, TokioAsyncReadCompatExt};

    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_keepalive(true)?;
    let mut stream = socket.connect(*server).await?;
    let _ = stream.set_nodelay(true);
    relay_handshake(
        &mut stream,
        &RelayHello::Beacon { name: name.to_string(), token: token.to_string() },
        std::time::Duration::from_secs(10),
    )
    .await?;
    info!("parked at rsserver {server} as session '{name}' (yamux)");

    // yamux speaks futures-io; TcpStream is tokio — compat both ways.
    let mut cfg = yamux::Config::default();
    cfg.set_max_num_streams(max_streams.max(1));
    let mut conn = yamux::Connection::new(stream.compat(), cfg, yamux::Mode::Client);

    loop {
        let next = futures_util::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await;
        let mux_stream = match next {
            Some(Ok(s)) => s,
            Some(Err(e)) => anyhow::bail!("yamux connection error: {e}"),
            None => return Ok(()),
        };
        let backend = backend.clone();
        let cert = cert_pem.to_vec();
        let key = key_pem.to_vec();
        tokio::spawn(async move {
            let s = mux_stream.compat_write();
            let res = if use_tls {
                match rscaller_proto::transport::tls::accept_tls(s, &cert, &key).await {
                    Ok(tls) => {
                        let (mut r, mut w) = tokio::io::split(tls);
                        handle_connection(&mut r, &mut w, &*backend).await
                    }
                    Err(e) => Err(anyhow::anyhow!("TLS handshake on mux stream: {e:#}")),
                }
            } else {
                let (mut r, mut w) = tokio::io::split(s);
                handle_connection(&mut r, &mut w, &*backend).await
            };
            if let Err(e) = res {
                warn!("reverse mux stream ended: {e:#}");
            }
        });
    }
}

async fn handle_connection<R, W>(reader: &mut R, writer: &mut W, backend: &dyn NetBackend) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let req: SyscallRequest = match read_message(reader).await {
            Ok(r) => r,
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                // EOF is normal: client disconnected cleanly
                if msg.contains("eof") || msg.contains("unexpectedeof") {
                    return Ok(());
                }
                return Err(e);
            }
        };

        tracing::info!("XDP_DIAG: req nr={} args={:?}", req.number, req.args);
        let resp = execute_syscall(&req, backend);
        tracing::info!("XDP_DIAG: resp ret={}", resp.ret);
        write_message(writer, &resp).await?;
    }
}
