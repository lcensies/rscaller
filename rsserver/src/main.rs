//! rsserver — optional rendezvous ("C2") server for rscaller.
//!
//! Beacons dial OUT to this server (`rsbeacon --connect`) and register under
//! a session name; all client sessions to that beacon are multiplexed over
//! the beacon's single outbound connection with yamux. Clients connect with
//! `rsc exec --server [token@]host:port` and are byte-piped to a fresh yamux
//! stream. The server never terminates TLS — client↔beacon encryption stays
//! end-to-end.
//!
//! Session management:
//! - sessions keyed by name (default "default"); unlimited sessions.
//! - one outbound beacon connection per session; yamux multiplexes all
//!   clients of that session over it (stream count bounded beacon-side by
//!   rsbeacon --max-connections).
//! - beacon liveness: a driver task owns the yamux connection; on close the
//!   session's beacon handle is dropped and clients are parked again.
//! - dead parked clients are reaped every 30s (MSG_PEEK liveness) and lazily
//!   on beacon reconnect.
//! - a client is acked only once paired: its connect() doubles as
//!   "waiting for beacon" backpressure and times out after 30s client-side.
//!
//! yamux 0.13 has no shared `Control` handle, so each beacon connection is
//! owned by a driver task; client pairings request fresh streams over an
//! mpsc channel (actor pattern).

use anyhow::{Context, Result};
use clap::Parser;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncWriteCompatExt, TokioAsyncReadCompatExt};
use tracing::{info, warn};

use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::{RelayAck, RelayHello};

#[derive(Parser)]
#[command(name = "rsserver", about = "rscaller rendezvous server (beacon dial-out relay)")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:4444")]
    listen: String,

    /// Shared auth token. When set, every hello must carry it; when unset,
    /// any token (including empty) is accepted — lab mode only.
    #[arg(long)]
    auth_token: Option<String>,
}

/// Handle to a live beacon mux: ask the driver task for a fresh yamux stream.
#[derive(Clone)]
struct BeaconHandle {
    tx: mpsc::Sender<oneshot::Sender<Result<yamux::Stream, String>>>,
}

impl BeaconHandle {
    async fn open_stream(&self) -> Result<yamux::Stream> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(tx).await.context("beacon driver gone")?;
        rx.await
            .context("beacon driver dropped reply")?
            .map_err(|e| anyhow::anyhow!("open stream to beacon: {e}"))
    }
}

#[derive(Default)]
struct Session {
    beacon: Option<BeaconHandle>,
    beacon_driver: Option<tokio::task::AbortHandle>,
    /// Bumped on every beacon registration; stale drivers must not clear a
    /// newer beacon's handle.
    generation: u64,
    waiting_clients: VecDeque<TcpStream>,
    active: usize,
}

type Registry = Arc<Mutex<HashMap<String, Session>>>;

/// Non-blocking liveness probe: MSG_PEEK | MSG_DONTWAIT.
/// r > 0 (data) or EAGAIN = alive; r == 0 (EOF) or other error = dead.
/// Only used for PARKED clients, which carry no application data, so peek
/// never steals.
fn is_alive(s: &TcpStream) -> bool {
    let mut b = [0u8; 1];
    let r = unsafe {
        libc::recv(s.as_raw_fd(), b.as_mut_ptr() as *mut _, 1, libc::MSG_PEEK | libc::MSG_DONTWAIT)
    };
    if r > 0 {
        return true;
    }
    if r == 0 {
        return false;
    }
    matches!(std::io::Error::last_os_error().raw_os_error(), Some(e) if e == libc::EAGAIN)
}

/// Reaper for parked clients (parked beacons don't exist — a beacon is its
/// yamux connection, monitored by its driver task).
fn spawn_reaper(registry: Registry) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tick.tick().await;
            let mut reg = registry.lock().expect("registry poisoned");
            reg.retain(|name, s| {
                let before = s.waiting_clients.len();
                s.waiting_clients.retain(is_alive);
                if before != s.waiting_clients.len() {
                    info!("session '{name}': reaped dead parked client(s)");
                }
                s.beacon.is_some() || s.active > 0 || !s.waiting_clients.is_empty()
            });
        }
    });
}

async fn ack(stream: &mut TcpStream, ok: bool, msg: &str) -> Result<()> {
    write_message(stream, &RelayAck { ok, msg: msg.to_string() }).await
}

/// Open a yamux stream to the session's beacon, ack the client, and pump
/// bytes between them until either side closes.
async fn pair_client(registry: Registry, name: String, handle: BeaconHandle, mut client: TcpStream) {
    let peer = client.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
    match handle.open_stream().await {
        Ok(mux) => {
            if let Err(e) = ack(&mut client, true, "paired").await {
                warn!("session '{name}': ack to {peer} failed: {e:#}");
                return;
            }
            {
                let mut reg = registry.lock().expect("registry poisoned");
                if let Some(s) = reg.get_mut(&name) {
                    s.active += 1;
                }
            }
            info!("session '{name}': client {peer} paired");
            let mut beacon_stream = mux.compat_write();
            match tokio::io::copy_bidirectional(&mut beacon_stream, &mut client).await {
                Ok((x, y)) => info!("session '{name}': pipe with {peer} closed ({x}+{y} bytes)"),
                Err(e) => warn!("session '{name}': pipe with {peer} error: {e}"),
            }
            let mut reg = registry.lock().expect("registry poisoned");
            if let Some(s) = reg.get_mut(&name) {
                s.active = s.active.saturating_sub(1);
            }
        }
        Err(e) => {
            warn!("session '{name}': pairing {peer} failed: {e:#}");
            let _ = ack(&mut client, false, &format!("pairing failed: {e:#}")).await;
        }
    }
}

/// Own a beacon's yamux connection: serve stream-open requests from client
/// pairings, drive connection I/O, detect death. The beacon (yamux client
/// mode) never opens streams toward us; any inbound stream is dropped.
async fn drive_beacon(
    registry: Registry,
    name: String,
    generation: u64,
    mut conn: yamux::Connection<tokio_util::compat::Compat<TcpStream>>,
    mut rx: mpsc::Receiver<oneshot::Sender<Result<yamux::Stream, String>>>,
) {
    let mut rx_closed = false;
    loop {
        tokio::select! {
            req = rx.recv(), if !rx_closed => {
                match req {
                    Some(reply) => {
                        let r = futures_util::future::poll_fn(|cx| conn.poll_new_outbound(cx)).await;
                        let _ = reply.send(r.map_err(|e| e.to_string()));
                    }
                    None => rx_closed = true, // last BeaconHandle dropped
                }
            }
            item = futures_util::future::poll_fn(|cx| conn.poll_next_inbound(cx)) => {
                match item {
                    Some(Ok(stream)) => {
                        warn!("session '{name}': unexpected beacon-initiated stream, dropping");
                        drop(stream);
                    }
                    Some(Err(e)) => {
                        warn!("session '{name}': beacon mux error: {e}");
                        break;
                    }
                    None => break, // clean close
                }
            }
        }
    }
    let mut reg = registry.lock().expect("registry poisoned");
    if let Some(s) = reg.get_mut(&name) {
        if s.generation == generation {
            s.beacon = None;
            s.beacon_driver = None;
            info!("session '{name}': beacon gone");
        }
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    registry: Registry,
    auth_token: Option<String>,
) -> Result<()> {
    let _ = stream.set_nodelay(true);

    let hello: RelayHello = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        read_message(&mut stream),
    )
    .await
    .context("hello timeout")??;

    let (name, token, is_beacon) = match &hello {
        RelayHello::Beacon { name, token } => (name.clone(), token.clone(), true),
        RelayHello::Client { name, token } => (name.clone(), token.clone(), false),
    };

    if let Some(want) = &auth_token {
        if &token != want {
            ack(&mut stream, false, "bad token").await?;
            warn!("{peer}: rejected (bad token, session '{name}')");
            return Ok(());
        }
    }

    if is_beacon {
        // Ack first: the beacon's connect returns as soon as it's registered.
        ack(&mut stream, true, "registered").await?;

        let mut cfg = yamux::Config::default();
        cfg.set_max_num_streams(256);
        let conn = yamux::Connection::new(stream.compat(), cfg, yamux::Mode::Server);
        let (tx, rx) = mpsc::channel(64);
        let handle = BeaconHandle { tx };

        let waiting = {
            let mut reg = registry.lock().expect("registry poisoned");
            let session = reg.entry(name.clone()).or_default();
            session.generation += 1;
            if let Some(old) = session.beacon_driver.take() {
                old.abort(); // replaced beacon: tear down the old mux
            }
            let generation = session.generation;
            let driver = tokio::spawn(drive_beacon(registry.clone(), name.clone(), generation, conn, rx));
            session.beacon_driver = Some(driver.abort_handle());
            session.beacon = Some(handle.clone());
            let waiting: Vec<TcpStream> = session
                .waiting_clients
                .drain(..)
                .filter(is_alive)
                .collect();
            info!("session '{name}': beacon {peer} registered ({} client(s) waiting)",
                  waiting.len());
            waiting
        };

        // Pair everyone who was parked waiting for this beacon.
        for client in waiting {
            tokio::spawn(pair_client(registry.clone(), name.clone(), handle.clone(), client));
        }
    } else {
        enum Act {
            Pair(BeaconHandle, TcpStream),
            Parked,
        }
        let act = {
            let mut reg = registry.lock().expect("registry poisoned");
            let session = reg.entry(name.clone()).or_default();
            match &session.beacon {
                Some(h) => Act::Pair(h.clone(), stream),
                None => {
                    session.waiting_clients.push_back(stream);
                    info!("session '{name}': client {peer} parked, waiting for beacon");
                    Act::Parked
                }
            }
        };
        if let Act::Pair(handle, stream) = act {
            tokio::spawn(pair_client(registry.clone(), name.clone(), handle, stream));
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rsserver=info".parse()?),
        )
        .init();

    let args = Args::parse();
    let addr: SocketAddr = args.listen.parse().context("parsing --listen")?;

    // TcpSocket (not TcpListener::bind) so accepted sockets inherit
    // SO_KEEPALIVE on Linux — idle relay links must not rot behind NAT.
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_keepalive(true)?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    info!("rsserver listening on {} (auth: {})", addr,
          if args.auth_token.is_some() { "token" } else { "OPEN — lab mode" });

    let registry = Registry::default();
    spawn_reaper(registry.clone());

    loop {
        let (stream, peer) = listener.accept().await?;
        let registry = registry.clone();
        let token = args.auth_token.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, peer, registry, token).await {
                warn!("{peer}: {e:#}");
            }
        });
    }
}
