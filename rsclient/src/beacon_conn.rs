//! Shared "connect to rsbeacon" helper.
//!
//! Used both by `main.rs`'s primary relay connection and by
//! `socket_proxy.rs`'s per-proxied-socket background connections — the
//! latter needs to open *additional* connections to rsbeacon with the same
//! transport/encryption settings the CLI was given, so this is factored out
//! rather than duplicated.
//!
//! TLS and plain TCP produce different concrete `AsyncRead`/`AsyncWrite`
//! types, so both are boxed into trait objects here — `socket_proxy`'s
//! background tasks aren't performance-critical (a handful of syscall
//! round-trips per read/write, not a hot data path in itself), so the
//! small dynamic-dispatch cost is not worth generic-parameter plumbing
//! through every call site.

use std::net::SocketAddr;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub type BeaconReader = Box<dyn AsyncRead + Unpin + Send>;
pub type BeaconWriter = Box<dyn AsyncWrite + Unpin + Send>;

/// Connection settings needed to open an (additional) connection to
/// rsbeacon — everything `connect_beacon` needs besides the address itself.
/// Cheap to clone (the CA PEM is the only non-trivial part, and connections
/// are opened rarely — once per proxied socket — not per read/write).
#[derive(Clone, Debug, Default)]
pub struct BeaconConnConfig {
    pub use_tls: bool,
    pub ca_pem: Option<Vec<u8>>,
}

/// Opens one connection to rsbeacon at `addr`, using `cfg`'s transport
/// settings. Mirrors the connection setup in `main.rs`'s `run_seccomp`/
/// `run_kmod`, factored out so `socket_proxy` can open its own additional
/// connections with the exact same settings.
pub async fn connect_beacon(addr: SocketAddr, cfg: &BeaconConnConfig) -> Result<(BeaconReader, BeaconWriter)> {
    if cfg.use_tls {
        let ca_pem = cfg
            .ca_pem
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("BeaconConnConfig::use_tls set but ca_pem is None"))?;
        let (r, w) = rscaller_proto::transport::tls::connect_tls(addr, "rsbeacon", ca_pem).await?;
        Ok((Box::new(r), Box::new(w)))
    } else {
        let stream = TcpStream::connect(addr).await?;
        let _ = stream.set_nodelay(true);
        let (r, w) = tokio::io::split(stream);
        Ok((Box::new(r), Box::new(w)))
    }
}
