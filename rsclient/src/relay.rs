//! Generic relay loop — controller-agnostic.
//!
//! [`Relay`] receives [`Notification`]s from any [`SyscallController`] backend,
//! optionally applies a network destination filter ([`NetFilter`]), forwards
//! matching notifications to rsbeacon as [`SyscallRequest`]s, and signals
//! completion back to the controller.
//!
//! Non-matching network syscalls (connect/sendto to addresses outside the
//! filter) are continued locally via [`SyscallController::continue_syscall`].

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;
use ctls::{Notification, SyscallController};
use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::{SyscallBuf, SyscallRequest, SyscallResponse};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

const EINVAL: i64 = 22;

// ---------------------------------------------------------------------------
// Network filter
// ---------------------------------------------------------------------------

/// IPv4 subnet + optional port list filter.
///
/// Built from `--filter-net` / `--filter-ports` CLI args.
/// `passes()` returns `true` if the syscall should be forwarded to rsbeacon.
#[derive(Clone, Debug, Default)]
pub struct NetFilter {
    /// If `Some`, only IPv4 connect/sendto destinations inside this subnet
    /// are forwarded.  `None` = forward everything (no filter).
    pub net: Option<(u32, u32)>, // (addr_be, mask_be) in network byte order

    /// If non-empty, only these destination ports (host byte order) pass.
    /// Empty = all ports pass.
    pub ports: Vec<u16>,
}

impl NetFilter {
    /// Parse from CLI strings.
    ///
    /// `net_str`: CIDR notation e.g. `"192.0.2.160/29"`.
    /// `ports_str`: comma-separated e.g. `"80,443,22"`.
    pub fn parse(net_str: Option<&str>, ports_str: Option<&str>) -> Result<Self> {
        let net = net_str.map(parse_cidr).transpose()?;
        let ports = ports_str
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().parse::<u16>().map_err(|e| anyhow::anyhow!("bad port '{}': {}", s, e)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { net, ports })
    }

    /// Returns `true` if this syscall should be forwarded to rsbeacon.
    ///
    /// For connect (42) and sendto (44) with a non-null sockaddr: checks the
    /// destination address and port against the configured filter.
    /// For all other syscalls (or if no filter is set): returns `true`.
    ///
    /// `sa_bytes`: the raw sockaddr bytes already read from tracee memory
    /// (i.e. `in_data` for connect arg 1, sendto arg 4).
    pub fn passes(&self, nr: u64, sa_bytes: Option<&[u8]>) -> bool {
        // No net filter configured → forward everything.
        let Some((net_addr, net_mask)) = self.net else {
            return true;
        };

        // Only filter connect and sendto.
        if nr != 42 && nr != 44 {
            return true;
        }

        let Some(sa) = sa_bytes else {
            return true; // no sockaddr data → pass through
        };

        // sockaddr_in: u16 family + u16 port_be + u32 addr_be
        if sa.len() < 8 {
            return true;
        }
        let family = u16::from_ne_bytes([sa[0], sa[1]]);
        if family != libc::AF_INET as u16 {
            return true; // non-IPv4 → pass through
        }
        let port_be = u16::from_be_bytes([sa[2], sa[3]]);
        let addr_be = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);

        // Subnet check (both in network/big-endian byte order).
        if (addr_be & net_mask) != (net_addr & net_mask) {
            return false;
        }

        // Port check.
        if !self.ports.is_empty() && !self.ports.contains(&port_be) {
            return false;
        }

        true
    }
}

fn parse_cidr(s: &str) -> Result<(u32, u32)> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("FILTER_NET missing '/': '{}'", s))?;
    let addr: Ipv4Addr = addr_str
        .parse()
        .map_err(|e| anyhow::anyhow!("bad FILTER_NET addr '{}': {}", addr_str, e))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|e| anyhow::anyhow!("bad FILTER_NET prefix '{}': {}", prefix_str, e))?;
    if prefix > 32 {
        anyhow::bail!("FILTER_NET prefix > 32: {}", prefix);
    }
    let addr_be = u32::from_be_bytes(addr.octets());
    let mask_be: u32 = if prefix == 0 { 0 } else { !((1u32 << (32 - prefix)) - 1) };
    Ok((addr_be, mask_be))
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

pub struct Relay<C, R, W>
where
    C: SyscallController,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub controller: C,
    pub beacon_reader: R,
    pub beacon_writer: W,
    pub filter: NetFilter,
}

impl<C, R, W> Relay<C, R, W>
where
    C: SyscallController,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(controller: C, beacon_reader: R, beacon_writer: W) -> Self {
        Self { controller, beacon_reader, beacon_writer, filter: NetFilter::default() }
    }

    pub fn with_filter(mut self, filter: NetFilter) -> Self {
        self.filter = filter;
        self
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            let notif = match self.controller.recv().await? {
                Some(n) => n,
                None => return Ok(()),
            };

            if let Err(e) = self.dispatch(notif).await {
                warn!(error = %e, "dispatch error");
            }
        }
    }

    async fn dispatch(&mut self, notif: Notification) -> Result<()> {
        let id = notif.id;
        let nr = notif.nr;

        // ── Network filter ────────────────────────────────────────────────
        // For connect(42): sockaddr is arg 1.
        // For sendto(44):  sockaddr is arg 4 (may be null for connected sockets).
        let sa_bytes: Option<&[u8]> = match nr {
            42 => notif.in_data.iter().find(|b| b.arg_idx == 1).map(|b| b.data.as_slice()),
            44 => notif.in_data.iter().find(|b| b.arg_idx == 4).map(|b| b.data.as_slice()),
            _ => None,
        };

        if !self.filter.passes(nr, sa_bytes) {
            debug!(id, nr, "net filter: continuing locally");
            self.controller.continue_syscall(id).await?;
            return Ok(());
        }

        // ── Forward to beacon ─────────────────────────────────────────────
        debug!(id, nr, pid = notif.pid, "dispatching to beacon");

        let req = notification_to_request(&notif);

        if let Err(e) = write_message(&mut self.beacon_writer, &req).await {
            warn!(error = %e, "send to beacon failed");
            self.controller.complete(id, -EINVAL, &[], &notif.args).await?;
            return Err(e);
        }

        let resp = match tokio::time::timeout(
            Duration::from_secs(30),
            read_message::<SyscallResponse, _>(&mut self.beacon_reader),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!(error = %e, id, "beacon response error");
                self.controller.complete(id, -EINVAL, &[], &notif.args).await?;
                return Err(e);
            }
            Err(_) => {
                warn!(id, "beacon response timeout");
                self.controller.complete(id, -EINVAL, &[], &notif.args).await?;
                return Err(anyhow::anyhow!("beacon response timeout"));
            }
        };

        debug!(id = resp.slot_idx, ret = resp.ret, "beacon response");
        let out_bufs: Vec<(u8, Vec<u8>)> = resp
            .out_bufs
            .into_iter()
            .map(|b| (b.arg_idx, b.data))
            .collect();
        self.controller
            .complete(resp.slot_idx, resp.ret, &out_bufs, &notif.args)
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn notification_to_request(n: &Notification) -> SyscallRequest {
    let in_bufs: Vec<SyscallBuf> = n
        .in_data
        .iter()
        .map(|b| SyscallBuf { arg_idx: b.arg_idx, data: b.data.clone() })
        .collect();

    SyscallRequest {
        slot_idx: n.id,
        number: n.nr,
        args: n.args,
        in_bufs,
        out_sizes: n.out_sizes.clone(),
    }
}

