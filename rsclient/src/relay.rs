//! Generic relay loop — controller-agnostic.
//!
//! [`Relay`] receives [`Notification`]s from any [`SyscallController`] backend,
//! forwards them to rsbeacon as [`SyscallRequest`]s, awaits [`SyscallResponse`]s,
//! and signals completion back to the controller.
//!
//! For the kmod backend the [`Notification`] already carries `in_data` (bytes
//! were copied by the kernel via `copy_from_user`).  For the seccomp backend
//! `in_data` is empty — pointer arguments must be read with [`read_tracee_mem`]
//! before forwarding.  The seccomp path requires a pointer-metadata table to
//! know which args are pointers and in which direction; currently we forward
//! raw args and let rsbeacon handle pointer allocation (same as kmod OUT bufs).

use std::time::Duration;

use anyhow::Result;
use ctls::{Notification, SyscallController};
use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::{SyscallBuf, SyscallRequest, SyscallResponse};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

const EINVAL: i64 = 22;

pub struct Relay<C, R, W>
where
    C: SyscallController,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub controller: C,
    pub beacon_reader: R,
    pub beacon_writer: W,
}

impl<C, R, W> Relay<C, R, W>
where
    C: SyscallController,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(controller: C, beacon_reader: R, beacon_writer: W) -> Self {
        Self { controller, beacon_reader, beacon_writer }
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            let notif = match self.controller.recv().await? {
                Some(n) => n,
                None => {
                    // Controller shut down (e.g. tracee exited).
                    return Ok(());
                }
            };

            if let Err(e) = self.dispatch(notif).await {
                warn!(error = %e, "dispatch error");
                // Keep running — one bad syscall shouldn't kill the relay.
            }
        }
    }

    async fn dispatch(&mut self, notif: Notification) -> Result<()> {
        let id = notif.id;
        let nr = notif.nr;

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

/// Convert a notification to a wire request.
///
/// `in_data` from the kmod backend maps directly to `in_bufs`.
/// For the seccomp backend `in_data` is empty — rsbeacon receives raw args
/// and must allocate its own buffers for pointer params.
fn notification_to_request(n: &Notification) -> SyscallRequest {
    let in_bufs: Vec<SyscallBuf> = n
        .in_data
        .iter()
        .map(|b| SyscallBuf {
            arg_idx: b.arg_idx,
            data: b.data.clone(),
        })
        .collect();

    SyscallRequest {
        slot_idx: n.id,
        number: n.nr,
        args: n.args,
        in_bufs,
        out_sizes: n.out_sizes.clone(),
    }
}


