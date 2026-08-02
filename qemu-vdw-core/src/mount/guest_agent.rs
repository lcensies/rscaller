//! A small QEMU Guest Agent (`qemu-ga`) client built on top of libvirt's
//! `virDomainQemuAgentCommand` (`Domain::qemu_agent_command`), used to run
//! commands inside the guest (`guest-exec`) with a bounded overall
//! timeout. See design.md Decision 3.

use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use virt::domain::Domain;

/// The result of a completed `guest-exec` invocation.
#[derive(Debug, Clone)]
pub struct GuestExecResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl GuestExecResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Errors talking to the guest agent. Kept separate from
/// [`super::MountError`]'s command-specific variants (LUKS open / mount
/// failed) — this type only covers the *channel* itself being unusable.
#[derive(Debug)]
pub enum GuestAgentError {
    /// The agent did not respond (or libvirt reported a failure talking
    /// to it) within the caller's bounded timeout.
    Unreachable { timeout: Duration, detail: Option<String> },
    /// The agent responded, but with something that wasn't a well-formed
    /// QEMU guest agent JSON reply.
    Protocol(String),
}

impl std::fmt::Display for GuestAgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuestAgentError::Unreachable { timeout, detail } => match detail {
                Some(d) => write!(
                    f,
                    "guest agent unreachable after {timeout:?}: {d}"
                ),
                None => write!(f, "guest agent unreachable after {timeout:?}"),
            },
            GuestAgentError::Protocol(msg) => write!(f, "guest agent protocol error: {msg}"),
        }
    }
}

impl std::error::Error for GuestAgentError {}

const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Run `path arg[0] arg[1] ...` inside the guest via `guest-exec`,
/// optionally feeding `input` to its stdin, polling `guest-exec-status`
/// until it exits or `timeout` elapses.
pub fn guest_exec(
    domain: &Domain,
    path: &str,
    args: &[&str],
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<GuestExecResult, GuestAgentError> {
    let deadline = Instant::now() + timeout;

    let mut arguments = serde_json::json!({
        "path": path,
        "arg": args,
        "capture-output": true,
    });
    if let Some(bytes) = input {
        arguments["input-data"] = Value::String(STANDARD.encode(bytes));
    }
    let exec_cmd = serde_json::json!({
        "execute": "guest-exec",
        "arguments": arguments,
    })
    .to_string();

    // The very first `guest-exec` dispatch commonly fails immediately —
    // not because the channel is truly unreachable, but because the VM
    // has only just started and the guest hasn't finished booting far
    // enough to have `qemu-ga` connected to the virtio-serial port yet
    // (confirmed against a real boot: `domain.create()` returns almost
    // instantly, well before guest userspace runs). So this dispatch is
    // retried against the same deadline as the exit-status poll below,
    // rather than failing on the first attempt.
    let exec_response = call_agent_with_retry(domain, &exec_cmd, timeout, deadline)?;
    let pid = exec_response
        .get("return")
        .and_then(|r| r.get("pid"))
        .and_then(Value::as_i64)
        .ok_or_else(|| GuestAgentError::Protocol("guest-exec response missing pid".to_string()))?;

    let status_cmd = serde_json::json!({
        "execute": "guest-exec-status",
        "arguments": { "pid": pid },
    })
    .to_string();

    loop {
        let status_response = call_agent_with_retry(domain, &status_cmd, timeout, deadline)?;
        let ret = status_response.get("return").ok_or_else(|| {
            GuestAgentError::Protocol("guest-exec-status response missing return".to_string())
        })?;

        let exited = ret.get("exited").and_then(Value::as_bool).unwrap_or(false);
        if exited {
            let exit_code = ret.get("exitcode").and_then(Value::as_i64).unwrap_or(-1) as i32;
            let stdout = decode_field(ret, "out-data")?;
            let stderr = decode_field(ret, "err-data")?;
            return Ok(GuestExecResult {
                exit_code,
                stdout,
                stderr,
            });
        }

        if Instant::now() >= deadline {
            return Err(GuestAgentError::Unreachable {
                timeout,
                detail: Some(format!("guest-exec pid {pid} did not exit in time")),
            });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn decode_field(value: &Value, field: &str) -> Result<Vec<u8>, GuestAgentError> {
    match value.get(field).and_then(Value::as_str) {
        Some(encoded) => STANDARD
            .decode(encoded)
            .map_err(|e| GuestAgentError::Protocol(format!("invalid base64 in `{field}`: {e}"))),
        None => Ok(Vec::new()),
    }
}

/// Issue `cmd`, retrying on any libvirt/agent-level failure (typically
/// "agent not connected yet") until it succeeds or `deadline` passes.
/// Malformed-JSON responses are NOT retried — a guest agent that is
/// actually connected but replying with garbage is a protocol error, not
/// a transient unavailability.
fn call_agent_with_retry(
    domain: &Domain,
    cmd: &str,
    timeout: Duration,
    deadline: Instant,
) -> Result<Value, GuestAgentError> {
    loop {
        match call_agent(domain, cmd, timeout) {
            Ok(value) => return Ok(value),
            Err(err @ GuestAgentError::Protocol(_)) => return Err(err),
            Err(unreachable @ GuestAgentError::Unreachable { .. }) => {
                if Instant::now() >= deadline {
                    return Err(unreachable);
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

fn call_agent(domain: &Domain, cmd: &str, timeout: Duration) -> Result<Value, GuestAgentError> {
    let timeout_secs = timeout.as_secs().clamp(1, i32::MAX as u64) as i32;
    let raw = domain
        .qemu_agent_command(cmd, timeout_secs, 0)
        .map_err(|source| GuestAgentError::Unreachable {
            timeout,
            detail: Some(source.to_string()),
        })?;
    serde_json::from_str(&raw)
        .map_err(|e| GuestAgentError::Protocol(format!("invalid JSON from guest agent: {e}")))
}
