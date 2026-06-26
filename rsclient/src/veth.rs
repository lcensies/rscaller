//! Veth pair creation and filter config helpers.
//!
//! Shells out to `ip` (iproute2) — requires CAP_NET_ADMIN / root.

use anyhow::{Context, Result};
use std::process::Command;
use tracing::info;

/// Create a veth pair, assign an IP to `name`, and bring both ends up.
///
/// Equivalent to:
/// ```text
/// ip link add <name> type veth peer name <peer>
/// ip addr add <ip>/32 dev <name>
/// ip link set <name> up
/// ip link set <peer> up
/// ```
pub fn setup_veth(name: &str, ip: &str, peer: &str) -> Result<()> {
    // Idempotent: delete existing pair if present (ignore failure).
    let _ = Command::new("ip")
        .args(["link", "del", name])
        .output();

    run_ip(
        &["link", "add", name, "type", "veth", "peer", "name", peer],
        "create veth pair",
    )?;

    // Accept bare IP or CIDR; default to /32 if no prefix given.
    let cidr = if ip.contains('/') {
        ip.to_string()
    } else {
        format!("{}/32", ip)
    };

    run_ip(&["addr", "add", &cidr, "dev", name], "assign IP")?;
    run_ip(&["link", "set", name, "up"], "bring veth up")?;
    run_ip(&["link", "set", peer, "up"], "bring peer up")?;

    info!("veth pair {}/{} up, {} assigned {}", name, peer, name, cidr);
    Ok(())
}

/// Optionally add a host route for `subnet` via the veth interface.
pub fn add_route(subnet: &str, dev: &str) -> Result<()> {
    run_ip(&["route", "add", subnet, "dev", dev], "add route")?;
    info!("route {} dev {}", subnet, dev);
    Ok(())
}

fn run_ip(args: &[&str], desc: &str) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("failed to exec `ip` for: {}", desc))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("`ip {}` failed ({}): {}", args.join(" "), desc, stderr.trim());
    }
    Ok(())
}
