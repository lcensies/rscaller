//! `rsc beacon-gen` — compile a zero-config rsbeacon.
//!
//! Bakes listen address and encryption into the binary via env vars read by
//! rsbeacon's `option_env!` defaults, forces a fresh CA/cert identity per
//! generation, and emits a directory with everything the beacon side needs:
//!
//!   rsbeacon   — run with NO arguments
//!   ca.pem     — client-side `--ca-cert` (TLS on)
//!
//! No config files, no flags on the beacon.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct BeaconGenArgs {
    pub listen: String,
    pub tls: bool,
    pub out: PathBuf,
    /// Bake reverse mode: the generated beacon dials out to this rsserver
    /// ([token@]host:port) instead of listening.
    pub connect: Option<String>,
    /// Session name baked for --connect mode (default "default").
    pub name: Option<String>,
}

/// Workspace root, baked at rsc compile time (…/rscaller/rsc → …/rscaller).
fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.to_path_buf())
        .context("resolving workspace root from CARGO_MANIFEST_DIR")
}

/// rsbeacon build-script OUT_DIR(s) holding the generated PEM identity.
fn find_out_dirs(ws: &Path) -> Result<Vec<PathBuf>> {
    let build_dir = ws.join("target/release/build");
    let mut dirs = Vec::new();
    for entry in std::fs::read_dir(&build_dir)
        .with_context(|| format!("reading {}", build_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("rsbeacon-") && entry.path().join("out").is_dir() {
            dirs.push(entry.path().join("out"));
        }
    }
    if dirs.is_empty() {
        bail!("no rsbeacon OUT_DIR under {} — build rsbeacon once first", build_dir.display());
    }
    Ok(dirs)
}

pub fn run_beacon_gen(args: BeaconGenArgs) -> Result<()> {
    let ws = workspace_root()?;

    // Fresh identity per generated beacon: drop cached PEMs so build.rs
    // regenerates CA + server cert.
    for out_dir in find_out_dirs(&ws)? {
        for pem in ["ca.pem", "cert.pem", "key.pem"] {
            let _ = std::fs::remove_file(out_dir.join(pem));
        }
    }

    let encryption = if args.tls { "tls" } else { "none" };
    // --connect may carry the token as token@host:port; split for baking.
    // Absent values must be UNSET (not empty): option_env! sees Some("").
    let mut envs = format!(
        "RSC_BEACON_LISTEN='{}' RSC_BEACON_ENCRYPTION='{}'",
        args.listen, encryption
    );
    if let Some(c) = &args.connect {
        let (addr, token) = match c.split_once('@') {
            Some((t, h)) => (h, t),
            None => (c.as_str(), ""),
        };
        envs.push_str(&format!(" RSC_BEACON_CONNECT='{addr}'"));
        if !token.is_empty() {
            envs.push_str(&format!(" RSC_BEACON_AUTH='{token}'"));
        }
    }
    if let Some(n) = &args.name {
        envs.push_str(&format!(" RSC_BEACON_NAME='{n}'"));
    }
    let status = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "source \"$HOME/.cargo/env\" 2>/dev/null; \
             {envs} cargo build -p rsbeacon --release"
        ))
        .current_dir(&ws)
        .status()
        .context("spawning cargo build")?;
    if !status.success() {
        bail!("cargo build -p rsbeacon failed (status {status})");
    }

    std::fs::create_dir_all(&args.out)
        .with_context(|| format!("creating {}", args.out.display()))?;
    let bin = ws.join("target/release/rsbeacon");
    std::fs::copy(&bin, args.out.join("rsbeacon"))
        .with_context(|| format!("copying {}", bin.display()))?;

    if args.tls {
        // CA lives in the (single) rsbeacon OUT_DIR, regenerated above.
        let ca = find_out_dirs(&ws)?
            .into_iter()
            .map(|d| d.join("ca.pem"))
            .find(|p| p.exists())
            .context("ca.pem not regenerated after build")?;
        std::fs::copy(&ca, args.out.join("ca.pem"))
            .with_context(|| format!("copying {}", ca.display()))?;
    }

    eprintln!("rsc: beacon written to {}", args.out.display());
    match &args.connect {
        Some(c) => eprintln!(
            "  beacon:  {}/rsbeacon   (run with no args; dials out to rsserver {c})",
            args.out.display()
        ),
        None => eprintln!(
            "  beacon:  {}/rsbeacon   (run with no args, listens on {})",
            args.out.display(),
            args.listen
        ),
    }
    if args.tls {
        eprintln!("  client:  --encryption tls --ca-cert {}/ca.pem", args.out.display());
    }
    Ok(())
}
