//! rscaller-runner: orchestrates the full deploy pipeline.
//!
//! 1. SSH into remote host, snapshot tracefs format files for forwarded syscalls
//! 2. Run codegen with the fetched tracefs dir to regenerate kmod C files
//! 3. Build kmod + Rust workspace on the remote, deploy binaries
//!
//! The runner does NOT (yet) launch rsbeacon / rscaller-run for you — once
//! deploy completes use scripts/run-image.sh or wire up the long-running
//! containers manually.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rscaller-runner", about = "Full rscaller deploy + run pipeline")]
struct Args {
    /// SSH target (e.g. dev-vm-rscaller)
    host: String,

    /// Container image to run (passed through to run-image.sh by caller)
    #[arg(long, default_value = "alpine:latest")]
    image: String,

    /// Beacon listen address
    #[arg(long, default_value = "0.0.0.0:9999")]
    beacon: String,

    /// Command to run in container
    #[arg(trailing_var_arg = true, default_value = "/bin/sh")]
    cmd: Vec<String>,

    /// Remote rscaller directory
    #[arg(long, default_value = "/home/ubuntu/rscaller")]
    remote_dir: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let _ = (&args.image, &args.beacon, &args.cmd); // reserved for future direct launch

    // 1. Fetch tracefs format files from the remote VM
    let tracefs_dir = fetch_tracefs_formats(&args.host)?;

    // 2. Regenerate kmod C files with the freshly snapshotted tracefs
    run_codegen(&tracefs_dir)?;

    // 3. Sync + build + deploy on the remote
    deploy(&args.host, &args.remote_dir)?;

    println!(
        "rscaller-runner: deploy complete. Launch via scripts/run-image.sh \
         {} {} (or insmod + rscaller-run manually).",
        args.host, args.image
    );
    Ok(())
}

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at .../rscaller/rscaller-runner — go up one.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rscaller-runner has a parent directory")
        .to_path_buf()
}

fn fetch_tracefs_formats(host: &str) -> Result<PathBuf> {
    let tmp = std::env::temp_dir().join("rscaller-tracefs");
    // Always start from a clean snapshot.
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).context("create tracefs tmp dir")?;

    let forwarded_path = repo_root().join("files/forwarded_syscalls");
    let forwarded = std::fs::read_to_string(&forwarded_path)
        .with_context(|| format!("read {}", forwarded_path.display()))?;
    let syscalls: Vec<&str> = forwarded
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    println!("==> Fetching tracefs format files from {host}");
    for name in &syscalls {
        let remote_path = format!(
            "/sys/kernel/tracing/events/syscalls/sys_enter_{}/format",
            name
        );
        let local_dir = tmp.join(format!("sys_enter_{}", name));
        std::fs::create_dir_all(&local_dir)?;
        let out = Command::new("ssh")
            .args([host, "cat", &remote_path])
            .output()
            .context("ssh cat tracefs")?;
        if out.status.success() && !out.stdout.is_empty() {
            std::fs::write(local_dir.join("format"), &out.stdout)
                .context("write format file")?;
            println!("    [ok] {name}");
        } else {
            eprintln!(
                "    [warn] {name}: no tracefs format (will fall back to hardcoded)"
            );
        }
    }
    Ok(tmp)
}

fn run_codegen(tracefs_dir: &Path) -> Result<()> {
    let root = repo_root();
    println!("==> Running codegen with tracefs dir: {}", tracefs_dir.display());
    let status = Command::new("cargo")
        .args([
            "run",
            "-p",
            "codegen",
            "--release",
            "--",
            "--tbl-dir",
            "files",
            "--forwarded",
            "files/forwarded_syscalls",
            "--tracefs-dir",
            tracefs_dir.to_str().context("tracefs dir utf8")?,
            "--out",
            "kmod",
        ])
        .current_dir(&root)
        .status()
        .context("spawn codegen")?;
    anyhow::ensure!(status.success(), "codegen failed");
    Ok(())
}

fn deploy(host: &str, remote_dir: &str) -> Result<()> {
    let root = repo_root();
    let script = root.join("scripts/deploy.sh");
    println!("==> Running {} {} {}", script.display(), host, remote_dir);
    let status = Command::new("bash")
        .args([
            script.to_str().context("deploy.sh utf8")?,
            host,
            remote_dir,
        ])
        .status()
        .context("spawn deploy.sh")?;
    anyhow::ensure!(status.success(), "deploy failed");
    Ok(())
}
