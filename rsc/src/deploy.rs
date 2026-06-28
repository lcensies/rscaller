use crate::DeployArgs;
use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn run_deploy(args: DeployArgs) -> Result<()> {
    if !args.skip_codegen {
        let tracefs_dir = fetch_tracefs_formats(&args.host)?;
        run_codegen(&tracefs_dir)?;
    }
    deploy(&args.host, &args.remote_dir)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rsc has a parent directory")
        .to_path_buf()
}

fn fetch_tracefs_formats(host: &str) -> Result<PathBuf> {
    let tmp = std::env::temp_dir().join("rscaller-tracefs");
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
            eprintln!("    [warn] {name}: no tracefs format (will fall back to hardcoded)");
        }
    }
    Ok(tmp)
}

fn run_codegen(tracefs_dir: &Path) -> Result<()> {
    let root = repo_root();
    println!("==> Running codegen with tracefs dir: {}", tracefs_dir.display());
    let status = Command::new("cargo")
        .args([
            "run", "-p", "codegen", "--release", "--",
            "--tbl-dir", "files",
            "--forwarded", "files/forwarded_syscalls",
            "--tracefs-dir", tracefs_dir.to_str().context("tracefs dir utf8")?,
            "--out", "kmod",
        ])
        .current_dir(&root)
        .status()
        .context("spawn codegen")?;
    ensure!(status.success(), "codegen failed");
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
    ensure!(status.success(), "deploy failed");
    Ok(())
}
