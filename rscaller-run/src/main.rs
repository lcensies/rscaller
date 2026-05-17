//! rscaller-run — run a command with syscalls forwarded to a remote rsbeacon.
//!
//! Two filter modes:
//!   --image <ref>          start a container, filter by cgroup namespace inode
//!   --progs-folder <path>  filter by host binary path prefix (no container)

use anyhow::{Context, Result};
use clap::Parser;
use std::process::Stdio;

#[derive(Parser)]
#[command(name = "rscaller-run")]
struct Args {
    /// OCI image reference (e.g. "alpine:latest") — enables container+cgns mode
    #[arg(long)]
    image: Option<String>,

    /// Host path prefix whose binaries get forwarded (e.g. /opt/my-progs) — no container
    #[arg(long)]
    progs_folder: Option<String>,

    /// Container runtime backend: "auto", "docker", "podman" (only with --image)
    #[arg(long, default_value = "auto")]
    backend: String,

    /// rsbeacon address (host:port)
    #[arg(long, default_value = "127.0.0.1:9999")]
    beacon: String,

    /// Path to rscaller proc entry
    #[arg(long, default_value = "/proc/rscaller")]
    proc_path: String,

    /// Command to run (container exec for --image, direct spawn for --progs-folder)
    #[arg(last = true)]
    cmd: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match (args.image.clone(), args.progs_folder.clone()) {
        (Some(_), Some(_)) => anyhow::bail!("--image and --progs-folder are mutually exclusive"),
        (None, None)       => anyhow::bail!("one of --image or --progs-folder is required"),
        (Some(image), None) => run_image(args, image).await,
        (None, Some(folder)) => run_progs_folder(args, folder).await,
    }
}

async fn spawn_rsclient(beacon: &str, proc_path: &str) -> Result<std::process::Child> {
    let rsclient_path = std::env::current_exe()?
        .parent().unwrap()
        .join("rsclient");
    let child = std::process::Command::new(&rsclient_path)
        .arg("--beacon").arg(beacon)
        .arg("--proc-path").arg(proc_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create("/tmp/rsclient-run.log")
            .context("creating rsclient log")?)
        .spawn()
        .with_context(|| format!("spawning rsclient from {:?}", rsclient_path))?;
    println!("rsclient relay started (pid {})", child.id());
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Ok(child)
}

async fn run_image(args: Args, image: String) -> Result<()> {
    let backend = match args.backend.as_str() {
        "docker" => ociman::backend::resolve::docker().await?,
        "podman" => ociman::backend::resolve::podman().await?,
        _        => ociman::backend::resolve::auto().await?,
    };

    let reference: ociman::Reference = image.parse()
        .map_err(anyhow::Error::msg)
        .context("parsing image reference")?;
    backend.pull_image_if_absent(&reference).await.context("pulling image")?;

    let mut container = ociman::Definition::new(backend, reference)
        .entrypoint("sleep")
        .argument("infinity")
        .run_detached()
        .await;

    // Get container PID, then stat its cgroup namespace to get the inode
    let pid_str = container.inspect_format("{{.State.Pid}}").await
        .context("getting container PID")?;
    let container_pid: u64 = pid_str.trim().parse()
        .with_context(|| format!("parsing container PID: {:?}", pid_str))?;

    let cgns_path = format!("/proc/{}/ns/cgroup", container_pid);
    let cgns_meta = std::fs::metadata(&cgns_path)
        .with_context(|| format!("stat {}", cgns_path))?;
    use std::os::unix::fs::MetadataExt;
    let cgns_inum = cgns_meta.ino();
    println!("Container PID: {}, cgroup ns inode: {}", container_pid, cgns_inum);

    let cgns_param = "/sys/module/rscaller/parameters/container_cgns_inum";
    std::fs::write(cgns_param, cgns_inum.to_string())
        .with_context(|| format!("writing cgns inum to {}", cgns_param))?;
    println!("Set container_cgns_inum = {}", cgns_inum);

    let mut rsclient = spawn_rsclient(&args.beacon, &args.proc_path).await?;

    let cmd = if args.cmd.is_empty() { vec!["/bin/sh".to_string()] } else { args.cmd };
    let mut exec = container.exec(&cmd[0]);
    for arg in &cmd[1..] { exec = exec.argument(arg); }
    let status = exec.tty().interactive().status().await;

    let _ = rsclient.kill(); let _ = rsclient.wait();
    let _ = container.stop().await; let _ = container.remove().await;
    let _ = std::fs::write(cgns_param, "0");

    status.context("container exec failed")
}

async fn run_progs_folder(args: Args, folder: String) -> Result<()> {
    let param = "/sys/module/rscaller/parameters/remote_progs_folder";
    std::fs::write(param, &folder)
        .with_context(|| format!("writing '{}' to {}", folder, param))?;
    println!("Set remote_progs_folder = {}", folder);

    let mut rsclient = spawn_rsclient(&args.beacon, &args.proc_path).await?;

    let cmd = if args.cmd.is_empty() { vec!["/bin/sh".to_string()] } else { args.cmd };
    let status = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .status()
        .with_context(|| format!("spawning {:?}", cmd))?;

    let _ = rsclient.kill(); let _ = rsclient.wait();
    let _ = std::fs::write(param, "");

    if status.success() { Ok(()) } else {
        anyhow::bail!("command exited with {}", status)
    }
}
