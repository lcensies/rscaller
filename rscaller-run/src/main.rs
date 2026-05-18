//! rscaller-run — run a command with syscalls forwarded to a remote rsbeacon.
//!
//! Two filter modes:
//!   --image <ref>          start a container, filter by cgroup namespace inode
//!   --progs-folder <path>  filter by host binary path prefix (no container)
//!
//! Add `--microvm` to either mode to launch an ephemeral QEMU microVM instead
//! of relying on a pre-provisioned VM.  The microVM boots rsbeacon inside,
//! handles the workload, then is destroyed on exit.

mod microvm;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
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

    /// rsbeacon address (host:port).  Overridden automatically when --microvm is set.
    #[arg(long, default_value = "127.0.0.1:9999")]
    beacon: String,

    /// Path to rscaller proc entry
    #[arg(long, default_value = "/proc/rscaller")]
    proc_path: String,

    // ── microVM flags ──────────────────────────────────────────────────────────

    /// Launch an ephemeral QEMU/Firecracker microVM instead of a pre-provisioned VM.
    /// The microVM boots, runs the workload, then is destroyed on exit.
    #[arg(long)]
    microvm: bool,

    /// microVM hypervisor backend: "auto" (default), "qemu", or "firecracker".
    /// "auto" prefers Firecracker if found, falls back to QEMU.
    #[arg(long, default_value = "auto")]
    microvm_backend: String,

    /// Path to the uncompressed guest kernel (vmlinux / bzImage).
    /// Falls back to the RSCALLER_KERNEL environment variable.
    #[arg(long)]
    microvm_kernel: Option<PathBuf>,

    /// Guest RAM in MiB (default: 512).
    #[arg(long, default_value_t = 512)]
    microvm_mem: u32,

    /// Guest vCPU count (default: 1).
    #[arg(long, default_value_t = 1)]
    microvm_cpus: u32,

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

// ── microVM helper ────────────────────────────────────────────────────────────

/// Build `MicroVmConfig` from parsed CLI args, launch the VM, and return the
/// effective beacon address (`127.0.0.1:<host_port>`).
async fn maybe_launch_microvm(
    args: &Args,
    image: &str,
) -> Result<Option<(microvm::MicroVmHandle, String)>> {
    if !args.microvm {
        return Ok(None);
    }

    // Resolve the guest kernel path.
    let kernel = args.microvm_kernel.clone()
        .or_else(|| std::env::var("RSCALLER_KERNEL").ok().map(PathBuf::from))
        .context("--microvm requires a guest kernel path; \
                  pass --microvm-kernel <path> or set RSCALLER_KERNEL")?;

    let backend: microvm::MicroVmBackend = args.microvm_backend.parse()
        .context("parsing --microvm-backend")?;

    let cfg = microvm::MicroVmConfig {
        backend,
        kernel,
        mem_mb: args.microvm_mem,
        cpus: args.microvm_cpus,
        beacon_timeout_secs: 60,
    };

    let handle = microvm::launch_microvm(&cfg, image).await?;
    let beacon_addr = format!("127.0.0.1:{}", handle.host_port);
    Ok(Some((handle, beacon_addr)))
}

// ── run_image ─────────────────────────────────────────────────────────────────

async fn run_image(args: Args, image: String) -> Result<()> {
    // Launch microVM if requested, overriding the beacon address.
    let (beacon, _vm_handle) = if args.microvm {
        let (handle, addr) = maybe_launch_microvm(&args, &image)
            .await?
            .expect("microvm=true guaranteed Some");
        (addr, Some(handle))
    } else {
        (args.beacon.clone(), None)
    };
    // _vm_handle dropped at end of scope → kills microVM.

    let backend = match args.backend.as_str() {
        "docker" => ociman::backend::resolve::docker().await?,
        "podman" => ociman::backend::resolve::podman().await?,
        _        => ociman::backend::resolve::auto().await?,
    };

    let reference: ociman::Reference = image.parse()
        .map_err(anyhow::Error::msg)
        .context("parsing image reference")?;
    backend.pull_image_if_absent(&reference).await.context("pulling image")?;

    // Notify dir bind-mounted into container. Container writes "ready" file inside it.
    let notify_dir = "/tmp/rscaller-notify-dir".to_string();
    std::fs::create_dir_all(&notify_dir).context("creating notify dir")?;
    let notify_flag = format!("{}/ready", notify_dir);
    let _ = std::fs::remove_file(&notify_flag);

    let mut container = ociman::Definition::new(backend, reference)
        .entrypoint("sleep")
        .argument("infinity")
        .mount(ociman::container::Mount::from(
            format!("type=bind,source={},target=/run/rscaller-notify", notify_dir)
        ))
        .run_detached()
        .await;

    // Get container PID, then stat its cgroup namespace to get the inode.
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

    let mut rsclient = spawn_rsclient(&beacon, &args.proc_path).await?;

    // Background task: wait for container to write ready flag, then enable forwarding.
    let notify_flag_clone = notify_flag.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if std::path::Path::new(&notify_flag_clone).exists() {
                let _ = std::fs::write(
                    "/sys/module/rscaller/parameters/forwarding_enabled", "1");
                println!("Forwarding enabled.");
                break;
            }
        }
    });

    let cmd = if args.cmd.is_empty() { vec!["/bin/sh".to_string()] } else { args.cmd };
    let wrapped = format!(
        "touch /run/rscaller-notify/ready && sleep 0.2 && exec {}",
        cmd.iter().map(|a| shell_escape(a)).collect::<Vec<_>>().join(" ")
    );
    let mut exec = container.exec("/bin/sh");
    exec = exec.argument("-c").argument(&wrapped);
    let status = exec.tty().interactive().status().await;

    let _ = rsclient.kill(); let _ = rsclient.wait();
    let _ = std::fs::write("/sys/module/rscaller/parameters/forwarding_enabled", "0");
    let _ = std::fs::remove_dir_all(&notify_dir);
    let _ = container.stop().await; let _ = container.remove().await;
    let _ = std::fs::write(cgns_param, "0");
    // _vm_handle dropped here → microVM killed + scratch dir removed.

    status.context("container exec failed")
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
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
