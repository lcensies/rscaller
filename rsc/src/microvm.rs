//! microVM support for rscaller-run.
//!
//! Launches an ephemeral QEMU microVM, injects rsbeacon into the rootfs,
//! waits for rsbeacon to be reachable, then returns a handle whose `Drop`
//! kills the VM and cleans up.
//!
//! # MVP scope
//! - QEMU backend with user-mode networking (no root/tap required)
//! - OCI image → ext4 rootfs via `docker export` + `mkfs.ext4 -d`
//! - rsbeacon binary injected from host at `<rootfs>/usr/local/bin/rsbeacon`
//! - Port-forwarded rsbeacon on a randomly-chosen host port
//!
//! # Not yet implemented
//! - Firecracker backend (see TODO below)
//! - tap networking
//! - Virtio-vsock transport

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::process::Command;

// ── public types ─────────────────────────────────────────────────────────────

/// Backend selection for the microVM hypervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MicroVmBackend {
    /// Prefer Firecracker; fall back to QEMU if not found.
    Auto,
    /// QEMU microvm machine type with user-mode networking.
    Qemu,
    /// TODO: Firecracker — not yet implemented.
    Firecracker,
}

impl std::str::FromStr for MicroVmBackend {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "auto"        => Ok(Self::Auto),
            "qemu"        => Ok(Self::Qemu),
            "firecracker" => Ok(Self::Firecracker),
            other         => bail!("unknown microvm backend {:?}; choose auto|qemu|firecracker", other),
        }
    }
}

/// Configuration for the microVM launch.
#[derive(Debug, Clone)]
pub struct MicroVmConfig {
    /// Resolved backend (after auto-detection).
    pub backend: MicroVmBackend,
    /// Path to guest kernel (uncompressed vmlinux or bzImage).
    pub kernel: PathBuf,
    /// Guest RAM in MiB.
    pub mem_mb: u32,
    /// vCPU count.
    pub cpus: u32,
    /// Seconds to wait for rsbeacon TCP port to open.
    pub beacon_timeout_secs: u64,
}

/// A running microVM instance.
///
/// Holds the QEMU child process, temp directory (rootfs), and the
/// host TCP port on which rsbeacon is reachable via QEMU's port-forward.
/// Dropping this struct kills the VM and removes the scratch directory.
pub struct MicroVmHandle {
    /// Host port forwarded to guest :9999.
    pub host_port: u16,
    child: tokio::process::Child,
    scratch_dir: PathBuf,
}

impl Drop for MicroVmHandle {
    fn drop(&mut self) {
        // Best-effort: kill the QEMU process.
        if let Err(e) = self.child.start_kill() {
            eprintln!("[microvm] warning: failed to kill QEMU: {e}");
        }
        // Remove scratch dir (rootfs + ext4 image).
        if let Err(e) = std::fs::remove_dir_all(&self.scratch_dir) {
            eprintln!("[microvm] warning: failed to remove scratch dir {:?}: {e}", self.scratch_dir);
        }
    }
}

// ── public entry point ────────────────────────────────────────────────────────

/// Launch a microVM for the given OCI image reference.
///
/// Steps:
/// 1. Resolve backend (auto-detect QEMU/Firecracker binary).
/// 2. Export OCI image to a tmpdir via `docker export`.
/// 3. Inject rsbeacon binary and a minimal init wrapper.
/// 4. Pack tmpdir → ext4 image with `mkfs.ext4 -d`.
/// 5. Spawn QEMU with user-mode net port-forward.
/// 6. Poll TCP until rsbeacon answers.
///
/// Returns a `MicroVmHandle` whose drop kills the VM + cleans up.
pub async fn launch_microvm(cfg: &MicroVmConfig, image: &str) -> Result<MicroVmHandle> {
    let backend = resolve_backend(&cfg.backend)?;
    println!("[microvm] backend: {:?}", backend);

    // 1. Create scratch dir.
    let scratch = create_scratch_dir().context("creating microvm scratch dir")?;
    println!("[microvm] scratch dir: {:?}", scratch);

    // 2. Export OCI image → rootfs dir.
    let rootfs_dir = scratch.join("rootfs");
    std::fs::create_dir_all(&rootfs_dir).context("creating rootfs dir")?;
    export_oci_image(image, &rootfs_dir).await
        .context("exporting OCI image to rootfs")?;

    // 3. Inject rsbeacon + init wrapper.
    inject_rsbeacon(&rootfs_dir).await
        .context("injecting rsbeacon into rootfs")?;
    write_init_wrapper(&rootfs_dir)
        .context("writing init wrapper")?;

    // 4. Pack to ext4.
    let rootfs_img = scratch.join("rootfs.img");
    pack_ext4(&rootfs_dir, &rootfs_img).await
        .context("packing rootfs to ext4")?;

    // 5. Choose a free host port.
    let host_port = free_tcp_port().context("finding free TCP port")?;
    println!("[microvm] rsbeacon will be reachable on 127.0.0.1:{}", host_port);

    // 6. Spawn QEMU.
    let child = match backend {
        MicroVmBackend::Qemu => {
            spawn_qemu(cfg, &cfg.kernel, &rootfs_img, host_port).await
                .context("spawning QEMU microVM")?
        }
        MicroVmBackend::Firecracker => {
            // TODO: implement Firecracker backend.
            // Firecracker requires a tap device (root) and its own REST API.
            bail!("Firecracker backend is not yet implemented; use --microvm-backend qemu");
        }
        MicroVmBackend::Auto => unreachable!("resolve_backend always returns Qemu or Firecracker"),
    };

    // 7. Wait for rsbeacon to be reachable.
    let addr = format!("127.0.0.1:{}", host_port);
    wait_for_tcp(&addr, Duration::from_secs(cfg.beacon_timeout_secs)).await
        .with_context(|| format!("rsbeacon not reachable at {} after {}s",
                                  addr, cfg.beacon_timeout_secs))?;
    println!("[microvm] rsbeacon ready at {}", addr);

    Ok(MicroVmHandle { host_port, child, scratch_dir: scratch })
}

// ── backend resolution ────────────────────────────────────────────────────────

fn resolve_backend(requested: &MicroVmBackend) -> Result<MicroVmBackend> {
    match requested {
        MicroVmBackend::Auto => {
            // Prefer Firecracker but it's not implemented yet; always use QEMU.
            if which("qemu-system-x86_64") {
                println!("[microvm] auto-selected QEMU (firecracker backend not yet implemented)");
                Ok(MicroVmBackend::Qemu)
            } else {
                bail!("neither qemu-system-x86_64 nor firecracker found in PATH; \
                       install QEMU or pass --microvm-backend explicitly");
            }
        }
        MicroVmBackend::Qemu => {
            if !which("qemu-system-x86_64") {
                bail!("qemu-system-x86_64 not found in PATH");
            }
            Ok(MicroVmBackend::Qemu)
        }
        MicroVmBackend::Firecracker => {
            bail!("Firecracker backend is not yet implemented; use --microvm-backend qemu");
        }
    }
}

fn which(binary: &str) -> bool {
    std::process::Command::new("which")
        .arg(binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── scratch dir ───────────────────────────────────────────────────────────────

fn create_scratch_dir() -> Result<PathBuf> {
    let base = std::env::temp_dir().join(format!("rscaller-microvm-{}", std::process::id()));
    std::fs::create_dir_all(&base)
        .with_context(|| format!("mkdir {:?}", base))?;
    Ok(base)
}

// ── OCI image export ──────────────────────────────────────────────────────────

/// Export OCI image layers to `rootfs_dir` via `docker export`.
///
/// Creates a temporary container, exports its filesystem as a tar,
/// extracts into `rootfs_dir`, then removes the container.
async fn export_oci_image(image: &str, rootfs_dir: &Path) -> Result<()> {
    println!("[microvm] creating temporary container from image {}", image);

    // Pull image if needed.
    run_command("docker", &["pull", image])
        .await
        .context("docker pull")?;

    // Create (but don't start) a container to get its merged filesystem.
    let output = Command::new("docker")
        .args(["create", "--name", "rscaller-microvm-export", image, "/bin/true"])
        .output()
        .await
        .context("docker create")?;
    if !output.status.success() {
        // Container might already exist from a crashed previous run; remove and retry.
        let _ = Command::new("docker")
            .args(["rm", "-f", "rscaller-microvm-export"])
            .output().await;
        let output2 = Command::new("docker")
            .args(["create", "--name", "rscaller-microvm-export", image, "/bin/true"])
            .output().await
            .context("docker create (retry)")?;
        if !output2.status.success() {
            bail!("docker create failed: {}", String::from_utf8_lossy(&output2.stderr));
        }
    }

    println!("[microvm] exporting container filesystem…");

    // `docker export` → pipe into `tar x` in rootfs_dir.
    // Use std::process (not tokio) so ChildStdout converts directly into Stdio.
    let mut export = std::process::Command::new("docker")
        .args(["export", "rscaller-microvm-export"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("spawn docker export")?;

    let export_stdout = export.stdout.take().context("docker export stdout")?;

    let tar = Command::new("tar")
        .args(["-xf", "-"])
        .current_dir(rootfs_dir)
        .stdin(export_stdout)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .context("tar extract")?;

    // Wait for docker export to finish too.
    let _ = export.wait();

    // Clean up the temporary container regardless of tar outcome.
    let _ = Command::new("docker")
        .args(["rm", "-f", "rscaller-microvm-export"])
        .output().await;

    if !tar.success() {
        bail!("tar extraction failed with {}", tar);
    }

    println!("[microvm] OCI rootfs extracted to {:?}", rootfs_dir);
    Ok(())
}

// ── rsbeacon injection ────────────────────────────────────────────────────────

/// Copy the host rsbeacon binary into the rootfs.
///
/// Looks for rsbeacon next to the current executable first, then on PATH.
async fn inject_rsbeacon(rootfs_dir: &Path) -> Result<()> {
    let rsbeacon_src = find_rsbeacon()?;
    let dst_dir = rootfs_dir.join("usr/local/bin");
    std::fs::create_dir_all(&dst_dir)
        .context("creating /usr/local/bin in rootfs")?;
    let dst = dst_dir.join("rsbeacon");
    std::fs::copy(&rsbeacon_src, &dst)
        .with_context(|| format!("copying rsbeacon {:?} → {:?}", rsbeacon_src, dst))?;
    // Make executable.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))
        .context("chmod rsbeacon")?;
    println!("[microvm] injected rsbeacon from {:?}", rsbeacon_src);
    Ok(())
}

fn find_rsbeacon() -> Result<PathBuf> {
    // 1. Sibling of current executable.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join("rsbeacon");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    // 2. Cargo target/release (for dev builds).
    let manifest_dir_candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/release/rsbeacon");
    if manifest_dir_candidate.exists() {
        return Ok(manifest_dir_candidate);
    }
    // 3. PATH.
    let out = std::process::Command::new("which")
        .arg("rsbeacon")
        .output()
        .context("which rsbeacon")?;
    if out.status.success() {
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    bail!("rsbeacon binary not found; build with `cargo build -p rsbeacon --release` \
           or ensure rsbeacon is on PATH");
}

/// Write a minimal `/init` script that starts rsbeacon then sleeps.
///
/// This is used when the OCI image doesn't have a proper init that would
/// run rsbeacon automatically.  We overwrite `/init` unconditionally so
/// the kernel executes it as PID 1.
fn write_init_wrapper(rootfs_dir: &Path) -> Result<()> {
    let init_path = rootfs_dir.join("init");
    let script = r#"#!/bin/sh
# rscaller microVM init — PID 1
# Mount essential virtual filesystems.
mount -t proc  proc  /proc  2>/dev/null || true
mount -t sysfs sysfs /sys   2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

# Configure loopback.
ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null || true

echo "[microvm-init] starting rsbeacon on 0.0.0.0:9999"
exec /usr/local/bin/rsbeacon --listen 0.0.0.0:9999
"#;
    std::fs::write(&init_path, script)
        .with_context(|| format!("writing {:?}", init_path))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&init_path, std::fs::Permissions::from_mode(0o755))
        .context("chmod /init")?;
    println!("[microvm] wrote /init wrapper to rootfs");
    Ok(())
}

// ── ext4 packaging ────────────────────────────────────────────────────────────

/// Pack `rootfs_dir` into an ext4 image at `img_path`.
///
/// Uses `mkfs.ext4 -d <dir>` which populates the image from a directory.
/// Image size is the rootfs size rounded up to the next 32 MiB boundary, with
/// a minimum of 128 MiB.
async fn pack_ext4(rootfs_dir: &Path, img_path: &Path) -> Result<()> {
    let size_mb = rootfs_size_mb(rootfs_dir)? + 64; // headroom
    let size_mb = size_mb.max(128);
    // Round up to 32 MiB.
    let size_mb = ((size_mb + 31) / 32) * 32;
    println!("[microvm] packing ext4 image ({}M) from {:?}", size_mb, rootfs_dir);

    // `mkfs.ext4 -d <dir> <image> <size>M`
    let status = Command::new("mkfs.ext4")
        .arg("-d").arg(rootfs_dir)
        .arg("-L").arg("rootfs")
        .arg(img_path)
        .arg(format!("{}M", size_mb))
        .status()
        .await
        .context("mkfs.ext4")?;

    if !status.success() {
        // Fallback: try genext2fs.
        println!("[microvm] mkfs.ext4 failed; trying genext2fs fallback");
        let status2 = Command::new("genext2fs")
            .arg("-d").arg(rootfs_dir)
            .arg("-b").arg(format!("{}", size_mb * 1024))
            .arg(img_path)
            .status()
            .await
            .context("genext2fs")?;
        if !status2.success() {
            bail!("both mkfs.ext4 and genext2fs failed; install e2fsprogs or genext2fs");
        }
    }

    println!("[microvm] ext4 image ready: {:?}", img_path);
    Ok(())
}

/// Returns the on-disk size of a directory tree in MiB (rounded up).
fn rootfs_size_mb(dir: &Path) -> Result<u64> {
    let output = std::process::Command::new("du")
        .args(["-sm", "--"])
        .arg(dir)
        .output()
        .context("du -sm")?;
    let line = String::from_utf8_lossy(&output.stdout);
    let mb: u64 = line.split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(256);
    Ok(mb)
}

// ── QEMU launch ───────────────────────────────────────────────────────────────

/// Spawn a QEMU microvm process.
///
/// Uses `-M microvm` for minimal overhead, KVM if available, user-mode
/// networking with a port-forward from `host_port` → guest 9999.
async fn spawn_qemu(
    cfg: &MicroVmConfig,
    kernel: &Path,
    rootfs_img: &Path,
    host_port: u16,
) -> Result<tokio::process::Child> {
    // Log QEMU output to /tmp for debugging.
    let log_path = format!("/tmp/rscaller-qemu-{}.log", std::process::id());
    let log_file = std::fs::File::create(&log_path)
        .with_context(|| format!("creating QEMU log {:?}", log_path))?;
    println!("[microvm] QEMU log: {}", log_path);

    // Detect KVM availability.
    let kvm_args: &[&str] = if Path::new("/dev/kvm").exists() {
        &["-enable-kvm", "-cpu", "host"]
    } else {
        eprintln!("[microvm] warning: /dev/kvm not available; running without KVM (slow)");
        &[]
    };

    let mut cmd = Command::new("qemu-system-x86_64");

    // Machine type: microvm (minimal virtual hardware).
    cmd.args([
        "-M", "microvm,x-option-roms=off,pit=off,pic=off,isa-serial=on,rtc=off",
    ]);

    // KVM + CPU.
    cmd.args(kvm_args);

    // SMP + memory.
    cmd.args([
        "-smp", &cfg.cpus.to_string(),
        "-m",   &format!("{}M", cfg.mem_mb),
    ]);

    // Kernel + boot params.
    // "init=/init" tells the kernel to run our injected init script as PID 1.
    cmd.arg("-kernel").arg(kernel);
    cmd.args([
        "-append",
        "console=ttyS0 root=/dev/vda rw init=/init quiet",
    ]);

    // Rootfs as virtio-blk.
    cmd.args([
        "-drive",
        &format!("id=rootfs,file={},format=raw,if=virtio", rootfs_img.display()),
    ]);

    // User-mode network with port-forward: host:<host_port> → guest:9999.
    cmd.args([
        "-netdev",
        &format!("user,id=net0,hostfwd=tcp::{host_port}-:9999"),
        "-device",
        "virtio-net-device,netdev=net0",
    ]);

    // No graphical output; serial on stdio so we capture it.
    cmd.args(["-nographic", "-serial", "stdio"]);

    let log_stderr = log_file.try_clone().context("clone log fd")?;
    cmd.stdout(log_file)
       .stderr(log_stderr)
       .stdin(std::process::Stdio::null());

    let child = cmd.spawn().context("spawning qemu-system-x86_64")?;
    println!("[microvm] QEMU started (pid {:?})", child.id());
    Ok(child)
}

// ── TCP polling ───────────────────────────────────────────────────────────────

/// Poll `addr` until a TCP connection succeeds or `timeout` elapses.
async fn wait_for_tcp(addr: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut interval = Duration::from_millis(200);
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(_) => {
                if Instant::now() >= deadline {
                    bail!("timed out waiting for {}", addr);
                }
                tokio::time::sleep(interval).await;
                // Back off up to 2s.
                interval = (interval * 2).min(Duration::from_secs(2));
            }
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Find a free TCP port by binding to port 0 and reading the assigned port.
fn free_tcp_port() -> Result<u16> {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").context("binding to get free port")?;
    let port = listener.local_addr().context("local_addr")?.port();
    Ok(port)
}

/// Run a command and return an error if it fails.
async fn run_command(prog: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .with_context(|| format!("running {prog}"))?;
    if !status.success() {
        bail!("{prog} exited with {status}");
    }
    Ok(())
}
