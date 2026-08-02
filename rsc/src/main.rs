//! rsc — run binaries/images/shells with syscalls forwarded to a remote rsbeacon.
//!
//! Subcommands:
//!   exec   — run a binary (with optional OCI container or microVM wrapping)
//!   shell  — open an interactive shell forwarded to beacon
//!   deploy — deploy the rscaller stack to a remote host
//!   fuse   — FUSE daemon for remote FS access (spawned internally by exec)

mod exec;
mod deploy;
mod mount_config;
#[cfg(feature = "relay")]
mod relay;
#[cfg(feature = "container")]
mod microvm;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rsc", about = "Run binaries with syscalls forwarded to a remote rsbeacon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a binary with syscalls forwarded to beacon.
    Exec(ExecArgs),
    /// Open an interactive shell forwarded to beacon (shorthand for exec -- $SHELL -i).
    Shell(ShellArgs),
    /// Deploy the rscaller stack to a remote host (tracefs snapshot → codegen → build → sync).
    Deploy(DeployArgs),
    /// FUSE daemon for remote FS access via rsbeacon (spawned internally by exec).
    #[command(hide = true)]
    Fuse(rscfuse::FuseArgs),
}

// ---------------------------------------------------------------------------
// Shared transport flags (used by both exec and shell)
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
pub struct TransportArgs {
    /// rsbeacon address (host:port).
    #[arg(long, default_value = "127.0.0.1:9999")]
    pub beacon: String,

    /// Interception backend: seccomp (default) or kmod (legacy).
    #[arg(long, default_value = "seccomp", hide = true)]
    pub ctl: String,

    /// Transport encryption: none or tls.
    #[arg(long, default_value = "none")]
    pub encryption: String,

    /// Path to CA certificate PEM (required for TLS).
    #[arg(long)]
    pub ca_cert: Option<String>,

    /// rscfuse mount base directory.
    #[arg(long, default_value = "/rsc")]
    pub mount_base: String,

    /// Name for the rscfuse mount subdirectory (default: derived from beacon host).
    #[arg(long)]
    pub name: Option<String>,

    /// Path to rsclient binary (default: rsclient next to rsc).
    #[arg(long, hide = true)]
    pub rsclient: Option<String>,
}

impl TransportArgs {
    pub fn resolve_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| {
            self.beacon.split(':').next().unwrap_or("remote").to_string()
        })
    }

    pub fn rsclient_bin(&self) -> String {
        self.rsclient.clone().unwrap_or_else(|| {
            sibling_bin("rsclient")
        })
    }
}

/// Find a binary that lives next to the current executable.
fn sibling_bin(name: &str) -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .filter(|p| p.exists())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string())
}

// ---------------------------------------------------------------------------
// exec args
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
pub struct ExecArgs {
    #[command(flatten)]
    pub transport: TransportArgs,

    /// OCI image reference (e.g. "alpine:latest") — enables container mode.
    #[arg(long)]
    pub image: Option<String>,

    /// Container runtime backend: auto, docker, or podman (only with --image).
    #[arg(long, default_value = "auto")]
    pub backend: String,

    /// Launch an ephemeral microVM instead of a pre-provisioned host.
    #[arg(long)]
    pub microvm: bool,

    /// microVM hypervisor: auto, qemu, or firecracker.
    #[arg(long, default_value = "auto")]
    pub microvm_backend: String,

    /// Path to guest kernel image (vmlinux / bzImage).
    #[arg(long)]
    pub microvm_kernel: Option<PathBuf>,

    /// Guest RAM in MiB.
    #[arg(long, default_value_t = 512)]
    pub microvm_mem: u32,

    /// Guest vCPU count.
    #[arg(long, default_value_t = 1)]
    pub microvm_cpus: u32,

    /// kmod cgroup parameter path (advanced).
    #[arg(long, default_value = "/sys/module/rscaller/parameters/target_cgroup_ino", hide = true)]
    pub kmod_param: String,

    /// Mount namespace overlay profile: none, recon, relay, shadow, ghost,
    /// qemu-relay, or path to a YAML file. Controls which remote paths are overlaid locally.
    #[arg(long, default_value = "none")]
    pub mount_profile: String,

    /// Directory containing relay VM boot artifacts (vmlinuz, initrd.img, rootfs.img).
    /// Used by the qemu-relay profile.
    #[arg(long)]
    pub relay_artifacts: Option<PathBuf>,

    /// Explicit remote device path for qemu-relay (e.g. /dev/sda1).
    /// If omitted, the first usable block device is discovered automatically.
    #[arg(long)]
    pub relay_device: Option<PathBuf>,

    /// Command and arguments to run.
    #[arg(last = true, required = true)]
    pub cmd: Vec<String>,
}

// ---------------------------------------------------------------------------
// shell args
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
pub struct ShellArgs {
    #[command(flatten)]
    pub transport: TransportArgs,

    /// OCI image reference — run shell inside a container.
    #[arg(long)]
    pub image: Option<String>,

    /// Container runtime backend.
    #[arg(long, default_value = "auto")]
    pub backend: String,

    /// Launch shell inside an ephemeral microVM.
    #[arg(long)]
    pub microvm: bool,

    #[arg(long, default_value = "auto")]
    pub microvm_backend: String,

    #[arg(long)]
    pub microvm_kernel: Option<PathBuf>,

    #[arg(long, default_value_t = 512)]
    pub microvm_mem: u32,

    #[arg(long, default_value_t = 1)]
    pub microvm_cpus: u32,

    /// Mount namespace overlay profile: none, recon, relay, shadow, ghost,
    /// qemu-relay, or path to a YAML file. Controls which remote paths are overlaid locally.
    #[arg(long, default_value = "none")]
    pub mount_profile: String,

    /// Directory containing relay VM boot artifacts (vmlinuz, initrd.img, rootfs.img).
    /// Used by the qemu-relay profile.
    #[arg(long)]
    pub relay_artifacts: Option<PathBuf>,

    /// Explicit remote device path for qemu-relay (e.g. /dev/sda1).
    /// If omitted, the first usable block device is discovered automatically.
    #[arg(long)]
    pub relay_device: Option<PathBuf>,

    /// Source shell rc files (~/.bashrc, /etc/profile, etc.).
    /// Disabled by default when mount-profile is non-none to avoid running
    /// beacon-side shell config that may have traps or unexpected behaviour.
    #[arg(long, default_value_t = false)]
    pub rc: bool,
}

// ---------------------------------------------------------------------------
// deploy args
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
pub struct DeployArgs {
    /// SSH target host (e.g. dev-vm-1).
    pub host: String,

    /// Remote rscaller directory.
    #[arg(long, default_value = "/home/ubuntu/rscaller")]
    pub remote_dir: String,

    /// Skip tracefs snapshot + codegen step.
    #[arg(long)]
    pub skip_codegen: bool,

    /// Skip kmod build step.
    #[arg(long)]
    pub skip_kmod: bool,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    if let Err(e) = dispatch(cli.cmd) {
        eprintln!("rsc: {e:#}");
        std::process::exit(1);
    }
}

fn dispatch(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Exec(args) => {
            let needs_async = args.image.is_some() || args.microvm;
            if needs_async {
                #[cfg(feature = "container")]
                return tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(exec::run_exec_async(args));
                #[cfg(not(feature = "container"))]
                anyhow::bail!("--image and --microvm require the 'container' feature");
            }
            exec::run_exec_sync(args)
        }
        Cmd::Shell(args) => {
            let needs_async = args.image.is_some() || args.microvm;
            if needs_async {
                #[cfg(feature = "container")]
                return tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(exec::run_shell_async(args));
                #[cfg(not(feature = "container"))]
                anyhow::bail!("--image and --microvm require the 'container' feature");
            }
            exec::run_shell_sync(args)
        }
        Cmd::Deploy(args) => deploy::run_deploy(args),
        Cmd::Fuse(args) => {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env()
                        .add_directive("rscfuse=debug".parse()?),
                )
                .init();
            rscfuse::run(args)
        }
    }
}
