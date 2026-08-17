pub mod client;
mod dirent;
pub mod fh;
pub mod fs;
pub mod inode;
pub mod procfs;
pub mod stat;

use anyhow::{Context, Result};
use clap::Parser;
use fuser::MountOption;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use client::{Client, Encryption, Transport};
use fh::FhTable;
use fs::RscFs;
use inode::InodeTable;
use procfs::ProcFs;

#[derive(Parser, Debug, Clone)]
#[command(name = "fuse", about = "FUSE daemon for remote FS access via rsbeacon")]
pub struct FuseArgs {
    /// rsbeacon address (host:port)
    #[arg(long, required_unless_present = "server")]
    pub beacon: Option<String>,

    /// Rendezvous mode: reach the beacon through an rsserver
    /// ([token@]host:port) instead of connecting directly.
    #[arg(long)]
    pub server: Option<String>,

    /// Auth token for rsserver (overridden by token@ in --server).
    #[arg(long)]
    pub auth: Option<String>,

    /// Local mount point
    #[arg(long)]
    pub mount: String,

    /// Filesystem name (shown in `mount` output)
    #[arg(long, default_value = "rscfuse")]
    pub name: String,

    /// Transport: tcp | uds
    #[arg(long, default_value = "tcp")]
    pub transport: String,

    /// Encryption: none | tls
    #[arg(long, default_value = "none")]
    pub encryption: String,

    /// Path to CA cert PEM (required when --encryption tls)
    #[arg(long)]
    pub ca_cert: Option<String>,

    /// Enable merged /proc mode: local PIDs served from real local procfs,
    /// beacon PIDs exposed with a +10_000_000 virtual offset.
    #[arg(long, default_value_t = false)]
    pub merged_proc: bool,
}

pub fn run(args: FuseArgs) -> Result<()> {
    let transport = match args.transport.as_str() {
        "tcp" => Transport::Tcp,
        "uds" => Transport::Uds,
        other => anyhow::bail!("unknown transport {:?}; use tcp or uds", other),
    };

    let encryption = match args.encryption.as_str() {
        "none" => Encryption::None,
        "tls" => {
            let pem = if let Some(path) = &args.ca_cert {
                std::fs::read(path).with_context(|| format!("reading CA cert {:?}", path))?
            } else {
                anyhow::bail!("--ca-cert is required with --encryption tls");
            };
            Encryption::Tls { ca_cert_pem: pem }
        }
        other => anyhow::bail!("unknown encryption {:?}; use none or tls", other),
    };

    let target = if let Some(server) = &args.server {
        if args.transport != "tcp" {
            anyhow::bail!("--server requires tcp transport");
        }
        // Session name = fs name: rsc passes the same --name to rsclient and
        // rscfuse, so both land on the same beacon session.
        rscaller_proto::transport::parse_relay_target(server, args.auth.as_deref(), &args.name)?
    } else {
        let beacon: SocketAddr = args
            .beacon
            .as_deref()
            .context("--beacon is required without --server")?
            .parse()
            .with_context(|| format!("parsing beacon address {:?}", args.beacon))?;
        rscaller_proto::transport::ConnectTarget::Direct(beacon)
    };

    tracing::info!("Connecting to beacon {:?} ...", target);
    let client = Arc::new(Client::new(target, transport, encryption)?);

    // Open a real /proc fd BEFORE mounting. After fuser::mount2 replaces /proc
    // (via bind-mount applied by rsc shell), openat(real_proc_dirfd, …) still
    // traverses the real kernel procfs inode tree, bypassing the FUSE mount.
    let proc_fs = if args.merged_proc {
        let fd = unsafe {
            libc::open(
                b"/proc\0".as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            anyhow::bail!(
                "open /proc for merged-proc mode: {}",
                std::io::Error::last_os_error()
            );
        }
        tracing::info!("Merged /proc mode active: real_proc_dirfd={}", fd);
        Some(ProcFs::new(client.clone(), fd))
    } else {
        None
    };

    let fs = RscFs {
        client,
        inodes: Arc::new(Mutex::new(InodeTable::new())),
        fhs: Arc::new(Mutex::new(FhTable::new())),
        proc_fs,
    };

    let options = vec![
        MountOption::RW,
        MountOption::FSName(args.name.clone()),
        // Required so that block-device nodes under /rsc/<target>/dev can be
        // opened by consumers like QEMU's raw disk driver.
        MountOption::Dev,
        // Libvirt/QEMU may run as a dedicated user (libvirt-qemu) rather than
        // the mounter; allow_other is required for any non-mounter access.
        MountOption::AllowOther,
    ];

    tracing::info!("Mounting FUSE fs at {} ...", args.mount);
    fuser::mount2(fs, &args.mount, &options)
        .with_context(|| format!("mounting FUSE fs at {:?}", args.mount))?;

    tracing::info!("Unmounted.");
    Ok(())
}
