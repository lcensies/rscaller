use anyhow::{Context, Result};
use clap::Parser;
use fuser::MountOption;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

mod client;
mod dirent;
mod fh;
mod fs;
mod inode;
mod stat;

use client::{Client, Encryption, Transport};
use fh::FhTable;
use fs::RscFs;
use inode::InodeTable;

#[derive(Parser, Debug)]
#[command(name = "rscfuse", about = "FUSE daemon for remote FS access via rsbeacon")]
struct Args {
    /// rsbeacon address (host:port)
    #[arg(long)]
    beacon: String,

    /// Local mount point
    #[arg(long)]
    mount: String,

    /// Filesystem name (shown in `mount` output)
    #[arg(long, default_value = "rscfuse")]
    name: String,

    /// Transport: tcp | uds
    #[arg(long, default_value = "tcp")]
    transport: String,

    /// Encryption: none | tls
    #[arg(long, default_value = "none")]
    encryption: String,

    /// Path to CA cert PEM (required when --encryption tls)
    #[arg(long)]
    ca_cert: Option<String>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rscfuse=debug".parse()?),
        )
        .init();

    let args = Args::parse();

    // Parse transport.
    let transport = match args.transport.as_str() {
        "tcp" => Transport::Tcp,
        "uds" => Transport::Uds,
        other => anyhow::bail!("unknown transport {:?}; use tcp or uds", other),
    };

    // Parse encryption.
    let encryption = match args.encryption.as_str() {
        "none" => Encryption::None,
        "tls" => {
            let pem = if let Some(path) = &args.ca_cert {
                std::fs::read(path).with_context(|| format!("reading CA cert {:?}", path))?
            } else {
                // Fall back to embedded ca.pem distributed with rsbeacon.
                // In a real deployment this would be baked in at build time;
                // for now error if not provided.
                anyhow::bail!("--ca-cert is required with --encryption tls");
            };
            Encryption::Tls { ca_cert_pem: pem }
        }
        other => anyhow::bail!("unknown encryption {:?}; use none or tls", other),
    };

    // Resolve beacon address.
    let beacon: SocketAddr = args
        .beacon
        .parse()
        .with_context(|| format!("parsing beacon address {:?}", args.beacon))?;

    tracing::info!("Connecting to beacon {} ...", beacon);
    let client = Arc::new(Client::new(beacon, transport, encryption)?);

    let fs = RscFs {
        client,
        inodes: Arc::new(Mutex::new(InodeTable::new())),
        fhs: Arc::new(Mutex::new(FhTable::new())),
    };

    let mount_point = &args.mount;
    let options = vec![
        MountOption::RW,
        MountOption::FSName(args.name.clone()),
        MountOption::AutoUnmount,
        MountOption::AllowOther,
    ];

    tracing::info!("Mounting FUSE fs at {} ...", mount_point);

    // fuser::mount2 blocks until the filesystem is unmounted.
    // SIGINT/SIGTERM trigger AutoUnmount via the kernel.
    fuser::mount2(fs, mount_point, &options)
        .with_context(|| format!("mounting FUSE fs at {:?}", mount_point))?;

    tracing::info!("Unmounted.");
    Ok(())
}
