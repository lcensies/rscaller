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

    /// Target name for /rsc/<name>/ path routing (defaults to beacon hostname)
    #[arg(long)]
    name: Option<String>,

    /// Transport for rsclient/rscfuse: tcp|uds
    #[arg(long, default_value = "tcp")]
    transport: String,

    /// Encryption for rsclient/rscfuse: none|tls
    #[arg(long, default_value = "tls")]
    encryption: String,

    /// Path to CA cert PEM (required for TLS unless default path exists)
    #[arg(long)]
    ca_cert: Option<String>,

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

async fn spawn_rsclient(beacon: &str, proc_path: &str, name: Option<&str>) -> Result<std::process::Child> {
    let rsclient_path = std::env::current_exe()?
        .parent().unwrap()
        .join("rsclient");
    let mut cmd = std::process::Command::new(&rsclient_path);
    cmd.arg("--beacon").arg(beacon)
        .arg("--proc-path").arg(proc_path)
        .env("RUST_LOG", "debug")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create("/tmp/rsclient-run.log")
            .context("creating rsclient log")?);
    if let Some(n) = name {
        cmd.arg("--name").arg(n);
    }
    let child = cmd.spawn()
        .with_context(|| format!("spawning rsclient from {:?}", rsclient_path))?;
    println!("rsclient relay started (pid {})", child.id());
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Ok(child)
}

async fn spawn_rscfuse(
    beacon: &str,
    mount_path: &str,
    name: &str,
    transport: &str,
    encryption: &str,
    ca_cert: Option<&str>,
) -> Result<std::process::Child> {
    let rscfuse_path = std::env::current_exe()?
        .parent().unwrap()
        .join("rscfuse");

    let log_file = std::fs::File::create("/tmp/rscfuse.log").context("rscfuse log")?;
    let log_file2 = log_file.try_clone().context("rscfuse log clone")?;

    let mut cmd = std::process::Command::new(&rscfuse_path);
    cmd.arg("--beacon").arg(beacon)
       .arg("--mount").arg(mount_path)
       .arg("--name").arg(name)
       .arg("--transport").arg(transport)
       .arg("--encryption").arg(encryption)
       .env("RUST_LOG", "info")
       .stdout(log_file)
       .stderr(log_file2);

    if let Some(ca) = ca_cert {
        cmd.arg("--ca-cert").arg(ca);
    }

    let child = cmd.spawn()
        .with_context(|| format!("spawning rscfuse from {:?}", rscfuse_path))?;
    println!("rscfuse started (pid {})", child.id());
    Ok(child)
}

fn derive_name(args: &Args) -> String {
    args.name.clone().unwrap_or_else(|| {
        args.beacon.split(':').next().unwrap_or("remote").to_string()
    })
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

    // Notify dir bind-mounted into container. Container writes "ready" file inside it.
    // (Docker creates target as directory; file-to-file bind-mounts don't work reliably.)
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

    let derived_name = derive_name(&args);
    let mut rsclient = spawn_rsclient(&args.beacon, &args.proc_path, Some(&derived_name)).await?;

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

    // Launch rscfuse and bind-mount into container
    let fuse_host_mount = format!("/tmp/rscfuse-{}", derived_name);
    std::fs::create_dir_all(&fuse_host_mount).ok();
    let mut rscfuse = spawn_rscfuse(
        &args.beacon,
        &fuse_host_mount,
        &derived_name,
        &args.transport,
        &args.encryption,
        args.ca_cert.as_deref(),
    ).await?;

    // Wait for FUSE mount to become ready (poll: different device than /tmp parent)
    let fuse_ready = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        async {
            loop {
                let parent_dev = std::fs::metadata("/tmp")
                    .ok().map(|m| { use std::os::unix::fs::MetadataExt; m.dev() });
                let mount_dev = std::fs::metadata(&fuse_host_mount)
                    .ok().map(|m| { use std::os::unix::fs::MetadataExt; m.dev() });
                if parent_dev.is_some() && mount_dev.is_some() && parent_dev != mount_dev {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        },
    ).await;
    if fuse_ready.is_err() {
        eprintln!("Warning: rscfuse mount not ready after 10s, continuing anyway");
    }

    // Bind-mount rscfuse into container mount namespace
    let container_mount_point = format!("/rsc/{}", derived_name);
    // Create mount point inside container via nsenter
    let _ = std::process::Command::new("nsenter")
        .args([
            &format!("--mount=/proc/{}/ns/mnt", container_pid),
            "--",
            "mkdir", "-p", &container_mount_point,
        ])
        .status();
    // Bind-mount
    let _ = std::process::Command::new("nsenter")
        .args([
            &format!("--mount=/proc/{}/ns/mnt", container_pid),
            "--",
            "mount", "--bind", &fuse_host_mount, &container_mount_point,
        ])
        .status();
    println!("rscfuse bind-mounted at container:{}", container_mount_point);

    let cmd = if args.cmd.is_empty() { vec!["/bin/sh".to_string()] } else { args.cmd };
    // Wrapper: create ready flag (runc is done), wait for host to enable forwarding,
    // then exec the real command.
    let wrapped = format!(
        "touch /run/rscaller-notify/ready && sleep 0.2 && exec {}",
        cmd.iter().map(|a| shell_escape(a)).collect::<Vec<_>>().join(" ")
    );
    let mut exec = container.exec("/bin/sh");
    exec = exec.argument("-c").argument(&wrapped);
    let status = exec.tty().interactive().status().await;

    let _ = rscfuse.kill(); let _ = rscfuse.wait();
    // Lazy unmount the fuse host mount
    let _ = std::process::Command::new("umount")
        .args(["-l", &fuse_host_mount])
        .status();
    let _ = std::fs::remove_dir(&fuse_host_mount);
    let _ = rsclient.kill(); let _ = rsclient.wait();
    let _ = std::fs::write("/sys/module/rscaller/parameters/forwarding_enabled", "0");
    let _ = std::fs::remove_dir_all(&notify_dir);
    let _ = container.stop().await; let _ = container.remove().await;
    let _ = std::fs::write(cgns_param, "0");

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

    let derived_name = derive_name(&args);
    let mut rsclient = spawn_rsclient(&args.beacon, &args.proc_path, Some(&derived_name)).await?;

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
