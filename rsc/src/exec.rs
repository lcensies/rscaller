use crate::{ExecArgs, ShellArgs, TransportArgs};
use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const CGROUP_BASE: &str = "/sys/fs/cgroup/rscaller";

// ---------------------------------------------------------------------------
// Public sync API
// ---------------------------------------------------------------------------

pub fn run_exec_sync(args: ExecArgs) -> Result<()> {
    if args.transport.ctl == "kmod" {
        run_kmod(args)
    } else {
        run_seccomp(args)
    }
}

pub fn run_shell_sync(args: ShellArgs) -> Result<()> {
    let cmd = vec![
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()),
        "-i".into(),
    ];
    run_exec_sync(ExecArgs { transport: args.transport, image: args.image, backend: args.backend, microvm: args.microvm, microvm_backend: args.microvm_backend, microvm_kernel: args.microvm_kernel, microvm_mem: args.microvm_mem, microvm_cpus: args.microvm_cpus, kmod_param: String::from("/sys/module/rscaller/parameters/target_cgroup_ino"), cmd })
}

// ---------------------------------------------------------------------------
// Public async API (container feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "container")]
pub async fn run_exec_async(args: ExecArgs) -> Result<()> {
    if let Some(image) = args.image.clone() {
        run_image(args, image).await
    } else if args.microvm {
        run_microvm_progs(args).await
    } else {
        bail!("run_exec_async requires --image or --microvm")
    }
}

#[cfg(feature = "container")]
pub async fn run_shell_async(args: ShellArgs) -> Result<()> {
    let cmd = vec![
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()),
        "-i".into(),
    ];
    run_exec_async(ExecArgs { transport: args.transport, image: args.image, backend: args.backend, microvm: args.microvm, microvm_backend: args.microvm_backend, microvm_kernel: args.microvm_kernel, microvm_mem: args.microvm_mem, microvm_cpus: args.microvm_cpus, kmod_param: String::from("/sys/module/rscaller/parameters/target_cgroup_ino"), cmd }).await
}

// ---------------------------------------------------------------------------
// kmod backend (cgroup-based, legacy)
// ---------------------------------------------------------------------------

fn run_kmod(args: ExecArgs) -> Result<()> {
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        bail!("cgroup v2 unified hierarchy not found — cgroup v1 is not supported");
    }

    if !Path::new(CGROUP_BASE).exists() {
        fs::create_dir(CGROUP_BASE)
            .with_context(|| format!("cannot create {CGROUP_BASE}"))?;
    }

    let uuid = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("rsc-{:032x}", t)
    };

    let cgroup_dir = PathBuf::from(CGROUP_BASE).join(&uuid);
    fs::create_dir(&cgroup_dir)
        .with_context(|| format!("cannot create cgroup {}", cgroup_dir.display()))?;

    if args.cmd.is_empty() {
        bail!("no command specified");
    }
    let cmd = &args.cmd[0];
    let cmd_args = &args.cmd[1..];

    let result = run_kmod_with_cgroup(&cgroup_dir, &args.kmod_param, cmd, cmd_args);

    let _ = write_kmod_param(&args.kmod_param, 0);
    kill_cgroup(&cgroup_dir);
    let _ = fs::remove_dir(&cgroup_dir);
    result
}

fn run_kmod_with_cgroup(
    cgroup_dir: &Path,
    kmod_param: &str,
    cmd: &str,
    cmd_args: &[String],
) -> Result<()> {
    let child_pid = unsafe { libc::fork() };
    match child_pid {
        -1 => bail!("fork failed: {}", std::io::Error::last_os_error()),
        0 => child_exec(cmd, cmd_args),
        pid => {
            let procs = cgroup_dir.join("cgroup.procs");
            fs::write(&procs, format!("{}\n", pid))
                .with_context(|| format!("write {}", procs.display()))?;

            let meta = fs::metadata(cgroup_dir)?;
            let ino = meta.ino();
            eprintln!("rsc: cgroup {} inode={} pid={}", cgroup_dir.display(), ino, pid);

            write_kmod_param(kmod_param, ino)?;
            wait_child(pid)?;
            write_kmod_param(kmod_param, 0)?;
            kill_cgroup(cgroup_dir);
            let _ = fs::remove_dir(cgroup_dir);
        }
    }
    #[allow(unreachable_code)]
    Ok(())
}

// ---------------------------------------------------------------------------
// seccomp backend
// ---------------------------------------------------------------------------

fn run_seccomp(args: ExecArgs) -> Result<()> {
    if args.cmd.is_empty() {
        bail!("no command specified");
    }

    let name = args.transport.resolve_name();
    let mount_point = format!("{}/{}", args.transport.mount_base, name);
    let fuse_pid = launch_rscfuse(
        &args.transport.rscfuse_bin(),
        &args.transport.beacon,
        &args.transport.encryption,
        args.transport.ca_cert.as_deref(),
        &mount_point,
        &name,
    )?;
    eprintln!("rsc: rscfuse mounted at {} (pid {})", mount_point, fuse_pid);

    let mut sv = [0i32; 2];
    let ret = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    };
    if ret != 0 {
        bail!("socketpair: {}", std::io::Error::last_os_error());
    }
    let (parent_sock, child_sock) = (sv[0], sv[1]);

    let child_pid = unsafe { libc::fork() };
    match child_pid {
        -1 => bail!("fork failed: {}", std::io::Error::last_os_error()),
        0 => {
            unsafe { libc::close(parent_sock) };
            let cmd = &args.cmd[0];
            let cmd_args = &args.cmd[1..];
            child_seccomp_exec(child_sock, &vec![62u32], cmd, cmd_args);
        }
        _pid => {
            unsafe { libc::close(child_sock) };
            let notify_fd = recv_fd(parent_sock)
                .context("receiving seccomp notify fd from child")?;
            unsafe { libc::close(parent_sock) };

            eprintln!("rsc: received seccomp notify fd {}", notify_fd);

            exec_rsclient(&args.transport.rsclient_bin(), &args.transport, notify_fd);
        }
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Fork+exec rscfuse in the background and wait until the mount point is live.
///
/// Returns the rscfuse child PID (left as a zombie until rsc exits;
/// AutoUnmount will clean up the FUSE mount on process death).
fn launch_rscfuse(
    bin: &str,
    beacon: &str,
    encryption: &str,
    ca_cert: Option<&str>,
    mount_point: &str,
    name: &str,
) -> Result<libc::pid_t> {
    fs::create_dir_all(mount_point)
        .with_context(|| format!("create mount point {mount_point}"))?;

    let mut argv_strs = vec![
        bin.to_string(),
        "--beacon".to_string(),
        beacon.to_string(),
        "--mount".to_string(),
        mount_point.to_string(),
        "--name".to_string(),
        name.to_string(),
        "--encryption".to_string(),
        encryption.to_string(),
    ];
    if let Some(ca) = ca_cert {
        argv_strs.push("--ca-cert".to_string());
        argv_strs.push(ca.to_string());
    }

    let argv: Vec<CString> = argv_strs
        .iter()
        .map(|s| CString::new(s.as_str()).expect("NUL in rscfuse arg"))
        .collect();
    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let envp: Vec<CString> = std::env::vars()
        .map(|(k, v)| CString::new(format!("{k}={v}")).expect("NUL in env"))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = envp
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => bail!("fork for rscfuse failed: {}", std::io::Error::last_os_error()),
        0 => {
            unsafe { libc::execvpe(argv_ptrs[0], argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
            eprintln!("rsc: exec rscfuse failed: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }
        child_pid => {
            // Poll until mount point is live (up to 3s).
            for _ in 0..30 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if is_mount_point(mount_point) {
                    return Ok(child_pid);
                }
                let mut status = 0;
                let r = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
                if r == child_pid {
                    bail!("rscfuse exited before mount was ready (status {})", status);
                }
            }
            bail!("rscfuse did not mount within 3s at {mount_point}");
        }
    }
}

/// Check if `path` is a mount point by reading `/proc/mounts`.
fn is_mount_point(path: &str) -> bool {
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else {
        return false;
    };
    mounts.lines().any(|l| {
        let mut parts = l.splitn(3, ' ');
        let _dev = parts.next();
        let mp = parts.next().unwrap_or("");
        mp == path
    })
}

/// Child side of the seccomp setup:
/// 1. `prctl(PR_SET_NO_NEW_PRIVS)`
/// 2. Install seccomp BPF filter → get notify fd
/// 3. Send notify fd to parent via SCM_RIGHTS
/// 4. `execvpe` target binary
fn child_seccomp_exec(
    sock: libc::c_int,
    syscall_nrs: &[u32],
    cmd: &str,
    cmd_args: &[String],
) -> ! {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        eprintln!(
            "rsc: prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    let notify_fd = match install_seccomp_filter(syscall_nrs) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("rsc: seccomp filter install failed: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = send_fd(sock, notify_fd) {
        eprintln!("rsc: send_fd failed: {e}");
        std::process::exit(1);
    }
    unsafe { libc::close(sock) };

    child_exec(cmd, cmd_args);
}

/// Install a seccomp BPF filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
/// Returns the notify fd.
fn install_seccomp_filter(syscall_nrs: &[u32]) -> Result<libc::c_int> {
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
    const SYS_SECCOMP: libc::c_long = 317; // x86_64

    let mut insns: Vec<libc::sock_filter> = Vec::new();

    // Load syscall number from seccomp_data.nr (offset 0).
    insns.push(libc::sock_filter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 0 });

    let n = syscall_nrs.len();
    for (i, &nr) in syscall_nrs.iter().enumerate() {
        let jt = (n - i) as u8; // jump to NOTIF past remaining JEQs + ALLOW
        insns.push(libc::sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt, jf: 0, k: nr });
    }

    // Default: allow.
    insns.push(libc::sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW });
    // Matched: notify.
    insns.push(libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_USER_NOTIF,
    });

    let prog = libc::sock_fprog {
        len: insns.len() as u16,
        filter: insns.as_mut_ptr(),
    };

    let fd = unsafe {
        libc::syscall(
            SYS_SECCOMP,
            libc::SECCOMP_SET_MODE_FILTER as libc::c_long,
            SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_long,
            &prog as *const libc::sock_fprog as libc::c_long,
        )
    };

    if fd < 0 {
        bail!(
            "seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER): {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(fd as libc::c_int)
}

/// Send `fd` over `sock` using SCM_RIGHTS ancillary data.
fn send_fd(sock: libc::c_int, fd: libc::c_int) -> Result<()> {
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: &dummy as *const u8 as *mut libc::c_void,
        iov_len: 1,
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        bail!("CMSG_FIRSTHDR returned null");
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len =
            libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        let data_ptr = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
        *data_ptr = fd;
    }

    let ret = unsafe { libc::sendmsg(sock, &msg, 0) };
    if ret < 0 {
        bail!("sendmsg: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// Receive a single fd via SCM_RIGHTS over `sock`.
fn recv_fd(sock: libc::c_int) -> Result<libc::c_int> {
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    let ret = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if ret < 0 {
        bail!("recvmsg: {}", std::io::Error::last_os_error());
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        bail!("no control message received");
    }

    let received_fd = unsafe {
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            bail!("unexpected cmsg level/type");
        }
        *(libc::CMSG_DATA(cmsg) as *const libc::c_int)
    };

    Ok(received_fd)
}

/// Parent side: exec `rsclient --ctl seccomp --notif-fd <fd> [transport flags]`.
///
/// This replaces the parent process image with rsclient.
fn exec_rsclient(rsclient_bin: &str, transport: &TransportArgs, notify_fd: libc::c_int) -> ! {
    let mut argv_strs = vec![
        rsclient_bin.to_string(),
        "--ctl".into(),
        "seccomp".into(),
        "--notif-fd".into(),
        notify_fd.to_string(),
        "--beacon".into(),
        transport.beacon.clone(),
        "--encryption".into(),
        transport.encryption.clone(),
    ];
    if let Some(ca) = &transport.ca_cert {
        argv_strs.push("--ca-cert".into());
        argv_strs.push(ca.clone());
    }

    let argv: Vec<CString> = argv_strs
        .iter()
        .map(|s| CString::new(s.as_str()).expect("NUL in arg"))
        .collect();
    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let envp: Vec<CString> = std::env::vars()
        .map(|(k, v)| CString::new(format!("{k}={v}")).expect("NUL in env"))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = envp
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        libc::execvpe(argv_ptrs[0], argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
    }

    eprintln!("rsc: exec rsclient failed: {}", std::io::Error::last_os_error());
    std::process::exit(127);
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Exec target binary (child side). Never returns on success.
fn child_exec(cmd: &str, args: &[String]) -> ! {
    let argv: Vec<CString> = std::iter::once(cmd)
        .chain(args.iter().map(|s| s.as_str()))
        .map(|s| CString::new(s).expect("NUL in argument"))
        .collect();
    let envp: Vec<CString> = std::env::vars()
        .filter(|(k, _)| k != "RSC_REMOTE")
        .map(|(k, v)| CString::new(format!("{k}={v}")).expect("NUL in env"))
        .collect();

    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = envp
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        libc::execvpe(argv_ptrs[0], argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
    }

    eprintln!("rsc: exec {cmd} failed: {}", std::io::Error::last_os_error());
    std::process::exit(127);
}

fn wait_child(pid: libc::pid_t) -> Result<()> {
    let mut status: libc::c_int = 0;
    loop {
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            bail!("waitpid: {err}");
        }
        break;
    }
    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        if code != 0 {
            bail!("child exited with status {code}");
        }
    } else if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        bail!("child killed by signal {sig}");
    }
    #[allow(unreachable_code)]
    Ok(())
}

fn write_kmod_param(path: &str, value: u64) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("open {path}"))?;
    write!(f, "{value}").with_context(|| format!("write {path}"))?;
    Ok(())
}

fn kill_cgroup(cgroup_dir: &Path) {
    let kill_file = cgroup_dir.join("cgroup.kill");
    if kill_file.exists() {
        let _ = fs::write(&kill_file, "1");
    }
}

// ---------------------------------------------------------------------------
// Container / async helpers (container feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "container")]
fn derive_name(args: &ExecArgs) -> String {
    args.transport.name.clone().unwrap_or_else(|| {
        args.transport.beacon.split(':').next().unwrap_or("remote").to_string()
    })
}

#[cfg(feature = "container")]
async fn spawn_rsclient_async(
    beacon: &str,
    proc_path: &str,
    name: Option<&str>,
) -> Result<std::process::Child> {
    let rsclient_path = std::env::current_exe()?
        .parent()
        .unwrap()
        .join("rsclient");
    let mut cmd = std::process::Command::new(&rsclient_path);
    cmd.arg("--beacon")
        .arg(beacon)
        .arg("--proc-path")
        .arg(proc_path)
        .env("RUST_LOG", "debug")
        .stdout(std::process::Stdio::null())
        .stderr(
            std::fs::File::create("/tmp/rsclient-run.log")
                .context("creating rsclient log")?,
        );
    if let Some(n) = name {
        cmd.arg("--name").arg(n);
    }
    let child = cmd
        .spawn()
        .with_context(|| format!("spawning rsclient from {:?}", rsclient_path))?;
    println!("rsclient relay started (pid {})", child.id());
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Ok(child)
}

#[cfg(feature = "container")]
async fn spawn_rscfuse_async(
    beacon: &str,
    mount_path: &str,
    name: &str,
    transport: &str,
    encryption: &str,
    ca_cert: Option<&str>,
) -> Result<std::process::Child> {
    let rscfuse_path = std::env::current_exe()?
        .parent()
        .unwrap()
        .join("rscfuse");

    let log_file =
        std::fs::File::create("/tmp/rscfuse.log").context("rscfuse log")?;
    let log_file2 = log_file.try_clone().context("rscfuse log clone")?;

    let mut cmd = std::process::Command::new(&rscfuse_path);
    cmd.arg("--beacon")
        .arg(beacon)
        .arg("--mount")
        .arg(mount_path)
        .arg("--name")
        .arg(name)
        .arg("--transport")
        .arg(transport)
        .arg("--encryption")
        .arg(encryption)
        .env("RUST_LOG", "info")
        .stdout(log_file)
        .stderr(log_file2);

    if let Some(ca) = ca_cert {
        cmd.arg("--ca-cert").arg(ca);
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("spawning rscfuse from {:?}", rscfuse_path))?;
    println!("rscfuse started (pid {})", child.id());
    Ok(child)
}

#[cfg(feature = "container")]
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ---------------------------------------------------------------------------
// run_image — container + cgns mode
// ---------------------------------------------------------------------------

#[cfg(feature = "container")]
async fn run_image(args: ExecArgs, image: String) -> Result<()> {
    // Launch microVM if requested, overriding the beacon address.
    let (beacon, _vm_handle) = if args.microvm {
        let backend: crate::microvm::MicroVmBackend = args
            .microvm_backend
            .parse()
            .context("parsing microvm backend")?;
        let kernel = args
            .microvm_kernel
            .clone()
            .or_else(|| std::env::var("RSCALLER_KERNEL").ok().map(PathBuf::from))
            .context(
                "--microvm requires a guest kernel path; \
                 pass --microvm-kernel <path> or set RSCALLER_KERNEL",
            )?;
        let cfg = crate::microvm::MicroVmConfig {
            backend,
            kernel,
            mem_mb: args.microvm_mem,
            cpus: args.microvm_cpus,
            beacon_timeout_secs: 60,
        };
        let handle = crate::microvm::launch_microvm(&cfg, &image).await?;
        let addr = format!("127.0.0.1:{}", handle.host_port);
        (addr, Some(handle))
    } else {
        (args.transport.beacon.clone(), None)
    };
    // _vm_handle dropped at end of scope → kills microVM.

    let backend = match args.backend.as_str() {
        "docker" => ociman::backend::resolve::docker().await?,
        "podman" => ociman::backend::resolve::podman().await?,
        _ => ociman::backend::resolve::auto().await?,
    };

    let reference: ociman::Reference = image
        .parse()
        .map_err(anyhow::Error::msg)
        .context("parsing image reference")?;
    backend.pull_image_if_absent(&reference).await.context("pulling image")?;

    let notify_dir = "/tmp/rscaller-notify-dir".to_string();
    std::fs::create_dir_all(&notify_dir).context("creating notify dir")?;
    let notify_flag = format!("{}/ready", notify_dir);
    let _ = std::fs::remove_file(&notify_flag);

    let mut container = ociman::Definition::new(backend, reference)
        .entrypoint("sleep")
        .argument("infinity")
        .mount(ociman::container::Mount::from(format!(
            "type=bind,source={},target=/run/rscaller-notify",
            notify_dir
        )))
        .run_detached()
        .await;

    let pid_str = container
        .inspect_format("{{.State.Pid}}")
        .await
        .context("getting container PID")?;
    let container_pid: u64 = pid_str
        .trim()
        .parse()
        .with_context(|| format!("parsing container PID: {:?}", pid_str))?;

    let cgns_path = format!("/proc/{}/ns/cgroup", container_pid);
    let cgns_meta = std::fs::metadata(&cgns_path)
        .with_context(|| format!("stat {}", cgns_path))?;
    let cgns_inum = cgns_meta.ino();
    println!("Container PID: {}, cgroup ns inode: {}", container_pid, cgns_inum);

    let cgns_param = "/sys/module/rscaller/parameters/container_cgns_inum";
    std::fs::write(cgns_param, cgns_inum.to_string())
        .with_context(|| format!("writing cgns inum to {}", cgns_param))?;
    println!("Set container_cgns_inum = {}", cgns_inum);

    let derived_name = derive_name(&args);
    let mut rsclient =
        spawn_rsclient_async(&beacon, &"/proc/rscaller", Some(&derived_name)).await?;

    let notify_flag_clone = notify_flag.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if std::path::Path::new(&notify_flag_clone).exists() {
                let _ = std::fs::write(
                    "/sys/module/rscaller/parameters/forwarding_enabled",
                    "1",
                );
                println!("Forwarding enabled.");
                break;
            }
        }
    });

    let fuse_host_mount = format!("/tmp/rscfuse-{}", derived_name);
    std::fs::create_dir_all(&fuse_host_mount).ok();
    let mut rscfuse = spawn_rscfuse_async(
        &beacon,
        &fuse_host_mount,
        &derived_name,
        &"tcp",
        &args.transport.encryption,
        args.transport.ca_cert.as_deref(),
    )
    .await?;

    // Wait for FUSE mount to become ready (poll: different device than /tmp parent).
    let fuse_ready = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        async {
            loop {
                let parent_dev = std::fs::metadata("/tmp")
                    .ok()
                    .map(|m| m.dev());
                let mount_dev = std::fs::metadata(&fuse_host_mount)
                    .ok()
                    .map(|m| m.dev());
                if parent_dev.is_some() && mount_dev.is_some() && parent_dev != mount_dev {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        },
    )
    .await;
    if fuse_ready.is_err() {
        eprintln!("Warning: rscfuse mount not ready after 10s, continuing anyway");
    }

    // Bind-mount rscfuse into container mount namespace.
    let container_mount_point = format!("/rsc/{}", derived_name);
    let _ = std::process::Command::new("nsenter")
        .args([
            &format!("--mount=/proc/{}/ns/mnt", container_pid),
            "--",
            "mkdir",
            "-p",
            &container_mount_point,
        ])
        .status();
    let _ = std::process::Command::new("nsenter")
        .args([
            &format!("--mount=/proc/{}/ns/mnt", container_pid),
            "--",
            "mount",
            "--bind",
            &fuse_host_mount,
            &container_mount_point,
        ])
        .status();
    println!("rscfuse bind-mounted at container:{}", container_mount_point);

    let cmd = if args.cmd.is_empty() {
        vec!["/bin/sh".to_string()]
    } else {
        args.cmd
    };
    let wrapped = format!(
        "touch /run/rscaller-notify/ready && sleep 0.2 && exec {}",
        cmd.iter().map(|a| shell_escape(a)).collect::<Vec<_>>().join(" ")
    );
    let mut exec = container.exec("/bin/sh");
    exec = exec.argument("-c").argument(&wrapped);
    let status = exec.tty().interactive().status().await;

    let _ = rscfuse.kill();
    let _ = rscfuse.wait();
    let _ = std::process::Command::new("umount")
        .args(["-l", &fuse_host_mount])
        .status();
    let _ = std::fs::remove_dir(&fuse_host_mount);
    let _ = rsclient.kill();
    let _ = rsclient.wait();
    let _ = std::fs::write("/sys/module/rscaller/parameters/forwarding_enabled", "0");
    let _ = std::fs::remove_dir_all(&notify_dir);
    let _ = container.stop().await;
    let _ = container.remove().await;
    let _ = std::fs::write(cgns_param, "0");
    // _vm_handle dropped here → microVM killed + scratch dir removed.

    status.context("container exec failed")
}

// ---------------------------------------------------------------------------
// run_microvm_progs — microVM without container (direct cmd execution)
// ---------------------------------------------------------------------------

#[cfg(feature = "container")]
async fn run_microvm_progs(args: ExecArgs) -> Result<()> {
    let backend: crate::microvm::MicroVmBackend = args
        .microvm_backend
        .parse()
        .context("parsing microvm backend")?;
    let kernel = args
        .microvm_kernel
        .clone()
        .or_else(|| std::env::var("RSCALLER_KERNEL").ok().map(PathBuf::from))
        .context(
            "--microvm requires a guest kernel path; \
             pass --microvm-kernel <path> or set RSCALLER_KERNEL",
        )?;
    let cfg = crate::microvm::MicroVmConfig {
        backend,
        kernel,
        mem_mb: args.microvm_mem,
        cpus: args.microvm_cpus,
        beacon_timeout_secs: 60,
    };

    // Use the progs_folder or empty string as a placeholder image hint.
    let image_hint = None::<String>
        .as_deref()
        .unwrap_or("")
        .to_string();
    let handle = crate::microvm::launch_microvm(&cfg, &image_hint).await?;
    let beacon_addr = format!("127.0.0.1:{}", handle.host_port);

    let derived_name = derive_name(&args);
    let mut rsclient =
        spawn_rsclient_async(&beacon_addr, &"/proc/rscaller", Some(&derived_name)).await?;

    let cmd = if args.cmd.is_empty() {
        vec!["/bin/sh".to_string()]
    } else {
        args.cmd
    };

    let status = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .status()
        .with_context(|| format!("spawning {:?}", cmd))?;

    let _ = rsclient.kill();
    let _ = rsclient.wait();
    // _handle dropped here → microVM killed + scratch dir removed.

    if status.success() {
        Ok(())
    } else {
        bail!("command exited with {}", status)
    }
}
