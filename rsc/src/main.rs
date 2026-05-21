//! rsc — run a binary with syscalls forwarded to rsbeacon.
//!
//! # Backends
//!
//! ## kmod (legacy)
//!   Uses the rscaller kernel module.  Creates a cgroup, moves the child into it,
//!   writes the cgroup inode to the kmod parameter, then execs the target.
//!   `rsclient --ctl kmod` must be running separately.
//!
//! ## seccomp (default)
//!   Uses `SECCOMP_RET_USER_NOTIF` — no kernel module required.
//!
//!   1. Opens a `socketpair(AF_UNIX, SOCK_SEQPACKET)` for fd passing.
//!   2. Forks.
//!   3. Child:
//!      a. Calls `prctl(PR_SET_NO_NEW_PRIVS, 1)` (required for unprivileged seccomp).
//!      b. Installs a BPF filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER` for the
//!         configured syscall set.  Receives the notify fd.
//!      c. Sends the notify fd to the parent via `SCM_RIGHTS` over the socketpair.
//!      d. Execs the target binary.
//!   4. Parent:
//!      a. Receives the notify fd.
//!      b. Sets `RSCALLER_NOTIF_FD=<fd>` in the environment.
//!      c. Execs `rsclient --ctl seccomp [--beacon <addr>] [--encryption <enc>]`.
//!
//! # Usage
//!   rsc [options] <cmd> [args...]
//!   rsc --ctl seccomp --beacon 10.0.0.1:9999 -- /bin/ls /tmp
//!   rsc --ctl kmod -- /usr/bin/python3 script.py

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const CGROUP_BASE: &str = "/sys/fs/cgroup/rscaller";
const DEFAULT_KMOD_PARAM: &str = "/sys/module/rscaller/parameters/target_cgroup_ino";

fn main() {
    if let Err(e) = run() {
        eprintln!("rsc: {e:#}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Arg parsing (manual to keep dependencies minimal)
// ---------------------------------------------------------------------------

struct Args {
    ctl: String,
    beacon: String,
    encryption: String,
    ca_cert: Option<String>,
    rsclient_bin: String,
    rscfuse_bin: String,
    /// Mount point base; rscfuse mounts at <mount_base>/<target_name>/
    mount_base: String,
    /// Target name used as the subdirectory under mount_base.
    target_name: String,
    kmod_param: String,
    forwarded_syscalls: Vec<u32>,
    cmd: String,
    cmd_args: Vec<String>,
}

fn parse_args() -> Result<Args> {
    let mut raw: Vec<String> = std::env::args().skip(1).collect();
    let mut ctl = "seccomp".to_string();
    let mut beacon = "127.0.0.1:9999".to_string();
    let mut encryption = "none".to_string();
    let mut ca_cert: Option<String> = None;
    let mut rsclient_bin = "rsclient".to_string();
    let mut rscfuse_bin = "rscfuse".to_string();
    let mut mount_base = "/rsc".to_string();
    let mut target_name = "default".to_string();
    let mut kmod_param = DEFAULT_KMOD_PARAM.to_string();
    // Default forwarded syscalls (open, read, write, close, stat family, execve, etc.)
    // Path-based syscalls (open, stat, read, write, close, getdents, chdir)
    // are intentionally NOT forwarded here — they are handled transparently
    // by rscfuse mounted at /rsc/<target>/.  The seccomp filter only covers
    // syscalls that have no filesystem path component and therefore cannot
    // be routed through a FUSE mount.
    let forwarded_syscalls: Vec<u32> = vec![
        62,  // kill
        // 321, // bpf  (add when needed)
    ];

    while !raw.is_empty() {
        match raw[0].as_str() {
            "--ctl" => { raw.remove(0); ctl = raw.remove(0); }
            "--beacon" => { raw.remove(0); beacon = raw.remove(0); }
            "--encryption" => { raw.remove(0); encryption = raw.remove(0); }
            "--ca-cert" => { raw.remove(0); ca_cert = Some(raw.remove(0)); }
            "--rsclient" => { raw.remove(0); rsclient_bin = raw.remove(0); }
            "--rscfuse"  => { raw.remove(0); rscfuse_bin  = raw.remove(0); }
            "--mount-base" => { raw.remove(0); mount_base = raw.remove(0); }
            "--target"   => { raw.remove(0); target_name  = raw.remove(0); }
            "--kmod-param" => { raw.remove(0); kmod_param = raw.remove(0); }
            "--" => { raw.remove(0); break; }
            s if s.starts_with('-') => {
                bail!("Unknown option: {s}");
            }
            _ => break,
        }
    }

    if raw.is_empty() {
        bail!("Usage: rsc [options] [--] <cmd> [args...]");
    }

    let cmd = raw.remove(0);
    let cmd_args = raw;

    Ok(Args {
        ctl,
        beacon,
        encryption,
        ca_cert,
        rsclient_bin,
        rscfuse_bin,
        mount_base,
        target_name,
        kmod_param,
        forwarded_syscalls,
        cmd,
        cmd_args,
    })
}

fn run() -> Result<()> {
    let args = parse_args()?;
    match args.ctl.as_str() {
        "kmod" => run_kmod(args),
        "seccomp" => run_seccomp(args),
        other => bail!("Unknown controller '{other}'. Valid: kmod, seccomp"),
    }
}

// ---------------------------------------------------------------------------
// kmod backend (cgroup-based, legacy)
// ---------------------------------------------------------------------------

fn run_kmod(args: Args) -> Result<()> {
    // Verify cgroup v2.
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        bail!("cgroup v2 unified hierarchy not found — cgroup v1 is not supported");
    }

    if !Path::new(CGROUP_BASE).exists() {
        fs::create_dir(CGROUP_BASE)
            .with_context(|| format!("cannot create {CGROUP_BASE}"))?;
    }

    let uuid = {
        // Generate a simple UUID-ish string without a dep.
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

    let result = run_kmod_with_cgroup(&cgroup_dir, &args.kmod_param, &args.cmd, &args.cmd_args);

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
            // Move child into cgroup.
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
    // Create mount point directory if absent.
    fs::create_dir_all(mount_point)
        .with_context(|| format!("create mount point {mount_point}"))?;

    let mut argv_strs = vec![
        bin.to_string(),
        "--beacon".to_string(), beacon.to_string(),
        "--mount".to_string(),  mount_point.to_string(),
        "--name".to_string(),   name.to_string(),
        "--encryption".to_string(), encryption.to_string(),
    ];
    if let Some(ca) = ca_cert {
        argv_strs.push("--ca-cert".to_string());
        argv_strs.push(ca.to_string());
    }

    let argv: Vec<CString> = argv_strs.iter()
        .map(|s| CString::new(s.as_str()).expect("NUL in rscfuse arg"))
        .collect();
    let argv_ptrs: Vec<*const libc::c_char> = argv.iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let envp: Vec<CString> = std::env::vars()
        .map(|(k, v)| CString::new(format!("{k}={v}")).expect("NUL in env"))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = envp.iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => bail!("fork for rscfuse failed: {}", std::io::Error::last_os_error()),
        0 => {
            // Child: exec rscfuse.
            unsafe { libc::execvpe(argv_ptrs[0], argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
            eprintln!("rsc: exec rscfuse failed: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }
        child_pid => {
            // Parent: poll until mount point is live (up to 3s).
            for _ in 0..30 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if is_mount_point(mount_point) {
                    return Ok(child_pid);
                }
                // Check child hasn't already died.
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

/// Check if `path` is a FUSE mount point by reading `/proc/mounts`.
fn is_mount_point(path: &str) -> bool {
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else { return false };
    mounts.lines().any(|l| {
        let mut parts = l.splitn(3, ' ');
        let _dev = parts.next();
        let mp = parts.next().unwrap_or("");
        mp == path
    })
}

fn run_seccomp(args: Args) -> Result<()> {
    // Mount rscfuse at /rsc/<target>/ before forking.
    let mount_point = format!("{}/{}", args.mount_base, args.target_name);
    let fuse_pid = launch_rscfuse(
        &args.rscfuse_bin,
        &args.beacon,
        &args.encryption,
        args.ca_cert.as_deref(),
        &mount_point,
        &args.target_name,
    )?;
    eprintln!("rsc: rscfuse mounted at {} (pid {})", mount_point, fuse_pid);

    // Create a socketpair for passing the notify fd from child to parent.
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
            // Child: close parent's end, install seccomp, send notify fd, exec target.
            unsafe { libc::close(parent_sock) };
            child_seccomp_exec(child_sock, &args.forwarded_syscalls, &args.cmd, &args.cmd_args);
        }
        _pid => {
            // Parent: close child's end, receive notify fd, exec rsclient.
            unsafe { libc::close(child_sock) };
            let notify_fd = recv_fd(parent_sock)
                .context("receiving seccomp notify fd from child")?;
            unsafe { libc::close(parent_sock) };

            eprintln!("rsc: received seccomp notify fd {}", notify_fd);

            // Exec rsclient with the notify fd.
            exec_rsclient(&args, notify_fd);
        }
    }
    #[allow(unreachable_code)]
    Ok(())
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
    // prctl(PR_SET_NO_NEW_PRIVS, 1) — required before seccomp w/o CAP_SYS_ADMIN.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        eprintln!(
            "rsc: prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    // Build and install the BPF filter.
    let notify_fd = match install_seccomp_filter(syscall_nrs) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("rsc: seccomp filter install failed: {e}");
            std::process::exit(1);
        }
    };

    // Send the notify fd to the parent.
    if let Err(e) = send_fd(sock, notify_fd) {
        eprintln!("rsc: send_fd failed: {e}");
        std::process::exit(1);
    }
    unsafe { libc::close(sock) };

    // Exec target binary.
    child_exec(cmd, cmd_args);
}

/// Install a seccomp BPF filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
/// Returns the notify fd.
fn install_seccomp_filter(syscall_nrs: &[u32]) -> Result<libc::c_int> {
    // BPF constants.
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
    insns.push(libc::sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_USER_NOTIF });

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
    // Control message buffer large enough for one fd.
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) }
        as usize;
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
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        let data_ptr = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
        *data_ptr = fd;
    }

    let ret = unsafe { libc::sendmsg(sock, &msg, 0) };
    if ret < 0 {
        bail!("sendmsg: {}", std::io::Error::last_os_error());
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Receive a single fd via SCM_RIGHTS over `sock`.
fn recv_fd(sock: libc::c_int) -> Result<libc::c_int> {
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) }
        as usize;
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

    let recv_fd = unsafe {
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            bail!("unexpected cmsg level/type");
        }
        *(libc::CMSG_DATA(cmsg) as *const libc::c_int)
    };

    Ok(recv_fd)
}

/// Parent side: exec `rsclient --ctl seccomp --notif-fd <fd> [transport flags]`.
///
/// This replaces the parent process image with rsclient.
fn exec_rsclient(args: &Args, notify_fd: libc::c_int) -> ! {
    // Build argv.
    let mut argv_strs = vec![
        args.rsclient_bin.clone(),
        "--ctl".into(),
        "seccomp".into(),
        "--notif-fd".into(),
        notify_fd.to_string(),
        "--beacon".into(),
        args.beacon.clone(),
        "--encryption".into(),
        args.encryption.clone(),
    ];
    if let Some(ref ca) = args.ca_cert {
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

    // Build envp: current env.
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
    #[allow(unreachable_code)]
    Ok(())
}

fn kill_cgroup(cgroup_dir: &Path) {
    let kill_file = cgroup_dir.join("cgroup.kill");
    if kill_file.exists() {
        let _ = fs::write(&kill_file, "1");
    }
}
