use crate::{ExecArgs, ShellArgs, TransportArgs};
use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::fd::IntoRawFd;
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
    let cmd = shell_cmd(&args);
    run_exec_sync(ExecArgs { transport: args.transport, image: args.image, backend: args.backend, microvm: args.microvm, microvm_backend: args.microvm_backend, microvm_kernel: args.microvm_kernel, microvm_mem: args.microvm_mem, microvm_cpus: args.microvm_cpus, kmod_param: String::from("/sys/module/rscaller/parameters/target_cgroup_ino"), cmd, mount_profile: args.mount_profile })
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
    let cmd = shell_cmd(&args);
    run_exec_async(ExecArgs { transport: args.transport, image: args.image, backend: args.backend, microvm: args.microvm, microvm_backend: args.microvm_backend, microvm_kernel: args.microvm_kernel, microvm_mem: args.microvm_mem, microvm_cpus: args.microvm_cpus, kmod_param: String::from("/sys/module/rscaller/parameters/target_cgroup_ino"), cmd, mount_profile: args.mount_profile }).await
}

/// Build the shell command vector for `rsc shell`.
///
/// When mount-profile is non-none, default to `--norc --noprofile` to avoid
/// sourcing any rc files that might exist on the overlaid filesystem.
/// Pass `--rc` to override and source normally.
fn shell_cmd(args: &ShellArgs) -> Vec<String> {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let no_rc = args.mount_profile != "none" && !args.rc;
    if no_rc {
        vec![shell, "--norc".into(), "--noprofile".into(), "-i".into()]
    } else {
        vec![shell, "-i".into()]
    }
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

    // Load profile first so we can inspect it before launching rscfuse.
    let mount_profile = crate::mount_config::load(&args.mount_profile)
        .context("loading mount profile")?;

    let name = args.transport.resolve_name();
    let mount_point = format!("{}/{}", args.transport.mount_base, name);
    let merged_proc = mount_profile.has_proc_bind();
    let fuse_pid = launch_rscfuse(
        &args.transport.beacon,
        &args.transport.encryption,
        args.transport.ca_cert.as_deref(),
        &mount_point,
        &name,
        merged_proc,
    )?;
    eprintln!("rsc: rscfuse mounted at {} (pid {})", mount_point, fuse_pid);
    if !mount_profile.mounts.is_empty() {
        eprintln!("rsc: mount profile {:?} ({} entries)", mount_profile.name, mount_profile.mounts.len());
    }

    // Use a plain pipe to transfer the seccomp notify fd number.
    // SCM_RIGHTS via sendmsg(2) would deadlock: sendmsg is syscall 46 which the
    // ghost/shadow profiles intercept, so the child would block on its own filter
    // before rsclient exists to process the notification.
    // write(2)/read(2) (syscalls 1/0) on this pipe are always real, low-numbered
    // fds (from pipe2() below) — even for a profile that fd-range-gates
    // read/write (see `ForwardFilter::fd_range`), the BPF filter only
    // notifies for fds in the beacon-owned virtual range, so this pipe I/O
    // is guaranteed to fall through to SECCOMP_RET_ALLOW and never block.
    let mut pipe_fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret != 0 {
        bail!("pipe2: {}", std::io::Error::last_os_error());
    }
    let (pipe_read, pipe_write) = (pipe_fds[0], pipe_fds[1]);

    let child_pid = unsafe { libc::fork() };
    match child_pid {
        -1 => bail!("fork failed: {}", std::io::Error::last_os_error()),
        0 => {
            unsafe { libc::close(pipe_read) };
            let cmd = &args.cmd[0];
            let cmd_args = &args.cmd[1..];
            let always_nrs = mount_profile.forward_nrs_always();
            let fd_gated_nrs = mount_profile.forward_nrs_fd_gated();
            child_seccomp_exec(pipe_write, &always_nrs, &fd_gated_nrs, cmd, cmd_args, &mount_profile, &mount_point);
        }
        child_pid => {
            unsafe { libc::close(pipe_write) };

            // Move child into session cgroup if the profile requests it.
            // Done before handing off to rsclient so the cgroup is populated
            // before any signal intercepts can arrive.
            let session_cgroup: Option<String> = if mount_profile.needs_local_cgroup() {
                match create_session_cgroup(child_pid) {
                    Ok(path) => {
                        eprintln!("rsc: session cgroup: {path}");
                        Some(path)
                    }
                    Err(e) => {
                        eprintln!("rsc: warning: could not create session cgroup: {e:#}");
                        None
                    }
                }
            } else {
                None
            };

            let notify_fd = recv_notify_fd(pipe_read, child_pid)
                .context("receiving seccomp notify fd from child")?;
            unsafe { libc::close(pipe_read) };

            eprintln!("rsc: received seccomp notify fd {}", notify_fd);

            let cgroup_gated = mount_profile.cgroup_gated_nrs();
            exec_rsclient(
                &args.transport.rsclient_bin(),
                &args.transport,
                notify_fd,
                session_cgroup.as_deref(),
                &cgroup_gated,
            );
        }
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Fork+exec `rsc fuse` in the background and wait until the mount point is live.
///
/// Returns the child PID (left as a zombie until rsc exits;
/// AutoUnmount will clean up the FUSE mount on process death).
fn launch_rscfuse(
    beacon: &str,
    encryption: &str,
    ca_cert: Option<&str>,
    mount_point: &str,
    name: &str,
    merged_proc: bool,
) -> Result<libc::pid_t> {
    // Lazily detach any stale FUSE mount left by a previous session.  Without
    // this, create_dir_all succeeds but stat(2) on the stale mountpoint hangs
    // or returns EIO, causing is_dir() to return false and the subsequent
    // fuser::mount2 to fail with EEXIST / EBUSY.
    if is_mount_point(mount_point) {
        let _ = std::process::Command::new("umount")
            .args(["-l", mount_point])
            .status();
    }
    fs::create_dir_all(mount_point)
        .with_context(|| format!("create mount point {mount_point}"))?;

    let rsc_exe = std::env::current_exe()
        .context("resolving current executable path")?
        .to_string_lossy()
        .into_owned();

    let mut argv_strs = vec![
        rsc_exe.clone(),
        "fuse".to_string(),
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
    if merged_proc {
        argv_strs.push("--merged-proc".to_string());
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
    pipe_write: libc::c_int,
    always_nrs: &[u32],
    fd_gated_nrs: &[u32],
    cmd: &str,
    cmd_args: &[String],
    mount_profile: &crate::mount_config::MountProfile,
    fuse_root: &str,
) -> ! {
    // Apply mount namespace BEFORE prctl — mounts require CAP_SYS_ADMIN.
    if let Err(e) = crate::mount_config::apply(mount_profile, fuse_root) {
        eprintln!("rsc: mount profile {:?} failed: {e}", mount_profile.name);
        std::process::exit(1);
    }

    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        eprintln!(
            "rsc: prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    let notify_fd = match install_seccomp_filter(always_nrs, fd_gated_nrs) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("rsc: seccomp filter install failed: {e}");
            std::process::exit(1);
        }
    };

    // The kernel sets O_CLOEXEC on the seccomp notify fd by default.
    // Clear it so the fd survives exec into bash; otherwise pidfd_getfd in
    // the parent would race against exec and see EBADF.
    unsafe { libc::fcntl(notify_fd, libc::F_SETFD, 0) };

    // Send notify fd NUMBER via write() (syscall 1) on `pipe_write`, a real
    // low-numbered fd — never intercepted, per the fd-range gating note above.
    // The parent steals the fd from our /proc entry via pidfd_getfd.
    let fd_bytes = (notify_fd as u32).to_ne_bytes();
    let ret = unsafe { libc::write(pipe_write, fd_bytes.as_ptr() as _, 4) };
    if ret != 4 {
        eprintln!("rsc: write notify fd number failed: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    unsafe { libc::close(pipe_write) };

    child_exec(cmd, cmd_args);
}

/// Install a seccomp BPF filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
/// Returns the notify fd.
///
/// `always_nrs` are notified unconditionally; `fd_gated_nrs` are notified
/// only when the syscall's fd argument (`args[0]`) is in the beacon-owned
/// virtual fd range — see `ctls::seccomp::build_filter_fd_gated` (this is a
/// thin wrapper; the actual BPF program construction lives there so
/// `ctls` — which also implements the userspace side of the same
/// mechanism, `SeccompController` — stays the single source of truth for
/// it, instead of two independently-maintained copies).
fn install_seccomp_filter(always_nrs: &[u32], fd_gated_nrs: &[u32]) -> Result<libc::c_int> {
    let (_insns, prog) = ctls::seccomp::build_filter_fd_gated(always_nrs, fd_gated_nrs);
    // SAFETY: `prog` points at `_insns`, which outlives this call.
    let fd = unsafe { ctls::seccomp::seccomp_install_filter(&prog as *const libc::sock_fprog) }
        .context("installing seccomp filter")?;
    Ok(fd.into_raw_fd() as libc::c_int)
}

/// Read the notify fd number written by the child and steal the fd from the
/// child's fd table using pidfd_getfd (Linux 5.6+).
///
/// The child writes a raw u32 (notify_fd number) via write(2) — syscall 1 on
/// `pipe_write`, a real fd well below the virtual fd range, so even a
/// profile that fd-range-gates write() never intercepts it (see the
/// fd-range gating note where the pipe is created). We then use
/// pidfd_getfd to atomically duplicate the fd from the child's fd table into
/// the parent's, without any sendmsg/recvmsg round-trip.
fn recv_notify_fd(pipe_read: libc::c_int, child_pid: libc::pid_t) -> Result<libc::c_int> {
    const SYS_PIDFD_OPEN: libc::c_long = 434; // x86_64
    const SYS_PIDFD_GETFD: libc::c_long = 438; // x86_64

    let mut buf = [0u8; 4];
    let ret = unsafe { libc::read(pipe_read, buf.as_mut_ptr() as _, 4) };
    if ret != 4 {
        bail!(
            "read notify fd number from child (got {} bytes): {}",
            ret,
            std::io::Error::last_os_error()
        );
    }
    let fd_num = u32::from_ne_bytes(buf) as libc::c_int;

    let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, child_pid as libc::c_long, 0i64) };
    if pidfd < 0 {
        bail!("pidfd_open({}): {}", child_pid, std::io::Error::last_os_error());
    }
    let pidfd = pidfd as libc::c_int;

    let duped = unsafe {
        libc::syscall(SYS_PIDFD_GETFD, pidfd as libc::c_long, fd_num as libc::c_long, 0i64)
    };
    unsafe { libc::close(pidfd) };

    if duped < 0 {
        bail!(
            "pidfd_getfd(child={}, fd={}): {}",
            child_pid, fd_num,
            std::io::Error::last_os_error()
        );
    }

    // pidfd_getfd always sets O_CLOEXEC on the result. Clear it so the fd
    // survives exec_rsclient's execvpe() into rsclient.
    unsafe { libc::fcntl(duped as libc::c_int, libc::F_SETFD, 0) };

    Ok(duped as libc::c_int)
}

/// Create a dedicated cgroup for locally-spawned processes and add `child_pid`.
///
/// Returns the cgroup path (e.g. `/sys/fs/cgroup/rscaller/session-<hex>`).
/// The cgroup is a leaf under `CGROUP_BASE` so cgroup v2 delegation rules apply.
fn create_session_cgroup(child_pid: libc::pid_t) -> Result<String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = format!("{CGROUP_BASE}/session-{ts:016x}");
    fs::create_dir_all(&path)
        .with_context(|| format!("create session cgroup {path}"))?;
    fs::write(format!("{path}/cgroup.procs"), format!("{child_pid}\n"))
        .with_context(|| format!("add PID {child_pid} to session cgroup"))?;
    Ok(path)
}

/// Parent side: exec `rsclient --ctl seccomp --notif-fd <fd> [transport flags]`.
///
/// This replaces the parent process image with rsclient.
/// `session_cgroup` — path to the local session cgroup, if one was created.
/// `cgroup_gated_nrs` — syscall numbers whose forwarding is gated by the cgroup filter.
fn exec_rsclient(
    rsclient_bin: &str,
    transport: &TransportArgs,
    notify_fd: libc::c_int,
    session_cgroup: Option<&str>,
    cgroup_gated_nrs: &[u32],
) -> ! {
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
    if let Some(cgroup) = session_cgroup {
        argv_strs.push("--local-cgroup".into());
        argv_strs.push(cgroup.to_string());
        if !cgroup_gated_nrs.is_empty() {
            let nrs = cgroup_gated_nrs.iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",");
            argv_strs.push("--cgroup-gated-nrs".into());
            argv_strs.push(nrs);
        }
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
    let rsc_exe = std::env::current_exe().context("resolving current exe")?;

    let log_file =
        std::fs::File::create("/tmp/rscfuse.log").context("rscfuse log")?;
    let log_file2 = log_file.try_clone().context("rscfuse log clone")?;

    let mut cmd = std::process::Command::new(&rsc_exe);
    cmd.arg("fuse")
        .arg("--beacon")
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
        .with_context(|| format!("spawning rsc fuse from {:?}", rsc_exe))?;
    println!("rsc fuse started (pid {})", child.id());
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
