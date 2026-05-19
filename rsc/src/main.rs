//! rsc — run a binary with syscalls forwarded to rsbeacon via the rscaller kmod.
//!
//! Usage:
//!   rsc [--kmod-param <path>] <cmd> [args...]
//!   RSC_REMOTE=1 ./binary          (when binary is on PATH or symlinked to rsc)
//!
//! What it does:
//!   1. Creates /sys/fs/cgroup/rscaller/<uuid>/
//!   2. Forks, moves child into that cgroup via cgroup.procs
//!   3. Stats the cgroup dir to get st_ino
//!   4. Writes inode to /sys/module/rscaller/parameters/target_cgroup_ino
//!   5. Execs the target binary (RSC_REMOTE stripped from env)
//!   6. Waits for child to exit
//!   7. Cleans up: writes 0 to param, removes cgroup dir
//!
//! Requires: root or CAP_SYS_ADMIN (cgroup v2 write access under
//! /sys/fs/cgroup/rscaller/).  cgroup v2 only (unified hierarchy).

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const CGROUP_BASE: &str = "/sys/fs/cgroup/rscaller";
const CGROUP_CONTROLLERS_CHECK: &str = "/sys/fs/cgroup/cgroup.controllers";
const DEFAULT_KMOD_PARAM: &str =
    "/sys/module/rscaller/parameters/target_cgroup_ino";

fn main() {
    if let Err(e) = run() {
        eprintln!("rsc: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    // Parse args: rsc [--kmod-param <path>] <cmd> [args...]
    let mut args: Vec<String> = std::env::args().collect();
    let mut kmod_param = DEFAULT_KMOD_PARAM.to_string();

    // Strip argv[0] (our own name).
    args.remove(0);

    // --kmod-param <path>
    if args.first().map(|s| s.as_str()) == Some("--kmod-param") {
        args.remove(0);
        kmod_param = args
            .first()
            .context("--kmod-param requires a path argument")?
            .clone();
        args.remove(0);
    }

    if args.is_empty() {
        bail!("Usage: rsc [--kmod-param <path>] <cmd> [args...]");
    }

    let cmd = args.remove(0);
    let cmd_args = args;

    // Verify cgroup v2.
    if !Path::new(CGROUP_CONTROLLERS_CHECK).exists() {
        bail!(
            "cgroup v2 unified hierarchy not found at /sys/fs/cgroup — \
             cgroup v1 is not supported"
        );
    }

    // Create /sys/fs/cgroup/rscaller/ if absent.
    if !Path::new(CGROUP_BASE).exists() {
        fs::create_dir(CGROUP_BASE).with_context(|| {
            format!(
                "cannot create {CGROUP_BASE}: are you root or do you have \
                 cgroup delegation?"
            )
        })?;
    }

    // Unique subtree for this invocation.
    let uuid = uuid::Uuid::new_v4().to_string();
    let cgroup_dir = PathBuf::from(CGROUP_BASE).join(&uuid);

    fs::create_dir(&cgroup_dir).with_context(|| {
        format!(
            "cannot create cgroup {}: EPERM means you need root or \
             delegated cgroup ownership",
            cgroup_dir.display()
        )
    })?;

    // From here on we must clean up cgroup_dir on any early return.
    let result = run_with_cgroup(&cgroup_dir, &kmod_param, &cmd, &cmd_args);

    // Best-effort cleanup (also done inside run_with_cgroup on success).
    let _ = write_kmod_param(&kmod_param, 0);
    kill_cgroup(&cgroup_dir);
    let _ = fs::remove_dir(&cgroup_dir);

    result
}

fn run_with_cgroup(
    cgroup_dir: &Path,
    kmod_param: &str,
    cmd: &str,
    cmd_args: &[String],
) -> Result<()> {
    // fork() so the child can be moved into the cgroup before exec.
    let child_pid = unsafe { libc::fork() };

    match child_pid {
        -1 => {
            bail!("fork failed: {}", std::io::Error::last_os_error());
        }
        0 => {
            // Child: exec the target binary. Parent handles cgroup setup.
            // child_exec is `-> !` and never returns.
            child_exec(cmd, cmd_args);
        }
        pid => {
            // Parent.
            parent_setup(cgroup_dir, kmod_param, pid)?;
            wait_child(pid)?;

            // Cleanup.
            write_kmod_param(kmod_param, 0)?;
            kill_cgroup(cgroup_dir);
            let _ = fs::remove_dir(cgroup_dir);
        }
    }

    Ok(())
}

/// Parent: write child PID to cgroup, stat inode, arm kmod param.
fn parent_setup(cgroup_dir: &Path, kmod_param: &str, child_pid: libc::pid_t) -> Result<()> {
    // Move child into the cgroup.
    let procs_file = cgroup_dir.join("cgroup.procs");
    fs::write(&procs_file, format!("{}\n", child_pid)).with_context(|| {
        format!("cannot write child PID to {}", procs_file.display())
    })?;

    // Get the cgroup dir inode — this is what the kmod compares against kn->id.
    let meta = fs::metadata(cgroup_dir)
        .with_context(|| format!("cannot stat {}", cgroup_dir.display()))?;
    let ino = meta.ino();

    eprintln!(
        "rsc: cgroup {} inode={} pid={}",
        cgroup_dir.display(),
        ino,
        child_pid
    );

    // Arm the kmod filter.
    write_kmod_param(kmod_param, ino).with_context(|| {
        format!("cannot write inode to kmod param {kmod_param}")
    })?;

    Ok(())
}

/// Write a u64 value to the kmod sysfs parameter file.
fn write_kmod_param(path: &str, value: u64) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("open {path}"))?;
    write!(f, "{value}").with_context(|| format!("write {path}"))?;
    Ok(())
}

/// Child: exec the target binary with RSC_REMOTE stripped.
///
/// This function must not return on success.
fn child_exec(cmd: &str, args: &[String]) -> ! {
    // Build argv: [cmd, args...]
    let argv: Vec<CString> = std::iter::once(cmd)
        .chain(args.iter().map(|s| s.as_str()))
        .map(|s| CString::new(s).expect("NUL in argument"))
        .collect();

    // Build envp: current env minus RSC_REMOTE.
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

    // execvpe only returns on error.
    eprintln!(
        "rsc: exec {cmd} failed: {}",
        std::io::Error::last_os_error()
    );
    std::process::exit(127);
}

/// Wait for child; return its exit status.
fn wait_child(pid: libc::pid_t) -> Result<()> {
    let mut status: libc::c_int = 0;
    loop {
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            bail!("waitpid failed: {err}");
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

    Ok(())
}

/// Kill all processes in the cgroup (best-effort, kernel 5.14+ cgroup.kill).
fn kill_cgroup(cgroup_dir: &Path) {
    // cgroup.kill: writing "1" sends SIGKILL to all tasks in the cgroup.
    // Available since Linux 5.14.  Silently skip if not present.
    let kill_file = cgroup_dir.join("cgroup.kill");
    if kill_file.exists() {
        let _ = fs::write(&kill_file, "1");
    }
}
