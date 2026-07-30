//! Mount namespace overlay profiles for `rsc exec`.
//!
//! A MountProfile describes which remote FUSE paths should be bind-mounted
//! over local paths inside the child's private mount namespace, making the
//! command transparently read from the remote filesystem.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::ffi::CString;
use std::fs;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Deserialize, Clone, Debug, Default)]
pub struct MountProfile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub mounts: Vec<MountEntry>,
    /// Ordered forwarding rules. Each rule names syscalls to intercept and an
    /// optional filter controlling when the interception is forwarded to beacon
    /// vs. continued locally.
    #[serde(default)]
    pub forward: Vec<ForwardRule>,
}

impl MountProfile {
    /// Returns true if any bind mount targets the local /proc directory.
    /// Used to decide whether to pass --merged-proc to rscfuse.
    pub fn has_proc_bind(&self) -> bool {
        self.mounts.iter().any(|m| {
            matches!(m.mount_type, MountType::Bind) && m.local == "/proc"
        })
    }

    /// Syscall numbers to intercept unconditionally — every rule without a
    /// `filter: {fd_range: ...}` (across all rules).
    pub fn forward_nrs_always(&self) -> Vec<u32> {
        let mut nrs: Vec<u32> = self.forward.iter()
            .filter(|r| !r.has_fd_range_filter())
            .flat_map(|r| r.syscall_nrs())
            .collect();
        nrs.sort_unstable();
        nrs.dedup();
        nrs
    }

    /// Syscall numbers to intercept only when their fd argument is in the
    /// beacon-owned virtual fd range — every rule with
    /// `filter: {fd_range: virtual}` (across all rules). See
    /// [`ForwardFilter::fd_range`] and `ctls::seccomp::build_filter_fd_gated`.
    pub fn forward_nrs_fd_gated(&self) -> Vec<u32> {
        let mut nrs: Vec<u32> = self.forward.iter()
            .filter(|r| r.has_fd_range_filter())
            .flat_map(|r| r.syscall_nrs())
            .collect();
        nrs.sort_unstable();
        nrs.dedup();
        nrs
    }

    /// Returns true if any rule carries a `filter: {cgroup: local}` — meaning
    /// a per-session cgroup must be created so the relay can consult it.
    pub fn needs_local_cgroup(&self) -> bool {
        self.forward.iter().any(|r| r.has_cgroup_filter())
    }

    /// Syscall numbers whose forwarding is gated by the local-cgroup exclusion.
    pub fn cgroup_gated_nrs(&self) -> Vec<u32> {
        self.forward.iter()
            .filter(|r| r.has_cgroup_filter())
            .flat_map(|r| r.syscall_nrs())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ForwardRule
// ---------------------------------------------------------------------------

#[derive(Deserialize, Clone, Debug)]
pub struct ForwardRule {
    /// Optional human-readable label (e.g. "network", "signal").
    #[serde(default)]
    pub name: Option<String>,
    /// Syscall names to intercept. Resolved to numbers via [`syscall_nr`].
    pub syscalls: Vec<String>,
    /// Per-rule filter controlling local vs. forwarded execution.
    #[serde(default)]
    pub filter: Option<ForwardFilter>,
}

impl ForwardRule {
    pub fn syscall_nrs(&self) -> Vec<u32> {
        self.syscalls.iter()
            .filter_map(|s| {
                let nr = syscall_nr(s);
                if nr.is_none() {
                    eprintln!("rsc: unknown forward syscall {s:?}, ignoring");
                }
                nr
            })
            .collect()
    }

    pub fn has_cgroup_filter(&self) -> bool {
        matches!(
            self.filter.as_ref().and_then(|f| f.cgroup.as_ref()),
            Some(CgroupScope::Local)
        )
    }

    pub fn has_fd_range_filter(&self) -> bool {
        matches!(
            self.filter.as_ref().and_then(|f| f.fd_range.as_ref()),
            Some(FdRangeScope::Virtual)
        )
    }
}

// ---------------------------------------------------------------------------
// ForwardFilter
// ---------------------------------------------------------------------------

/// Per-rule filter. All fields are optional; absent fields impose no constraint.
#[derive(Deserialize, Clone, Debug)]
pub struct ForwardFilter {
    /// Cgroup-based exclusion. `local` means: if the signal target PID lives
    /// inside the session's local cgroup, continue the syscall locally instead
    /// of forwarding it to beacon. Keeps shell job control intact for
    /// locally-spawned processes while still forwarding signals to beacon PIDs.
    #[serde(default)]
    pub cgroup: Option<CgroupScope>,
    /// Fd-range gating, for syscalls that operate on *any* fd (`read`,
    /// `write`, `close`, `poll`, `ppoll`) rather than being inherently
    /// network-specific. `virtual` means: only forward when the syscall's
    /// fd argument is one previously handed back by a beacon `NetBackend`
    /// (see `rscaller_proto::types::VIRTUAL_FD_BASE`) — an ordinary local
    /// fd (file, pipe, real socket) is left completely untouched, running
    /// against the tracee's own kernel exactly as if this profile didn't
    /// exist. This check happens in the seccomp BPF filter itself (see
    /// `ctls::seccomp::build_filter_fd_gated`), before any syscall ever
    /// reaches rsclient/rsbeacon.
    #[serde(default)]
    pub fd_range: Option<FdRangeScope>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CgroupScope {
    /// Exclude PIDs that are members of the per-session local cgroup.
    Local,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FdRangeScope {
    /// Only forward if the fd argument is in the beacon-owned virtual fd
    /// range.
    Virtual,
}

// Generated from files/syscall_nrs by build.rs.
include!(concat!(env!("OUT_DIR"), "/syscall_nrs.rs"));

#[derive(Deserialize, Clone, Debug)]
pub struct MountEntry {
    /// Path on the remote filesystem, relative to the FUSE mount root.
    pub remote: String,
    /// Absolute local path where the remote path will be mounted.
    pub local: String,
    /// Mount mechanism.
    #[serde(rename = "type", default)]
    pub mount_type: MountType,
    /// When true, silently skip this entry if the remote path is absent.
    #[serde(default)]
    pub optional: bool,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    #[default]
    Bind,
    // Overlay support (overlayfs full-root) is reserved for a future layer.
    Overlay,
}

// ---------------------------------------------------------------------------
// Built-in presets — auto-generated from profiles/*.yaml by build.rs.
// To add a profile: drop a .yaml file in rsc/profiles/ and recompile.
// ---------------------------------------------------------------------------

// Generated from profiles/*.yaml by build.rs.
include!(concat!(env!("OUT_DIR"), "/profiles.rs"));

// ---------------------------------------------------------------------------
// Profile loading
// ---------------------------------------------------------------------------

/// Load a profile by name (built-in or user profile) or by YAML file path.
///
/// Resolution order:
/// 1. If `name_or_path` contains `/` or ends with `.yaml`/`.yml` → treat as file path.
/// 2. Built-in preset (none, proc, proc-sys, full).
/// 3. `~/.config/rsc/profiles/<name>.yaml`
/// 4. `/etc/rsc/profiles/<name>.yaml`
pub fn load(name_or_path: &str) -> Result<MountProfile> {
    if name_or_path.contains('/')
        || name_or_path.ends_with(".yaml")
        || name_or_path.ends_with(".yml")
    {
        return load_file(name_or_path);
    }
    if let Some(p) = builtin_preset(name_or_path) {
        return Ok(p);
    }
    let candidates: Vec<String> = [
        std::env::var("HOME")
            .ok()
            .map(|h| format!("{h}/.config/rsc/profiles/{name_or_path}.yaml")),
        Some(format!("/etc/rsc/profiles/{name_or_path}.yaml")),
    ]
    .into_iter()
    .flatten()
    .collect();

    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return load_file(path);
        }
    }

    let list = builtin_names()
        .iter()
        .filter_map(|n| builtin_preset(n))
        .map(|p| format!("  {:12} {}", p.name, p.description))
        .collect::<Vec<_>>()
        .join("\n");
    bail!(
        "unknown mount profile {name_or_path:?}\n\
         built-in profiles:\n{list}\n\
         or pass a path to a YAML file with --mount-profile /path/to/profile.yaml"
    )
}

pub fn load_file(path: &str) -> Result<MountProfile> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading mount profile {path:?}"))?;
    serde_yaml::from_str(&text).with_context(|| format!("parsing mount profile {path:?}"))
}

// ---------------------------------------------------------------------------
// Application (runs in the forked child, before exec)
// ---------------------------------------------------------------------------

/// Set up a private mount namespace and apply the profile's bind-mounts.
///
/// `fuse_root` is the path where rscfuse is mounted (e.g. `/tmp/rsc/target`).
///
/// Call this BEFORE `prctl(PR_SET_NO_NEW_PRIVS)` while CAP_SYS_ADMIN is live.
/// Only call from a single-threaded forked child.
pub fn apply(profile: &MountProfile, fuse_root: &str) -> Result<()> {
    if profile.mounts.is_empty() {
        return Ok(());
    }

    let ret = unsafe { libc::unshare(libc::CLONE_NEWNS) };
    if ret != 0 {
        bail!("unshare(CLONE_NEWNS): {}", std::io::Error::last_os_error());
    }

    // Make the entire tree private so bind-mounts don't propagate to the host.
    {
        let root = CString::new("/").unwrap();
        let ret = unsafe {
            libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            bail!(
                "mount --make-rprivate /: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    for entry in &profile.mounts {
        apply_entry(entry, fuse_root)?;
    }

    Ok(())
}

fn apply_entry(entry: &MountEntry, fuse_root: &str) -> Result<()> {
    match entry.mount_type {
        MountType::Bind => apply_bind(entry, fuse_root),
        MountType::Overlay => {
            if entry.optional {
                eprintln!(
                    "rsc: overlay mount type not yet implemented for {:?} (optional, skipping)",
                    entry.local
                );
                Ok(())
            } else {
                bail!(
                    "overlay mount type not yet implemented (entry: local={:?})",
                    entry.local
                )
            }
        }
    }
}

fn apply_bind(entry: &MountEntry, fuse_root: &str) -> Result<()> {
    let remote_rel = entry.remote.trim_start_matches('/');
    let source_path = format!("{}/{}", fuse_root.trim_end_matches('/'), remote_rel);

    if !std::path::Path::new(&source_path).exists() {
        if entry.optional {
            return Ok(());
        }
        bail!("remote path {source_path:?} not found in FUSE mount");
    }

    // Auto-create target if absent — bind(2) requires the target to already exist.
    let target_path = std::path::Path::new(&entry.local);
    if !target_path.exists() {
        if std::path::Path::new(&source_path).is_dir() {
            fs::create_dir_all(target_path)
                .with_context(|| format!("auto-create target dir {:?}", target_path))?;
        } else {
            if let Some(parent) = target_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("auto-create parent of {:?}", target_path))?;
                }
            }
            fs::File::create(target_path)
                .with_context(|| format!("auto-create target file {:?}", target_path))?;
        }
    }

    let source = CString::new(source_path.as_str()).expect("NUL in source path");
    let target = CString::new(entry.local.as_str()).expect("NUL in target path");

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if entry.optional {
            eprintln!(
                "rsc: bind-mount {:?} → {:?}: {} (optional, skipping)",
                source_path, entry.local, err
            );
            return Ok(());
        }
        bail!("bind-mount {:?} → {:?}: {}", source_path, entry.local, err);
    }

    eprintln!("rsc: bind-mounted {:?} → {:?}", source_path, entry.local);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_profile_parses_and_lists_listen() {
        let profile = builtin_preset("shadow").expect("shadow profile should exist");
        let always = profile.forward_nrs_always();
        // listen (50) must be present now — previously missing entirely.
        assert!(always.contains(&50), "listen missing from shadow's always list: {always:?}");
        // The rest of the always-network syscalls are still there too.
        for nr in [41u32, 42, 44, 45, 49, 54, 55, 288, 46, 47] {
            assert!(always.contains(&nr), "nr={nr} missing from shadow always list: {always:?}");
        }
    }

    #[test]
    fn shadow_profile_fd_gates_generic_fd_syscalls() {
        let profile = builtin_preset("shadow").expect("shadow profile should exist");
        let fd_gated = profile.forward_nrs_fd_gated();
        let always = profile.forward_nrs_always();
        for nr in [0u32, 1, 3, 7, 271, 72] {
            assert!(fd_gated.contains(&nr), "nr={nr} missing from shadow fd-gated list: {fd_gated:?}");
            assert!(!always.contains(&nr), "nr={nr} should not also be in the always list");
        }
    }

    #[test]
    fn ghost_profile_cgroup_filter_still_parses() {
        // Regression check: adding `fd_range` (with #[serde(default)]) to
        // ForwardFilter must not break profiles that only ever set `cgroup`.
        let profile = builtin_preset("ghost").expect("ghost profile should exist");
        assert!(profile.needs_local_cgroup());
        let gated = profile.cgroup_gated_nrs();
        assert!(!gated.is_empty());
        // ghost has no fd_range-filtered rules.
        assert!(profile.forward_nrs_fd_gated().is_empty());
    }

    #[test]
    fn forward_filter_with_only_fd_range_parses_without_cgroup_key() {
        let yaml = r#"
name: test
forward:
  - name: x
    syscalls: [read, write]
    filter:
      fd_range: virtual
"#;
        let profile: MountProfile = serde_yaml::from_str(yaml).expect("should parse");
        assert!(profile.forward[0].has_fd_range_filter());
        assert!(!profile.forward[0].has_cgroup_filter());
    }

    #[test]
    fn builtin_names_include_both_profiles() {
        let names = builtin_names();
        assert!(names.contains(&"ghost"));
        assert!(names.contains(&"shadow"));
    }
}
