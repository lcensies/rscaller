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
    /// Profile to inherit from (mounts and forward rules merged, child overrides parent).
    #[serde(default)]
    pub extends: Option<String>,
    #[serde(default)]
    pub mounts: Vec<MountEntry>,
    /// Ordered forwarding rules. Each rule names syscalls to intercept and an
    /// optional filter controlling when the interception is forwarded to beacon
    /// vs. continued locally.
    #[serde(default)]
    pub forward: Vec<ForwardRule>,
    /// QEMU relay mode: when present, `rsc exec` runs the command inside a
    /// local QEMU VM with the beacon's block device attached (see relay.rs).
    /// Toggle relay mode by pointing --mount-profile at any profile carrying
    /// this section — the built-in `qemu-relay` profile is just the defaults.
    #[serde(default)]
    pub relay: Option<RelayConfig>,
}

// ---------------------------------------------------------------------------
// RelayConfig — QEMU relay VM settings
// ---------------------------------------------------------------------------

pub const DEFAULT_RELAY_ARTIFACTS: &str = "/var/lib/libvirt/images/rscaller-relay";
pub const DEFAULT_RELAY_KERNEL_CMDLINE: &str =
    "root=/dev/vda rw console=ttyS0 quiet init=/vm-init-relay.sh";
pub const DEFAULT_RELAY_MOUNT_POINT: &str = "/mnt/relay";
pub const DEFAULT_RELAY_MEMORY_MIB: u64 = 512;
pub const DEFAULT_RELAY_VCPUS: u32 = 1;

fn default_relay_artifacts() -> std::path::PathBuf {
    std::path::PathBuf::from(DEFAULT_RELAY_ARTIFACTS)
}
fn default_relay_cmdline() -> String {
    DEFAULT_RELAY_KERNEL_CMDLINE.to_string()
}
fn default_relay_mount_point() -> String {
    DEFAULT_RELAY_MOUNT_POINT.to_string()
}
fn default_relay_memory() -> u64 {
    DEFAULT_RELAY_MEMORY_MIB
}
fn default_relay_vcpus() -> u32 {
    DEFAULT_RELAY_VCPUS
}

/// QEMU relay VM configuration. Every field has a default, so a profile can
/// enable relay mode with a bare `relay: {}`; override only what differs.
///
/// Precedence: CLI flag (`--relay-artifacts`, `--relay-device`) > profile
/// `relay:` section > built-in defaults.
#[derive(Deserialize, Clone, Debug)]
pub struct RelayConfig {
    /// Directory containing the relay VM boot artifacts:
    /// `vmlinuz`, `initrd.img`, `rootfs.img`. See docs/qemu-relay.md for how
    /// to prepare a custom image.
    #[serde(default = "default_relay_artifacts")]
    pub artifacts: std::path::PathBuf,
    /// Device on the beacon to attach: absolute path (`/dev/vdb`) or bare
    /// name under the beacon's /dev (`vdb`). When omitted, the beacon's root
    /// device is auto-discovered (LVM-aware) via /proc/mounts + sysfs.
    #[serde(default)]
    pub device: Option<std::path::PathBuf>,
    /// Guest kernel command line. Must match the image's init contract: the
    /// referenced init must start qemu-guest-agent on the virtio-serial
    /// channel and keep PID 1 alive.
    #[serde(default = "default_relay_cmdline")]
    pub kernel_cmdline: String,
    /// Guest-side mount point where the attached device is mounted.
    #[serde(default = "default_relay_mount_point")]
    pub mount_point: String,
    #[serde(default = "default_relay_memory")]
    pub memory_mib: u64,
    #[serde(default = "default_relay_vcpus")]
    pub vcpus: u32,
    /// libvirt connection URI. None = qemu:///session.
    #[serde(default)]
    pub libvirt_uri: Option<String>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            artifacts: default_relay_artifacts(),
            device: None,
            kernel_cmdline: default_relay_cmdline(),
            mount_point: default_relay_mount_point(),
            memory_mib: default_relay_memory(),
            vcpus: default_relay_vcpus(),
            libvirt_uri: None,
        }
    }
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
    /// Network routing policy: ordered list of destination subnet → direction rules.
    /// First match wins. Applies to `connect()` and `sendto()` syscalls.
    #[serde(default)]
    pub net_routes: Option<Vec<NetRoute>>,
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

/// Network routing rule: match destination subnet/port, apply direction (LOCAL or REMOTE).
#[derive(Deserialize, Clone, Debug)]
pub struct NetRoute {
    /// Destination subnet in CIDR notation, e.g. "192.168.1.0/24" or "10.0.0.1/32".
    pub subnet: String,
    /// Optional: specific destination port (host byte order). Omit or 0 for any port.
    #[serde(default)]
    pub port: Option<u16>,
    /// Direction: LOCAL (use tracee's kernel) or REMOTE (forward to beacon).
    pub direction: NetRouteDirection,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum NetRouteDirection {
    Local,
    Remote,
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
    /// Bind-mount from an absolute host path, bypassing the FUSE mount root.
    /// Used by the qemu-relay profile to expose the relay view.
    Host,
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
    let mut profile: MountProfile = serde_yaml::from_str(&text).with_context(|| format!("parsing mount profile {path:?}"))?;
    resolve_extends(&mut profile)?;
    Ok(profile)
}

/// Recursively resolve `extends:` directive: load parent profile, merge mounts/forward.
/// Child values override parent (child mounts append, child forward rules prepend for priority).
fn resolve_extends(profile: &mut MountProfile) -> Result<()> {
    if profile.extends.is_none() {
        return Ok(());
    }
    
    let parent_name = profile.extends.take().ok_or_else(|| anyhow::anyhow!("extends is None after take"))?;
    let mut parent = load(&parent_name)
        .with_context(|| format!("loading parent profile '{}' for '{}'", parent_name, profile.name))?;
    
    // Merge: parent mounts first, then child mounts (child can override/add)
    let mut merged_mounts = parent.mounts;
    merged_mounts.append(&mut profile.mounts);
    profile.mounts = merged_mounts;
    
    // Merge: parent forward rules first, then child forward rules (order matters for priority)
    let mut merged_forward = parent.forward;
    merged_forward.append(&mut profile.forward);
    profile.forward = merged_forward;
    
    // Merge: inherit parent's description if child didn't provide one
    if profile.description.is_empty() {
        profile.description = parent.description;
    }

    // Inherit relay config when the child doesn't define its own.
    if profile.relay.is_none() {
        profile.relay = parent.relay;
    }

    Ok(())
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
        MountType::Host => apply_host_bind(entry),
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
    apply_bind_absolute(entry, &source_path)
}

fn apply_host_bind(entry: &MountEntry) -> Result<()> {
    apply_bind_absolute(entry, &entry.remote)
}

fn apply_bind_absolute(entry: &MountEntry, source_path: &str) -> Result<()> {
    if !std::path::Path::new(source_path).exists() {
        if entry.optional {
            return Ok(());
        }
        bail!("source path {source_path:?} not found");
    }

    // Auto-create target if absent — bind(2) requires the target to already exist.
    let target_path = std::path::Path::new(&entry.local);
    if !target_path.exists() {
        if std::path::Path::new(source_path).is_dir() {
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

    let source = CString::new(source_path).expect("NUL in source path");
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

    #[test]
    fn relay_section_defaults_and_overrides() {
        // Bare section: every field falls back to the built-in default.
        let bare: MountProfile = serde_yaml::from_str("name: t\nrelay: {}\n").unwrap();
        let cfg = bare.relay.expect("relay section present");
        assert_eq!(cfg.artifacts, std::path::PathBuf::from(DEFAULT_RELAY_ARTIFACTS));
        assert_eq!(cfg.kernel_cmdline, DEFAULT_RELAY_KERNEL_CMDLINE);
        assert_eq!(cfg.mount_point, DEFAULT_RELAY_MOUNT_POINT);
        assert_eq!(cfg.memory_mib, DEFAULT_RELAY_MEMORY_MIB);
        assert_eq!(cfg.vcpus, DEFAULT_RELAY_VCPUS);
        assert!(cfg.device.is_none());
        assert!(cfg.libvirt_uri.is_none());

        // Overrides land; profiles without a relay section stay in normal mode.
        let custom: MountProfile = serde_yaml::from_str(
            "name: t\nrelay:\n  artifacts: /opt/img\n  device: /dev/vdc\n  memory_mib: 512\n",
        )
        .unwrap();
        let cfg = custom.relay.unwrap();
        assert_eq!(cfg.artifacts, std::path::PathBuf::from("/opt/img"));
        assert_eq!(cfg.device, Some(std::path::PathBuf::from("/dev/vdc")));
        assert_eq!(cfg.memory_mib, 512);
        assert_eq!(cfg.vcpus, DEFAULT_RELAY_VCPUS); // untouched field keeps default
        let plain: MountProfile = serde_yaml::from_str("name: t\n").unwrap();
        assert!(plain.relay.is_none());
    }

    #[test]
    fn builtin_qemu_relay_profile_enables_relay_mode() {
        let profile = builtin_preset("qemu-relay").expect("qemu-relay preset exists");
        let cfg = profile.relay.expect("qemu-relay must carry a relay section");
        assert!(cfg.kernel_cmdline.contains("init="));
    }
}
