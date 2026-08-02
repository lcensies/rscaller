//! Root/passthrough device discovery.
//!
//! This module answers one question: *which host block device should be
//! passed through to a guest VM, and what does the caller need to know
//! about it (plain filesystem, LUKS container, or LVM logical volume) in
//! order to mount it later via [`crate::mount`]?*
//!
//! Discovery is strictly **read-only**: it never opens a LUKS container,
//! activates a volume group, or mounts anything. See
//! `specs/root-device-discovery/spec.md` in the originating change for the
//! full requirements this module implements.

mod cli_probe;

pub use cli_probe::CliProbeDiscoverer;

use std::path::PathBuf;

/// How a [`PassthroughDevice`] is classified after a read-only probe.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeviceKind {
    /// A block device with a directly-mountable filesystem signature
    /// (ext4, xfs, vfat, ntfs, ...).
    Plain,
    /// A block device carrying a `crypto_LUKS` signature. Its contents are
    /// opaque until it is opened (which discovery deliberately never does).
    Luks,
    /// An LVM logical volume, resolvable directly from the host's LVM
    /// metadata without activating anything new (i.e. the volume group was
    /// already active, or its metadata is readable in place).
    Lvm {
        volume_group: String,
        logical_volume: String,
    },
}

/// A host block device eligible for VM passthrough, together with its
/// read-only classification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PassthroughDevice {
    /// The device node to pass through to the guest (e.g. `/dev/sda2`, or
    /// `/dev/vgname/lvname` for an already-resolvable LVM logical volume).
    pub path: PathBuf,
    pub kind: DeviceKind,
}

impl PassthroughDevice {
    /// Construct a device description directly, bypassing discovery.
    ///
    /// Per design.md's open question: callers are not required to go
    /// through [`RootDeviceDiscoverer`] — they may already know the exact
    /// device path and classification (e.g. from their own inventory) and
    /// hand it straight to [`crate::provisioning`] / [`crate::mount`].
    pub fn new(path: impl Into<PathBuf>, kind: DeviceKind) -> Self {
        Self {
            path: path.into(),
            kind,
        }
    }
}

/// Errors a [`RootDeviceDiscoverer`] implementation can return.
///
/// Distinguishes "a required tool is missing" from "a tool ran but failed"
/// from "a tool succeeded but its output could not be parsed", per the
/// "Discovery failures are typed and actionable" requirement.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("required probing tool `{tool}` is not available on this host: {source}")]
    ToolUnavailable {
        tool: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("probing tool `{tool}` exited with a failure it did not expect: {stderr}")]
    ToolFailed { tool: &'static str, stderr: String },

    #[error("could not parse output of `{tool}`: {reason}")]
    ParseError { tool: &'static str, reason: String },
}

/// Enumerates host block devices eligible for VM passthrough.
///
/// Implementations MUST be read-only (see module docs). The default,
/// production implementation is [`CliProbeDiscoverer`], which wraps
/// `blkid`, `cryptsetup isLuks`, and `lvs` — already-installed tools on the
/// PoC's guest/host images — behind this trait so a future native
/// (`libblkid`/`libudev`) implementation can replace it without changing
/// callers.
pub trait RootDeviceDiscoverer {
    fn discover(&self) -> Result<Vec<PassthroughDevice>, DiscoveryError>;
}
