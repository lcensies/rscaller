//! QEMU VM provisioning via the libvirt SDK.
//!
//! Defines and starts a QEMU/KVM domain from a caller-supplied disk image
//! (the guest OS — e.g. the PoC's `rootfs.img`) plus the kernel/initrd
//! boot artifacts, optionally attaching a [`PassthroughDevice`] discovered
//! by [`crate::discovery`]. See `specs/qemu-vm-provisioning/spec.md` and
//! design.md Decision 2 for the full requirements and rationale (libvirt
//! over a hand-built `qemu-system-x86_64` argv).

mod xml;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use virt::connect::Connect;
use virt::domain::Domain;

use crate::discovery::PassthroughDevice;

/// Default libvirt connection URI: a per-user session daemon, matching the
/// PoC's current no-root-required `qemu-system-x86_64` invocation (see
/// design.md's "Open Questions").
pub const DEFAULT_LIBVIRT_URI: &str = "qemu:///session";

/// Default guest kernel command line: boots the disk image at `vda` as
/// root and hands control to the SDK's guest-agent-enabled init script
/// (see `scripts/vm-sdk-init.sh`).
pub const DEFAULT_KERNEL_CMDLINE: &str = "root=/dev/vda rw console=ttyS0 quiet init=/vm-sdk-init.sh";

/// The libvirt/QEMU target device name a passthrough device is always
/// attached as. [`crate::mount`] relies on this to know which guest-side
/// device node (`/dev/vdb`) corresponds to a [`PassthroughDevice`]'s
/// host-side path.
pub const PASSTHROUGH_TARGET_DEV: &str = "vdb";

/// Everything needed to define and start a VM.
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    /// The guest OS disk image (attached as `vda`) — e.g. the PoC's
    /// `artifacts/rootfs.img`.
    pub disk_image: PathBuf,
    /// A device discovered via [`crate::discovery`] (or constructed
    /// directly), attached raw as `vdb` for the guest to inspect/mount.
    pub passthrough_device: Option<PathBuf>,
    pub kernel_cmdline: String,
    pub memory_mib: u64,
    pub vcpus: u32,
    /// `None` means [`DEFAULT_LIBVIRT_URI`].
    pub libvirt_uri: Option<String>,
    /// `None` means a generated, unique-per-call name.
    pub domain_name: Option<String>,
}

impl ProvisionRequest {
    pub fn new(
        kernel: impl Into<PathBuf>,
        initrd: impl Into<PathBuf>,
        disk_image: impl Into<PathBuf>,
    ) -> Self {
        Self {
            kernel: kernel.into(),
            initrd: initrd.into(),
            disk_image: disk_image.into(),
            passthrough_device: None,
            kernel_cmdline: DEFAULT_KERNEL_CMDLINE.to_string(),
            memory_mib: 2048,
            vcpus: 2,
            libvirt_uri: None,
            domain_name: None,
        }
    }

    /// Attach a passthrough device by path (e.g. `passthrough.path` from a
    /// [`PassthroughDevice`] returned by [`crate::discovery`]).
    pub fn with_passthrough_device(mut self, device: impl Into<PathBuf>) -> Self {
        self.passthrough_device = Some(device.into());
        self
    }

    /// Convenience: attach the device path from a discovered
    /// [`PassthroughDevice`] directly.
    pub fn with_discovered_device(self, device: &PassthroughDevice) -> Self {
        self.with_passthrough_device(device.path.clone())
    }

    pub fn with_memory_mib(mut self, mib: u64) -> Self {
        self.memory_mib = mib;
        self
    }

    pub fn with_vcpus(mut self, vcpus: u32) -> Self {
        self.vcpus = vcpus;
        self
    }

    pub fn with_kernel_cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.kernel_cmdline = cmdline.into();
        self
    }

    pub fn with_libvirt_uri(mut self, uri: impl Into<String>) -> Self {
        self.libvirt_uri = Some(uri.into());
        self
    }

    pub fn with_domain_name(mut self, name: impl Into<String>) -> Self {
        self.domain_name = Some(name.into());
        self
    }
}

/// Errors returned while defining/starting/operating a VM. Connection
/// failures are kept distinct from domain-definition/start/operation
/// failures per the "Provisioning failures are typed and actionable"
/// requirement.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("missing required {role} artifact at {path}")]
    MissingArtifact { role: &'static str, path: PathBuf },

    #[error("could not connect to libvirt at `{uri}`: {source}")]
    ConnectionFailed {
        uri: String,
        #[source]
        source: virt::error::Error,
    },

    #[error("libvirt rejected the domain definition: {source}")]
    DomainDefinitionFailed {
        #[source]
        source: virt::error::Error,
    },

    #[error("failed to start the defined domain: {source}")]
    DomainStartFailed {
        #[source]
        source: virt::error::Error,
    },

    #[error("domain operation failed: {source}")]
    DomainOperationFailed {
        #[source]
        source: virt::error::Error,
    },
}

/// The state of a provisioned VM, mapped from libvirt's `virDomainState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    NoState,
    Running,
    Blocked,
    Paused,
    ShuttingDown,
    ShutOff,
    Crashed,
    PmSuspended,
    Unknown(u32),
}

impl VmState {
    fn from_raw(raw: virt::sys::virDomainState) -> Self {
        match raw {
            virt::sys::VIR_DOMAIN_NOSTATE => VmState::NoState,
            virt::sys::VIR_DOMAIN_RUNNING => VmState::Running,
            virt::sys::VIR_DOMAIN_BLOCKED => VmState::Blocked,
            virt::sys::VIR_DOMAIN_PAUSED => VmState::Paused,
            virt::sys::VIR_DOMAIN_SHUTDOWN => VmState::ShuttingDown,
            virt::sys::VIR_DOMAIN_SHUTOFF => VmState::ShutOff,
            virt::sys::VIR_DOMAIN_CRASHED => VmState::Crashed,
            virt::sys::VIR_DOMAIN_PMSUSPENDED => VmState::PmSuspended,
            other => VmState::Unknown(other),
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, VmState::Running)
    }
}

/// A handle to a running (or since-stopped) VM. Exposes just enough
/// lifecycle control for callers that don't want to touch libvirt/QEMU
/// directly; [`crate::mount`] additionally uses [`VmHandle::domain`] to
/// reach the QEMU guest agent channel.
#[derive(Debug)]
pub struct VmHandle {
    connect: Connect,
    domain: Domain,
    name: String,
}

impl VmHandle {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn state(&self) -> Result<VmState, ProvisionError> {
        let (raw, _reason) = self
            .domain
            .get_state()
            .map_err(|source| ProvisionError::DomainOperationFailed { source })?;
        Ok(VmState::from_raw(raw))
    }

    /// Stop the VM. Provisioned VMs are treated as ephemeral/one-shot (as
    /// the existing PoC's scripts already do), so this destroys the
    /// domain immediately rather than requesting a graceful ACPI shutdown.
    pub fn stop(&self) -> Result<(), ProvisionError> {
        self.domain
            .destroy()
            .map_err(|source| ProvisionError::DomainOperationFailed { source })?;
        Ok(())
    }

    /// Undefine the domain, removing its persistent XML from libvirt.
    /// Call after [`stop`] (or when the domain is already shut off) to
    /// release the domain name.
    pub fn undefine(&self) -> Result<(), ProvisionError> {
        self.domain
            .undefine()
            .map_err(|source| ProvisionError::DomainOperationFailed { source })?;
        Ok(())
    }

    /// The underlying libvirt domain handle, used by [`crate::mount`] to
    /// issue QEMU guest agent commands.
    pub fn domain(&self) -> &Domain {
        &self.domain
    }
}

impl Drop for VmHandle {
    fn drop(&mut self) {
        // Best-effort: release the libvirt connection. Failure here isn't
        // actionable by the caller and the domain itself is unaffected.
        let _ = self.connect.close();
    }
}

/// Define and start a VM per `req`, returning a handle to it once running.
pub fn provision(req: &ProvisionRequest) -> Result<VmHandle, ProvisionError> {
    require_exists("kernel", &req.kernel)?;
    require_exists("initrd", &req.initrd)?;
    require_exists("disk image", &req.disk_image)?;
    if let Some(device) = &req.passthrough_device {
        require_exists("passthrough device", device)?;
    }

    let uri = req.libvirt_uri.as_deref().unwrap_or(DEFAULT_LIBVIRT_URI);
    let connect = Connect::open(Some(uri)).map_err(|source| ProvisionError::ConnectionFailed {
        uri: uri.to_string(),
        source,
    })?;

    let name = req.domain_name.clone().unwrap_or_else(generate_domain_name);
    let domain_xml = xml::build_domain_xml(&name, req);

    let domain = Domain::define_xml(&connect, &domain_xml)
        .map_err(|source| ProvisionError::DomainDefinitionFailed { source })?;
    domain
        .create()
        .map_err(|source| ProvisionError::DomainStartFailed { source })?;

    Ok(VmHandle {
        connect,
        domain,
        name,
    })
}

/// Reconnect to an already-defined, running VM by its domain name — e.g.
/// from a separate process invocation than the one that called
/// [`provision`]. Lets [`crate::mount`] be driven against a VM that was
/// provisioned earlier, without keeping the provisioning process alive.
pub fn attach(name: &str, libvirt_uri: Option<&str>) -> Result<VmHandle, ProvisionError> {
    let uri = libvirt_uri.unwrap_or(DEFAULT_LIBVIRT_URI);
    let connect = Connect::open(Some(uri)).map_err(|source| ProvisionError::ConnectionFailed {
        uri: uri.to_string(),
        source,
    })?;
    let domain = Domain::lookup_by_name(&connect, name)
        .map_err(|source| ProvisionError::DomainOperationFailed { source })?;
    Ok(VmHandle {
        connect,
        domain,
        name: name.to_string(),
    })
}

fn require_exists(role: &'static str, path: &Path) -> Result<(), ProvisionError> {
    if path.exists() {
        Ok(())
    } else {
        Err(ProvisionError::MissingArtifact {
            role,
            path: path.to_path_buf(),
        })
    }
}

fn generate_domain_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("qemu-vdw-{nanos:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_kernel_is_reported_before_any_libvirt_call() {
        let req = ProvisionRequest::new(
            "/nonexistent/vmlinuz",
            "/nonexistent/initrd.img",
            "/nonexistent/rootfs.img",
        );
        let err = provision(&req).unwrap_err();
        match err {
            ProvisionError::MissingArtifact { role, path } => {
                assert_eq!(role, "kernel");
                assert_eq!(path, PathBuf::from("/nonexistent/vmlinuz"));
            }
            other => panic!("expected MissingArtifact, got {other:?}"),
        }
    }

    #[test]
    fn missing_passthrough_device_is_reported() {
        // Kernel/initrd/disk image all point at this crate's own
        // Cargo.toml (guaranteed to exist), so the first path check to
        // fail is the passthrough device.
        let existing = existing_placeholder_path();
        let req = ProvisionRequest::new(&existing, &existing, &existing)
            .with_passthrough_device("/nonexistent/device");
        let err = provision(&req).unwrap_err();
        match err {
            ProvisionError::MissingArtifact { role, .. } => assert_eq!(role, "passthrough device"),
            other => panic!("expected MissingArtifact, got {other:?}"),
        }
    }

    #[test]
    fn unreachable_libvirt_uri_is_a_connection_error_not_a_panic() {
        let existing = existing_placeholder_path();
        let req = ProvisionRequest::new(&existing, &existing, &existing)
            .with_libvirt_uri("test+bogus-driver:///does-not-exist");
        let err = provision(&req).unwrap_err();
        match err {
            ProvisionError::ConnectionFailed { uri, .. } => {
                assert_eq!(uri, "test+bogus-driver:///does-not-exist");
            }
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }
    }

    fn existing_placeholder_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
    }
}
