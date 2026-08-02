//! Guest mount orchestration.
//!
//! Given a running VM (from [`crate::provisioning`]) and a
//! [`PassthroughDevice`] (from [`crate::discovery`], or constructed
//! directly), mounts it at a caller-specified path *inside the guest*,
//! resolving LUKS/LVM layers as needed. See
//! `specs/guest-mount-orchestration/spec.md` and design.md Decision 3
//! (QEMU Guest Agent `guest-exec`, not a baked-in init script).

mod guest_agent;

use std::path::PathBuf;
use std::time::Duration;

use crate::discovery::{DeviceKind, PassthroughDevice};
use crate::provisioning::{VmHandle, PASSTHROUGH_TARGET_DEV};

pub use guest_agent::{GuestAgentError, GuestExecResult};

/// Abstraction over "run a command inside the guest and wait for it to
/// finish", so the orchestration sequencing in [`mount_via`] can be unit
/// tested with a fake channel instead of a live libvirt/QEMU guest agent.
/// The production implementation ([`LibvirtChannel`]) drives this over
/// libvirt's `virDomainQemuAgentCommand` (see `guest_agent`).
pub(crate) trait GuestAgentChannel {
    fn exec(
        &self,
        path: &str,
        args: &[&str],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<GuestExecResult, GuestAgentError>;
}

struct LibvirtChannel<'d> {
    domain: &'d virt::domain::Domain,
}

impl<'d> GuestAgentChannel for LibvirtChannel<'d> {
    fn exec(
        &self,
        path: &str,
        args: &[&str],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<GuestExecResult, GuestAgentError> {
        guest_agent::guest_exec(self.domain, path, args, input, timeout)
    }
}

/// The name `guest-mount-orchestration` opens a LUKS passthrough device
/// under, i.e. it appears as `/dev/mapper/<MAPPER_NAME>` in the guest.
const MAPPER_NAME: &str = "vdw-crypt";

/// A mount request: which device (and how to unlock it, if needed), and
/// where to mount it inside the guest.
#[derive(Debug, Clone)]
pub struct MountRequest<'a> {
    pub device: &'a PassthroughDevice,
    pub target_path: String,
    /// Passphrase/key material for `Luks` devices. Sent to `cryptsetup
    /// open`'s stdin over the guest-agent channel — never placed on an
    /// argv where it could leak via `ps`.
    pub luks_key: Option<Vec<u8>>,
    /// Bounded timeout applied to each guest-agent round trip and to the
    /// overall wait for a command to finish executing in the guest.
    pub timeout: Duration,
}

impl<'a> MountRequest<'a> {
    pub fn new(device: &'a PassthroughDevice, target_path: impl Into<String>) -> Self {
        Self {
            device,
            target_path: target_path.into(),
            luks_key: None,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_luks_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.luks_key = Some(key.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// The outcome of a successful mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountResult {
    /// The original, host-known device path from the [`PassthroughDevice`]
    /// this request was built from.
    pub passthrough_device: PathBuf,
    /// The device actually passed to `mount(8)` inside the guest — may
    /// differ from the passthrough device's host path (e.g. an opened
    /// LUKS mapper device, or an activated LVM logical volume).
    pub resolved_device: String,
    pub target_path: String,
}

/// Errors mounting a device inside the guest. Kept distinguishable per
/// step so callers can tell "the channel is down" apart from "the key was
/// wrong" apart from "the mount command itself failed".
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    #[error("guest agent unreachable: {0}")]
    GuestAgentUnreachable(String),

    #[error("no LUKS key material was supplied for {device}")]
    MissingKeyMaterial { device: PathBuf },

    #[error("failed to open LUKS container: {detail}")]
    LuksOpenFailed { detail: String },

    #[error("failed to activate volume group `{volume_group}`: {detail}")]
    LvmActivationFailed { volume_group: String, detail: String },

    #[error("failed to mount {resolved_device} at {target_path}: {detail}")]
    MountFailed {
        resolved_device: String,
        target_path: String,
        detail: String,
    },
}

impl From<GuestAgentError> for MountError {
    fn from(err: GuestAgentError) -> Self {
        MountError::GuestAgentUnreachable(err.to_string())
    }
}

/// Mount `req.device` at `req.target_path` inside the guest managed by
/// `handle`.
pub fn mount_device(handle: &VmHandle, req: &MountRequest<'_>) -> Result<MountResult, MountError> {
    let channel = LibvirtChannel {
        domain: handle.domain(),
    };
    mount_via(&channel, req)
}

/// Run an arbitrary command inside the guest managed by `handle`.
pub fn exec_in_guest(
    handle: &VmHandle,
    path: &str,
    args: &[&str],
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<GuestExecResult, GuestAgentError> {
    guest_agent::guest_exec(handle.domain(), path, args, input, timeout)
}

/// The actual orchestration sequencing, generic over [`GuestAgentChannel`]
/// so it can be unit tested (see the `tests` module below) without a live
/// libvirt/QEMU guest agent.
fn mount_via(channel: &impl GuestAgentChannel, req: &MountRequest<'_>) -> Result<MountResult, MountError> {
    let guest_device = format!("/dev/{PASSTHROUGH_TARGET_DEV}");

    let resolved_device = match &req.device.kind {
        DeviceKind::Plain => guest_device,

        DeviceKind::Luks => {
            let key = req
                .luks_key
                .as_ref()
                .ok_or_else(|| MountError::MissingKeyMaterial {
                    device: req.device.path.clone(),
                })?;

            let open = channel.exec(
                "/sbin/cryptsetup",
                &["open", &guest_device, MAPPER_NAME],
                Some(key.as_slice()),
                req.timeout,
            )?;
            if !open.success() {
                return Err(MountError::LuksOpenFailed {
                    detail: open.stderr_string(),
                });
            }

            // Best-effort: activate any LVM VG that might live inside the
            // now-decrypted container (mirrors scripts/vm-enter.sh). A
            // plain-ext4-on-LUKS layout has no VG, so a failure here is
            // expected and not itself fatal to the mount.
            let _ = channel.exec("/sbin/vgchange", &["-ay"], None, req.timeout);

            first_active_lv(channel, req.timeout).unwrap_or_else(|| format!("/dev/mapper/{MAPPER_NAME}"))
        }

        DeviceKind::Lvm {
            volume_group,
            logical_volume,
        } => {
            let activate = channel.exec("/sbin/vgchange", &["-ay", volume_group], None, req.timeout)?;
            if !activate.success() {
                return Err(MountError::LvmActivationFailed {
                    volume_group: volume_group.clone(),
                    detail: activate.stderr_string(),
                });
            }
            format!("/dev/{volume_group}/{logical_volume}")
        }
    };

    let mkdir = channel.exec("/bin/mkdir", &["-p", &req.target_path], None, req.timeout)?;
    if !mkdir.success() {
        return Err(MountError::MountFailed {
            resolved_device: resolved_device.clone(),
            target_path: req.target_path.clone(),
            detail: mkdir.stderr_string(),
        });
    }

    let mount = channel.exec(
        "/bin/mount",
        &[resolved_device.as_str(), req.target_path.as_str()],
        None,
        req.timeout,
    )?;
    if !mount.success() {
        return Err(MountError::MountFailed {
            resolved_device: resolved_device.clone(),
            target_path: req.target_path.clone(),
            detail: mount.stderr_string(),
        });
    }

    Ok(MountResult {
        passthrough_device: req.device.path.clone(),
        resolved_device,
        target_path: req.target_path.clone(),
    })
}

/// Best-effort: after activating VGs, ask `lvs` for any logical volume's
/// device path (mirrors `scripts/vm-enter.sh`'s
/// `lvs --noheadings -o lv_path | head -1`).
fn first_active_lv(channel: &impl GuestAgentChannel, timeout: Duration) -> Option<String> {
    let result = channel
        .exec("/sbin/lvs", &["--noheadings", "-o", "lv_path"], None, timeout)
        .ok()?;
    if !result.success() {
        return None;
    }
    String::from_utf8_lossy(&result.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// A [`GuestAgentChannel`] that returns pre-scripted results per
    /// `(path, args)` invocation and records the calls made, so tests can
    /// assert both outcomes and exact orchestration sequencing without any
    /// real VM.
    #[derive(Default)]
    struct FakeChannel {
        responses: RefCell<HashMap<(String, Vec<String>), Result<GuestExecResult, String>>>,
        calls: RefCell<Vec<(String, Vec<String>)>>,
    }

    impl FakeChannel {
        fn ok(&self, path: &str, args: &[&str], exit_code: i32, stdout: &str, stderr: &str) {
            self.responses.borrow_mut().insert(
                (path.to_string(), args.iter().map(|s| s.to_string()).collect()),
                Ok(GuestExecResult {
                    exit_code,
                    stdout: stdout.as_bytes().to_vec(),
                    stderr: stderr.as_bytes().to_vec(),
                }),
            );
        }

        fn unreachable(&self, path: &str, args: &[&str]) {
            self.responses.borrow_mut().insert(
                (path.to_string(), args.iter().map(|s| s.to_string()).collect()),
                Err("simulated unreachable guest agent".to_string()),
            );
        }

        fn call_count(&self) -> usize {
            self.calls.borrow().len()
        }
    }

    impl GuestAgentChannel for FakeChannel {
        fn exec(
            &self,
            path: &str,
            args: &[&str],
            _input: Option<&[u8]>,
            _timeout: Duration,
        ) -> Result<GuestExecResult, GuestAgentError> {
            let key = (path.to_string(), args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            self.calls.borrow_mut().push(key.clone());
            match self.responses.borrow().get(&key) {
                Some(Ok(result)) => Ok(result.clone()),
                Some(Err(detail)) => Err(GuestAgentError::Unreachable {
                    timeout: Duration::from_secs(1),
                    detail: Some(detail.clone()),
                }),
                None => panic!("unscripted guest-exec: {path} {args:?}"),
            }
        }
    }

    fn plain_device() -> PassthroughDevice {
        PassthroughDevice::new("/dev/sdb1", DeviceKind::Plain)
    }

    fn luks_device() -> PassthroughDevice {
        PassthroughDevice::new("/dev/sdb2", DeviceKind::Luks)
    }

    fn lvm_device() -> PassthroughDevice {
        PassthroughDevice::new(
            "/dev/sdc1",
            DeviceKind::Lvm {
                volume_group: "data-vg".to_string(),
                logical_volume: "data-lv".to_string(),
            },
        )
    }

    #[test]
    fn mounts_a_plain_device_at_the_caller_specified_target() {
        let channel = FakeChannel::default();
        channel.ok("/bin/mkdir", &["-p", "/mnt/whatever"], 0, "", "");
        channel.ok("/bin/mount", &["/dev/vdb", "/mnt/whatever"], 0, "", "");

        let device = plain_device();
        let req = MountRequest::new(&device, "/mnt/whatever");
        let result = mount_via(&channel, &req).unwrap();

        assert_eq!(result.resolved_device, "/dev/vdb");
        assert_eq!(result.target_path, "/mnt/whatever");
        assert_eq!(result.passthrough_device, PathBuf::from("/dev/sdb1"));
    }

    #[test]
    fn mounts_a_luks_device_after_opening_it() {
        let channel = FakeChannel::default();
        channel.ok("/sbin/cryptsetup", &["open", "/dev/vdb", MAPPER_NAME], 0, "", "");
        channel.ok("/sbin/vgchange", &["-ay"], 1, "", "no VG found");
        channel.ok("/sbin/lvs", &["--noheadings", "-o", "lv_path"], 0, "", "");
        channel.ok("/bin/mkdir", &["-p", "/mnt/secret"], 0, "", "");
        channel.ok(
            "/bin/mount",
            &[format!("/dev/mapper/{MAPPER_NAME}").as_str(), "/mnt/secret"],
            0,
            "",
            "",
        );

        let device = luks_device();
        let req = MountRequest::new(&device, "/mnt/secret").with_luks_key(b"correct horse".to_vec());
        let result = mount_via(&channel, &req).unwrap();

        assert_eq!(result.resolved_device, format!("/dev/mapper/{MAPPER_NAME}"));
        assert_eq!(result.passthrough_device, PathBuf::from("/dev/sdb2"));
    }

    #[test]
    fn mounts_an_lvm_device_after_activating_its_volume_group() {
        let channel = FakeChannel::default();
        channel.ok("/sbin/vgchange", &["-ay", "data-vg"], 0, "", "");
        channel.ok("/bin/mkdir", &["-p", "/mnt/data"], 0, "", "");
        channel.ok("/bin/mount", &["/dev/data-vg/data-lv", "/mnt/data"], 0, "", "");

        let device = lvm_device();
        let req = MountRequest::new(&device, "/mnt/data");
        let result = mount_via(&channel, &req).unwrap();

        assert_eq!(result.resolved_device, "/dev/data-vg/data-lv");
    }

    #[test]
    fn two_calls_can_target_two_independent_paths() {
        let channel = FakeChannel::default();
        channel.ok("/bin/mkdir", &["-p", "/mnt/a"], 0, "", "");
        channel.ok("/bin/mount", &["/dev/vdb", "/mnt/a"], 0, "", "");
        channel.ok("/bin/mkdir", &["-p", "/mnt/b"], 0, "", "");
        channel.ok("/bin/mount", &["/dev/vdb", "/mnt/b"], 0, "", "");

        let device = plain_device();
        let first = mount_via(&channel, &MountRequest::new(&device, "/mnt/a")).unwrap();
        let second = mount_via(&channel, &MountRequest::new(&device, "/mnt/b")).unwrap();

        assert_eq!(first.target_path, "/mnt/a");
        assert_eq!(second.target_path, "/mnt/b");
    }

    #[test]
    fn guest_agent_unreachable_is_reported_without_hanging() {
        let channel = FakeChannel::default();
        channel.unreachable("/bin/mkdir", &["-p", "/mnt/whatever"]);

        let device = plain_device();
        let req = MountRequest::new(&device, "/mnt/whatever").with_timeout(Duration::from_millis(50));
        let err = mount_via(&channel, &req).unwrap_err();

        assert!(matches!(err, MountError::GuestAgentUnreachable(_)));
    }

    #[test]
    fn luks_open_failure_stops_before_mounting() {
        let channel = FakeChannel::default();
        channel.ok(
            "/sbin/cryptsetup",
            &["open", "/dev/vdb", MAPPER_NAME],
            1,
            "",
            "No key available with this passphrase.",
        );

        let device = luks_device();
        let req = MountRequest::new(&device, "/mnt/secret").with_luks_key(b"wrong".to_vec());
        let err = mount_via(&channel, &req).unwrap_err();

        assert!(matches!(err, MountError::LuksOpenFailed { .. }));
        // Only the failed cryptsetup call happened - no vgchange/mkdir/mount.
        assert_eq!(channel.call_count(), 1);
    }

    #[test]
    fn missing_luks_key_is_reported_without_any_guest_call() {
        let channel = FakeChannel::default();
        let device = luks_device();
        let req = MountRequest::new(&device, "/mnt/secret");

        let err = mount_via(&channel, &req).unwrap_err();

        assert!(matches!(err, MountError::MissingKeyMaterial { .. }));
        assert_eq!(channel.call_count(), 0);
    }

    #[test]
    fn mount_command_failure_reports_guest_detail() {
        let channel = FakeChannel::default();
        channel.ok("/bin/mkdir", &["-p", "/mnt/whatever"], 0, "", "");
        channel.ok(
            "/bin/mount",
            &["/dev/vdb", "/mnt/whatever"],
            32,
            "",
            "mount: unknown filesystem type",
        );

        let device = plain_device();
        let req = MountRequest::new(&device, "/mnt/whatever");
        let err = mount_via(&channel, &req).unwrap_err();

        match err {
            MountError::MountFailed { detail, .. } => {
                assert!(detail.contains("unknown filesystem type"))
            }
            other => panic!("expected MountFailed, got {other:?}"),
        }
    }
}
