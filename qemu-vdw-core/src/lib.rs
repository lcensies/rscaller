//! `qemu-vdw-core`: an SDK-first Rust library for the
//! `qemu-direct-device-write` PoC.
//!
//! This crate exposes three composable, independently callable
//! capabilities — every one of them a plain library function/trait, with
//! no CLI, daemon, or other consumer required to use them:
//!
//! 1. [`discovery`] — **root/passthrough device discovery**: find a host
//!    block device eligible for VM passthrough (plain, LUKS, or LVM),
//!    read-only, returning a typed [`discovery::PassthroughDevice`]
//!    instead of parsed `blkid`/`lvs` text.
//! 2. [`provisioning`] — **QEMU VM provisioning**: define and start a
//!    QEMU/KVM domain from a caller-supplied disk image via the libvirt
//!    SDK (the `virt` crate), optionally attaching a passthrough device,
//!    returning a [`provisioning::VmHandle`] with lifecycle operations.
//! 3. [`mount`] — **guest mount orchestration**: given a running VM and a
//!    passthrough device, mount it at a caller-specified path *inside the
//!    guest* (resolving LUKS/LVM layers as needed) over the QEMU Guest
//!    Agent, and report back the resolved device/target.
//!
//! `qemu-vdw-cli` (a sibling crate in this workspace) is a thin binary
//! that only calls into these three APIs — proof that nothing here
//! requires a CLI to be useful. See the originating change's
//! `proposal.md`/`design.md`/`specs/` for the full requirements and
//! rationale (in particular, why libvirt + the QEMU Guest Agent were
//! chosen over a hand-built `qemu-system-x86_64` invocation and a
//! baked-in guest init script).
//!
//! # Typical flow
//!
//! ```no_run
//! use std::time::Duration;
//! use qemu_vdw_core::discovery::{CliProbeDiscoverer, RootDeviceDiscoverer};
//! use qemu_vdw_core::provisioning::{self, ProvisionRequest};
//! use qemu_vdw_core::mount::{self, MountRequest};
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Discover a candidate host device.
//! let devices = CliProbeDiscoverer::new().discover()?;
//! let device = devices.first().expect("at least one eligible device");
//!
//! // 2. Provision a VM from a caller-supplied disk image, attaching it.
//! let request = ProvisionRequest::new("/boot/vmlinuz", "/boot/initrd.img", "/images/rootfs.img")
//!     .with_discovered_device(device);
//! let vm = provisioning::provision(&request)?;
//!
//! // 3. Mount the device at a caller-chosen path inside the guest.
//! let mount_req = MountRequest::new(device, "/mnt/whatever").with_timeout(Duration::from_secs(30));
//! let result = mount::mount_device(&vm, &mount_req)?;
//! println!("mounted {} at {}", result.resolved_device, result.target_path);
//! # Ok(())
//! # }
//! ```

pub mod discovery;
pub mod mount;
pub mod provisioning;

pub use mount::{exec_in_guest, GuestExecResult};
