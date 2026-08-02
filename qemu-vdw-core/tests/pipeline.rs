//! End-to-end integration test: discover -> provision -> mount against the
//! PoC's real, `make build`-produced boot artifacts and a real libvirt/KVM
//! stack.
//!
//! This test is deliberately `#[ignore]`d by default (per tasks.md 4.2):
//! it needs a real environment, not just `cargo test`:
//!
//! - `libvirtd` reachable at `qemu:///session` (or `QEMU_VDW_TEST_URI`),
//!   with KVM available;
//! - `../artifacts/{vmlinuz,initrd.img,rootfs.img}` present (`make build`
//!   in the repo root);
//! - for the mount assertions specifically: a `rootfs.img` built *after*
//!   `qemu-guest-agent` was added to the root `Dockerfile` and
//!   `scripts/vm-sdk-init.sh` was wired into `scripts/build-rootfs.sh` /
//!   `scripts/Dockerfile.builder` (see design.md Decision 3) — an older
//!   `rootfs.img` predating that change will provision fine but the mount
//!   step will time out waiting for a guest agent that was never started;
//! - a spare raw block device the test process is allowed to attach and
//!   overwrite, given via `QEMU_VDW_TEST_PASSTHROUGH_DEVICE` (e.g. a spare
//!   loop device set up with `losetup`). Without it, the test still
//!   exercises discovery + provisioning end-to-end and skips the mount
//!   step.
//!
//! Run with: `cargo test --test pipeline -- --ignored`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use qemu_vdw_core::discovery::{CliProbeDiscoverer, RootDeviceDiscoverer};
use qemu_vdw_core::mount::{self, MountRequest};
use qemu_vdw_core::provisioning::{self, ProvisionRequest, VmState};

fn artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("artifacts")
}

fn require_artifact(path: &Path) {
    assert!(
        path.exists(),
        "missing {path:?} — run `make build` in the repo root before this test"
    );
}

#[test]
#[ignore = "requires a real libvirtd/KVM stack and make build's boot artifacts"]
fn discover_provision_and_optionally_mount() {
    let artifacts = artifacts_dir();
    let kernel = artifacts.join("vmlinuz");
    let initrd = artifacts.join("initrd.img");
    let rootfs = artifacts.join("rootfs.img");
    require_artifact(&kernel);
    require_artifact(&initrd);
    require_artifact(&rootfs);

    // 1. Discovery: exercised for real against whatever this host
    // actually has. We don't assert on its contents (CI hosts vary
    // wildly), just that it runs without erroring.
    let discovered = CliProbeDiscoverer::new()
        .discover()
        .expect("root-device-discovery should not fail on a normal Linux host");
    eprintln!("discovered {} candidate device(s)", discovered.len());

    // 2. Provisioning: define + start a real VM via libvirt.
    let uri = std::env::var("QEMU_VDW_TEST_URI").ok();
    let passthrough = std::env::var("QEMU_VDW_TEST_PASSTHROUGH_DEVICE").ok();

    let mut request = ProvisionRequest::new(kernel, initrd, rootfs)
        .with_domain_name(format!("qemu-vdw-pipeline-test-{}", std::process::id()));
    if let Some(uri) = &uri {
        request = request.with_libvirt_uri(uri.clone());
    }
    if let Some(device) = &passthrough {
        request = request.with_passthrough_device(device);
    }

    let vm = provisioning::provision(&request).expect("provisioning should succeed against a real libvirt/KVM stack");

    // Give the guest a moment to actually reach "running" (libvirt
    // reports the domain running essentially immediately, but poll
    // briefly to be robust against slow schedulers).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match vm.state() {
            Ok(VmState::Running) => break,
            Ok(_other) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            Ok(other) => panic!("VM never reached Running state (last seen: {other:?})"),
            Err(e) => panic!("failed to query VM state: {e}"),
        }
    }

    // 3. Mount orchestration: only if the caller gave us a real
    // passthrough device to mount (see module docs above).
    if let Some(device_path) = passthrough {
        let device = qemu_vdw_core::discovery::PassthroughDevice::new(
            device_path,
            qemu_vdw_core::discovery::DeviceKind::Plain,
        );
        let mount_request = MountRequest::new(&device, "/mnt/qemu-vdw-pipeline-test")
            .with_timeout(Duration::from_secs(60));
        let result = mount::mount_device(&vm, &mount_request)
            .expect("mount orchestration should succeed against a guest-agent-equipped image");
        assert_eq!(result.target_path, "/mnt/qemu-vdw-pipeline-test");
        eprintln!("mounted {} at {}", result.resolved_device, result.target_path);
    } else {
        eprintln!(
            "QEMU_VDW_TEST_PASSTHROUGH_DEVICE not set — skipping the mount \
             assertions, provisioning-only coverage still ran for real"
        );
    }

    vm.stop().expect("stopping the test VM should succeed");
}
