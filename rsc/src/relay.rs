//! QEMU VM-based relay execution for `rsc exec --profile qemu-relay`.
//!
//! Instead of forwarding syscalls via seccomp/rsclient, this path provisions a
//! local QEMU/KVM VM, attaches the remote beacon's block device as a raw
//! passthrough disk, mounts it inside the VM, and runs the target command via
//! the QEMU Guest Agent. The raw device write happens inside the VM and is
//! invisible to the attacker's host EDR.
//!
//! TODO: when `--microvm` is used, the relay mount should happen inside the
//! microVM at startup instead of provisioning a separate QEMU VM here.

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::ExecArgs;
use qemu_vdw_core::discovery::{DeviceKind, PassthroughDevice};
use qemu_vdw_core::mount::{exec_in_guest, mount_device, MountRequest};
use qemu_vdw_core::provisioning::{attach, provision, ProvisionRequest, VmHandle};

use crate::mount_config::RelayConfig;

/// Run a command inside a QEMU relay VM.
///
/// 1. Launches `rsc fuse` so we can see `/rsc/<target>/dev/` for discovery.
/// 2. Discovers the first usable block device on the beacon.
/// 3. Provisions a local QEMU VM with that device attached.
/// 4. Mounts the device inside the VM.
/// 5. Runs the target command via guest agent.
/// 6. Tears down the VM.
///
/// VM settings come from the profile's `relay:` section (`cfg`); CLI flags
/// `--relay-artifacts` / `--relay-device` override the config values.
pub fn run_relay_exec(args: ExecArgs, cfg: &RelayConfig) -> Result<()> {
    let name = args.transport.resolve_name();
    let mount_base = &args.transport.mount_base;
    let fuse_root = format!("{}/{}", mount_base.trim_end_matches('/'), name);

    // 1. Start rscfuse for discovery and general remote FS access.
    let fuse_pid = launch_rscfuse(&args, &fuse_root, &name)?;

    // Give rscfuse a moment to settle.
    std::thread::sleep(Duration::from_millis(500));

    let result = (|| -> Result<()> {
        // 2. Discover remote block device through the FUSE view.
        // CLI --relay-device wins over the profile's relay.device.
        let device = if let Some(dev) = args.relay_device.as_ref().or(cfg.device.as_ref()) {
            let full = if dev.is_absolute() && dev.exists() {
                // An existing local path (a real host block device).
                dev.clone()
            } else if dev.is_absolute() {
                // Absolute path that doesn't exist locally — it's a path on
                // the beacon; resolve it through the FUSE view.
                Path::new(&fuse_root).join(dev.strip_prefix("/").unwrap())
            } else {
                // Bare device name under the beacon's /dev.
                Path::new(&fuse_root).join("dev").join(dev)
            };
            PassthroughDevice::new(full, DeviceKind::Plain)
        } else {
            discover_remote_device(&fuse_root)
                .context("discovering remote block device")?
        };
        eprintln!("rsc-relay: using device {:?} (kind {:?})", device.path, device.kind);

        // 3. Provision local QEMU VM.
        let artifacts = resolve_artifacts(&args, cfg);
        let vm = provision_relay_vm(&device, &artifacts, &name, cfg)
            .context("provisioning relay VM")?;
        eprintln!("rsc-relay: VM {} running", vm.name());

        let vm_result = (|| -> Result<()> {
            // 4. Mount device inside guest.
            mount_device(&vm, &MountRequest::new(&device, &cfg.mount_point))
                .context("mounting device inside relay VM")?;
            eprintln!("rsc-relay: mounted at {} inside VM", cfg.mount_point);

            // 5. Run target command inside VM.
            if args.cmd.is_empty() {
                bail!("no command specified");
            }
            let path = &args.cmd[0];
            let cmd_args: Vec<&str> = args.cmd[1..].iter().map(|s| s.as_str()).collect();
            let res = exec_in_guest(&vm, path, &cmd_args, None, Duration::from_secs(300))
                .context("running command inside relay VM")?;

            // Forward guest output so `rsc exec` behaves like a local exec.
            use std::io::Write as _;
            let _ = std::io::stdout().write_all(&res.stdout);
            let _ = std::io::stderr().write_all(&res.stderr);

            if !res.success() {
                bail!("command exited with code {}", res.exit_code);
            }
            eprintln!("rsc-relay: command finished with exit code {}", res.exit_code);
            Ok(())
        })();

        // 6. Teardown VM — destroy if running, then undefine so the name is
        // released for the next run. Runs on success and failure alike.
        if let Err(e) = vm.stop() {
            eprintln!("rsc-relay: warning: failed to stop VM: {}", e);
        }
        if let Err(e) = vm.undefine() {
            eprintln!("rsc-relay: warning: failed to undefine VM: {}", e);
        }
        vm_result
    })();

    // Always clean up rscfuse.
    let _ = stop_rscfuse(fuse_pid, &fuse_root);
    result
}

fn resolve_artifacts(args: &ExecArgs, cfg: &RelayConfig) -> RelayArtifacts {
    // CLI --relay-artifacts wins over the profile's relay.artifacts.
    let dir = args
        .relay_artifacts
        .clone()
        .unwrap_or_else(|| cfg.artifacts.clone());
    RelayArtifacts {
        kernel: dir.join("vmlinuz"),
        initrd: dir.join("initrd.img"),
        disk_image: dir.join("rootfs.img"),
    }
}

struct RelayArtifacts {
    kernel: PathBuf,
    initrd: PathBuf,
    disk_image: PathBuf,
}

fn provision_relay_vm(
    device: &PassthroughDevice,
    artifacts: &RelayArtifacts,
    name: &str,
    cfg: &RelayConfig,
) -> Result<VmHandle> {
    for (role, path) in [
        ("kernel", &artifacts.kernel),
        ("initrd", &artifacts.initrd),
        ("disk image", &artifacts.disk_image),
    ] {
        if !path.exists() {
            bail!("missing relay artifact: {} at {:?}", role, path);
        }
    }

    let domain_name = format!("rsc-relay-{}", name);

    // Best-effort cleanup of a leftover domain from a previous crashed run —
    // `provision` fails to define when the name is taken, and a domain whose
    // create() failed is left defined-but-not-running.
    if let Ok(old) = attach(&domain_name, cfg.libvirt_uri.as_deref()) {
        let _ = old.stop();
        let _ = old.undefine();
    }

    let mut req = ProvisionRequest::new(&artifacts.kernel, &artifacts.initrd, &artifacts.disk_image)
        .with_discovered_device(device)
        .with_domain_name(&domain_name)
        .with_kernel_cmdline(&cfg.kernel_cmdline)
        .with_memory_mib(cfg.memory_mib)
        .with_vcpus(cfg.vcpus);
    if let Some(uri) = &cfg.libvirt_uri {
        req = req.with_libvirt_uri(uri);
    }

    provision(&req).map_err(|e| anyhow::anyhow!("libvirt provisioning failed: {}", e))
}

/// Discover the beacon's root block device through the FUSE view.
///
/// Reads the beacon's /proc/mounts for the device backing "/":
/// - LVM root (/dev/mapper/<vg>-<lv> or /dev/dm-N): resolve VG/LV names and
///   the physical volume via sysfs slaves, so the relay VM can vgchange+mount
///   the logical volume itself (see DeviceKind::Lvm).
/// - Plain partition root (/dev/sdXN etc.): attach it directly.
/// Falls back to a /dev/ name-pattern scan if mounts parsing yields nothing.
///
/// rscfuse reports remote block devices as regular files, so no file-type
/// checks are usable here.
fn discover_remote_device(fuse_root: &str) -> Result<PassthroughDevice> {
    let root = Path::new(fuse_root);

    if let Ok(mounts) = std::fs::read_to_string(root.join("proc/mounts")) {
        if let Some(src) = mounts
            .lines()
            .find(|l| l.split_whitespace().nth(1) == Some("/"))
            .and_then(|l| l.split_whitespace().next())
        {
            if let Some(dev) = resolve_lvm_root(root, src) {
                return Ok(dev);
            }
            let plain = root.join(src.trim_start_matches('/'));
            if plain.exists() {
                return Ok(PassthroughDevice::new(plain, DeviceKind::Plain));
            }
        }
    }

    discover_plain_by_name(root)
}

/// Resolve an LVM-backed root source to its physical volume + VG/LV names.
///
/// `root_src` is what /proc/mounts reports for "/", e.g.
/// `/dev/mapper/ubuntu--vg-ubuntu--lv` or `/dev/dm-0`. The relay VM attaches
/// only the PV; `mount_via` activates the VG and mounts the LV inside.
///
/// ponytail: multi-PV (striped/mirrored) LVM attaches only the first slave —
/// single-PV roots are the common case; attach all PVs if that ever matters.
fn resolve_lvm_root(root: &Path, root_src: &str) -> Option<PassthroughDevice> {
    let (mapper, dm) = match root_src.strip_prefix("/dev/mapper/") {
        Some(m) => (m.to_string(), None),
        None => {
            let d = root_src.strip_prefix("/dev/")?;
            if !d.starts_with("dm-") {
                return None;
            }
            let name = std::fs::read_to_string(root.join("sys/block").join(d).join("dm/name"))
                .ok()?;
            (name.trim().to_string(), Some(d.to_string()))
        }
    };

    let (vg, lv) = split_mapper_name(&mapper)?;

    // Find the dm device carrying this mapper name by scanning sysfs, then
    // take its first slave as the physical volume (e.g. vda3).
    let dm_name = match dm {
        Some(d) => d,
        None => find_dm_by_name(root, &mapper)?,
    };
    let slaves_dir = root.join("sys/block").join(&dm_name).join("slaves");
    let pv = std::fs::read_dir(&slaves_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| !n.is_empty())?;

    let pv_path = root.join("dev").join(&pv);
    if !pv_path.exists() {
        return None;
    }
    Some(PassthroughDevice::new(
        pv_path,
        DeviceKind::Lvm {
            volume_group: vg,
            logical_volume: lv,
        },
    ))
}

/// Scan /sys/block/dm-* for the device whose dm/name matches `mapper`.
fn find_dm_by_name(root: &Path, mapper: &str) -> Option<String> {
    for entry in std::fs::read_dir(root.join("sys/block")).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("dm-") {
            continue;
        }
        if let Ok(n) = std::fs::read_to_string(entry.path().join("dm/name")) {
            if n.trim() == mapper {
                return Some(name);
            }
        }
    }
    None
}

/// Split a device-mapper name into (vg, lv). In /dev/mapper names, a literal
/// '-' inside the VG or LV is doubled ('--'); a single '-' joins VG and LV.
fn split_mapper_name(mapper: &str) -> Option<(String, String)> {
    let mut vg = String::new();
    let mut lv = String::new();
    let mut into_lv = false;
    let mut chars = mapper.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '-' {
            if chars.peek() == Some(&'-') {
                chars.next();
                (if into_lv { &mut lv } else { &mut vg }).push('-');
            } else if !into_lv {
                into_lv = true;
            } else {
                lv.push(c);
            }
        } else {
            (if into_lv { &mut lv } else { &mut vg }).push(c);
        }
    }
    if vg.is_empty() || lv.is_empty() {
        return None;
    }
    Some((vg, lv))
}

/// Last-resort discovery: first disk-looking device under the beacon's /dev/.
fn discover_plain_by_name(root: &Path) -> Result<PassthroughDevice> {
    let dev_root = root.join("dev");
    if !dev_root.exists() {
        bail!("FUSE device directory {:?} not found; is rscfuse mounted?", dev_root);
    }

    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(&dev_root)
        .with_context(|| format!("reading {:?}", dev_root))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("sd")
            && !name_str.starts_with("vd")
            && !name_str.starts_with("hd")
            && !name_str.starts_with("nvme")
            && !name_str.starts_with("mmcblk")
        {
            continue;
        }
        candidates.push(dev_root.join(&name));
    }

    if candidates.is_empty() {
        bail!("no usable block device found under {:?}", dev_root);
    }

    candidates.sort();
    let path = candidates
        .into_iter()
        .next()
        .expect("candidates not empty");
    Ok(PassthroughDevice::new(path, DeviceKind::Plain))
}

/// Fork `rsc fuse` in the background and return its PID.
fn launch_rscfuse(args: &ExecArgs, mount_point: &str, name: &str) -> Result<libc::pid_t> {
    if is_mount_point(mount_point) {
        let _ = Command::new("umount").args(["-l", mount_point]).status();
    }
    std::fs::create_dir_all(mount_point)
        .with_context(|| format!("create mount point {mount_point}"))?;

    let rsc_exe = std::env::current_exe()
        .context("resolving current executable path")?
        .to_string_lossy()
        .into_owned();

    let mut argv_strs = vec![
        rsc_exe.clone(),
        "fuse".to_string(),
        "--beacon".to_string(),
        args.transport.beacon.clone(),
        "--mount".to_string(),
        mount_point.to_string(),
        "--name".to_string(),
        name.to_string(),
        "--encryption".to_string(),
        args.transport.encryption.clone(),
    ];
    if let Some(ca) = &args.transport.ca_cert {
        argv_strs.push("--ca-cert".to_string());
        argv_strs.push(ca.clone());
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
            for _ in 0..30 {
                std::thread::sleep(Duration::from_millis(100));
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

fn stop_rscfuse(pid: libc::pid_t, mount_point: &str) -> Result<()> {
    unsafe {
        libc::kill(pid, libc::SIGTERM);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
    let _ = Command::new("umount").args(["-l", mount_point]).status();
    Ok(())
}

fn is_mount_point(path: &str) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return false;
    };
    mounts.lines().any(|l| {
        let mut parts = l.splitn(3, ' ');
        let _dev = parts.next();
        let mp = parts.next().unwrap_or("");
        mp == path
    })
}

#[cfg(test)]
mod tests {
    use super::split_mapper_name;

    #[test]
    fn mapper_names_split_into_vg_and_lv() {
        // Ubuntu default: vg "ubuntu-vg", lv "ubuntu-lv".
        assert_eq!(
            split_mapper_name("ubuntu--vg-ubuntu--lv"),
            Some(("ubuntu-vg".to_string(), "ubuntu-lv".to_string()))
        );
        // No dashes at all.
        assert_eq!(
            split_mapper_name("data-lv0"),
            Some(("data".to_string(), "lv0".to_string()))
        );
        // Missing LV part is rejected.
        assert_eq!(split_mapper_name("justvg"), None);
    }
}
