//! Builds the libvirt domain XML for a [`super::ProvisionRequest`].

use std::path::Path;

use super::ProvisionRequest;

pub(super) fn build_domain_xml(name: &str, req: &ProvisionRequest) -> String {
    let mut disks = disk_xml(&req.disk_image, "vda");
    if let Some(device) = &req.passthrough_device {
        // Paths under /rsc/ are FUSE-proxied beacon devices; present them as
        // file-backed raw disks so QEMU does buffered I/O through rscfuse.
        let is_fuse = device.to_string_lossy().starts_with("/rsc/");
        disks.push_str(&passthrough_disk_xml(device, super::PASSTHROUGH_TARGET_DEV, is_fuse));
    }

    format!(
        r#"<domain type='kvm'>
  <name>{name}</name>
  <memory unit='MiB'>{memory}</memory>
  <currentMemory unit='MiB'>{memory}</currentMemory>
  <vcpu placement='static'>{vcpus}</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <kernel>{kernel}</kernel>
    <initrd>{initrd}</initrd>
    <cmdline>{cmdline}</cmdline>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>destroy</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
{disks}    <channel type='unix'>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <serial type='pty'>
      <target port='0'/>
    </serial>
  </devices>
</domain>
"#,
        name = xml_escape(name),
        memory = req.memory_mib,
        vcpus = req.vcpus,
        kernel = xml_escape(&path_to_string(&req.kernel)),
        initrd = xml_escape(&path_to_string(&req.initrd)),
        cmdline = xml_escape(&req.kernel_cmdline),
        disks = disks,
    )
}

/// The guest OS disk image (`vda`): a plain file-backed virtio-blk disk.
fn disk_xml(path: &Path, target_dev: &str) -> String {
    format!(
        r#"    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='{path}'/>
      <target dev='{dev}' bus='virtio'/>
    </disk>
"#,
        path = xml_escape(&path_to_string(path)),
        dev = target_dev,
    )
}

/// A discovered/explicit host block device passed through raw (`vdb`).
/// When `as_file` is true the source is treated as a raw file (used for
/// FUSE-proxied beacon devices under /rsc/); otherwise it is a host block
/// device.
fn passthrough_disk_xml(path: &Path, target_dev: &str, as_file: bool) -> String {
    if as_file {
        format!(
            r#"    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='writeback' io='threads'/>
      <source file='{path}'/>
      <target dev='{dev}' bus='virtio'/>
    </disk>
"#,
            path = xml_escape(&path_to_string(path)),
            dev = target_dev,
        )
    } else {
        format!(
            r#"    <disk type='block' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source dev='{path}'/>
      <target dev='{dev}' bus='virtio'/>
    </disk>
"#,
            path = xml_escape(&path_to_string(path)),
            dev = target_dev,
        )
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_includes_kernel_initrd_and_primary_disk() {
        let req = ProvisionRequest::new("/boot/vmlinuz", "/boot/initrd.img", "/images/rootfs.img");
        let xml = build_domain_xml("test-domain", &req);
        assert!(xml.contains("<kernel>/boot/vmlinuz</kernel>"));
        assert!(xml.contains("<initrd>/boot/initrd.img</initrd>"));
        assert!(xml.contains("<source file='/images/rootfs.img'/>"));
        assert!(xml.contains("<target dev='vda' bus='virtio'/>"));
        assert!(!xml.contains("vdb"));
    }

    #[test]
    fn xml_attaches_passthrough_device_as_block_source() {
        let req = ProvisionRequest::new("/boot/vmlinuz", "/boot/initrd.img", "/images/rootfs.img")
            .with_passthrough_device("/dev/sdb2");
        let xml = build_domain_xml("test-domain", &req);
        assert!(xml.contains("<source dev='/dev/sdb2'/>"));
        assert!(xml.contains("<target dev='vdb' bus='virtio'/>"));
        assert!(xml.contains("type='block'"));
    }

    #[test]
    fn xml_attaches_fuse_passthrough_device_as_file_source() {
        let req = ProvisionRequest::new("/boot/vmlinuz", "/boot/initrd.img", "/images/rootfs.img")
            .with_passthrough_device("/rsc/beacon/dev/sda1");
        let xml = build_domain_xml("test-domain", &req);
        assert!(xml.contains("<source file='/rsc/beacon/dev/sda1'/>"));
        assert!(xml.contains("<target dev='vdb' bus='virtio'/>"));
        assert!(xml.contains("type='file'"));
    }

    #[test]
    fn xml_carries_guest_agent_channel() {
        let req = ProvisionRequest::new("/boot/vmlinuz", "/boot/initrd.img", "/images/rootfs.img");
        let xml = build_domain_xml("test-domain", &req);
        assert!(xml.contains("org.qemu.guest_agent.0"));
    }

    #[test]
    fn xml_escapes_special_characters_in_paths() {
        let req = ProvisionRequest::new(
            "/boot/vmlinuz",
            "/boot/initrd.img",
            "/images/weird & <name>.img",
        );
        let xml = build_domain_xml("test-domain", &req);
        assert!(xml.contains("weird &amp; &lt;name&gt;.img"));
    }
}
