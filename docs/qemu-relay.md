# QEMU relay mode

`rsc exec` with a relay-enabled mount profile runs the command inside a local
QEMU/KVM VM instead of on the host. The beacon's block device is attached to
the VM through rscfuse, mounted in the guest, and the command runs via the
QEMU Guest Agent. Raw device I/O happens inside the guest kernel, so host-side
tracing (tracee/eBPF/EDR) on either machine sees only opaque block traffic
from rsbeacon — no paths, no filenames, no exec events.

## Toggling relay mode

Relay mode is toggled by the mount profile: any profile with a `relay:`
section enables it. The built-in `qemu-relay` profile carries the defaults:

```
rsc exec --beacon <ip>:9999 --encryption none \
  --mount-profile qemu-relay [--relay-device /dev/vdb] -- <command>
```

A custom profile is a YAML file (passed by path, or dropped into
`~/.config/rsc/profiles/<name>.yaml` or `/etc/rsc/profiles/<name>.yaml`):

```yaml
name: my-relay
relay:
  artifacts: /opt/my-relay-image        # dir with vmlinuz/initrd.img/rootfs.img
  device: /dev/vdc                      # omit = auto-discover beacon root (LVM-aware)
  kernel_cmdline: "root=/dev/vda rw console=ttyS0 quiet init=/vm-init-relay.sh"
  mount_point: /mnt/relay               # guest-side mount point for the device
  memory_mib: 512                       # default; the guest only mounts + runs one
  vcpus: 1                              # command. 128 MiB/1 is the verified floor.
  # libvirt_uri: qemu:///system         # default: qemu:///session
```

Every field has a default (`mount_config::RelayConfig`), so `relay: {}` is
valid. Precedence: CLI flag > profile `relay:` section > built-in default.
CLI overrides: `--relay-artifacts <dir>`, `--relay-device <dev>`.

Device discovery when `device` is omitted: the beacon's own `/proc/mounts`
(read through rscfuse) yields the device backing `/`; LVM roots
(`/dev/mapper/<vg>-<lv>`) are resolved to their physical volume via sysfs
slaves and mounted in the guest via `vgchange -ay <vg>`.

## Guest image contract

The artifacts dir must contain three files:

| File | Role |
|---|---|
| `vmlinuz` | Kernel with `virtio-blk` and `virtio_console` built in |
| `initrd.img` | Matching initrd (may be small/empty-ish) |
| `rootfs.img` | ext4 rootfs attached as `vda`, booted rw as `/` |

The kernel cmdline (`relay.kernel_cmdline`) must hand control to an init that:

1. Mounts `/proc`, `/sys`, `/dev` (devtmpfs), plus tmpfs on `/tmp` and `/run`.
2. Starts the QEMU guest agent on the virtio-serial channel:
   `qemu-ga --method=virtio-serial --path=/dev/virtio-ports/org.qemu.guest_agent.0 --daemonize`
   (if the `virtio-ports` symlink is absent, fall back to the first `/dev/vport*`).
3. Keeps PID 1 alive (e.g. `while true; do sleep 60; done`). Powering off or
   exiting kills the session.

`qemu-guest-agent` must be installed in the rootfs — the mount/exec plumbing
(`mount_device`, `exec_in_guest`) talks only to the agent.

## Preparing a custom image (the way the bundled one was built)

The bundled image (`/var/lib/libvirt/images/rscaller-relay/`, synced from
repo `qemu-relay-artifacts/` by `deploy.sh`) is a minimal Alpine rootfs:

```sh
# On any host with the base rootfs.img:
mount rootfs.img /mnt
cp /etc/resolv.conf /mnt/etc/resolv.conf
chroot /mnt /sbin/apk update
chroot /mnt /sbin/apk add qemu-guest-agent
cat > /mnt/vm-init-relay.sh <<'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
GA_PORT=/dev/virtio-ports/org.qemu.guest_agent.0
[ -e "$GA_PORT" ] || GA_PORT=$(ls /dev/vport* | head -1)
/usr/bin/qemu-ga --method=virtio-serial --path="$GA_PORT" --daemonize
while true; do sleep 60; done
EOF
chmod +x /mnt/vm-init-relay.sh
umount /mnt
```

Any distro works as long as the contract above is met (Debian cloud image +
`qemu-guest-agent` + a custom init script is equally fine). Point
`relay.artifacts` (or `--relay-artifacts`) at your directory and adjust
`kernel_cmdline` to the init path you installed.

## Host requirements

- KVM + libvirt on the client; `bootstrap.sh` handles:
  `security_driver = "none"` in `/etc/libvirt/qemu.conf` (AppArmor's per-VM
  profile generator cannot open FUSE paths) and `user_allow_other` in
  `/etc/fuse.conf`.
- rscfuse mounts with `Dev` + `AllowOther`; beacon block devices are exposed
  as regular files with their real size. Do not regress these — see
  `AGENTS.md` → "QEMU relay exec".
