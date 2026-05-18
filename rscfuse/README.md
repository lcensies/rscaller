# rscfuse

FUSE filesystem daemon that forwards VFS operations as raw syscalls via rsbeacon.

## System dependencies

The `fuser` crate requires the FUSE 3 development headers at **build time**.

```
# Debian / Ubuntu
sudo apt-get install libfuse3-dev

# Fedora / RHEL / CentOS
sudo dnf install fuse3-devel

# Arch Linux
sudo pacman -S fuse3
```

Also ensure the `fuse` kernel module is loaded and the user running `rscfuse` is
in the `fuse` group (or you are root):

```
sudo modprobe fuse
sudo usermod -aG fuse $USER   # re-login after
```

## Build

```
cargo build -p rscfuse
# or release:
cargo build --release -p rscfuse
```

## Usage

```
rscfuse \
  --beacon <host:port> \
  --mount  <local-mountpoint> \
  --name   <fs-name> \
  --transport <tcp|uds> \
  --encryption <none|tls> \
  [--ca-cert <path-to-ca.pem>]
```

`rsbeacon` must be running on the remote host.

### Plain TCP example

```bash
# On remote VM:
rsbeacon --listen 0.0.0.0:9999

# Locally:
mkdir -p /tmp/rsc
rscfuse --beacon 192.168.1.10:9999 --mount /tmp/rsc --name myfs --transport tcp --encryption none
ls /tmp/rsc
```

### TLS example

```bash
rscfuse --beacon 192.168.1.10:9999 --mount /tmp/rsc \
        --transport tcp --encryption tls --ca-cert /path/to/ca.pem
```

## Signal handling

`rscfuse` mounts with `AutoUnmount`. Sending `SIGINT` or `SIGTERM` (Ctrl-C) will
unmount the filesystem cleanly.
