# VM Kernel Compilation for Debugging

This document describes how to use the VM kernel compilation feature for debugging the rscaller project.

## Prerequisites

1. **Vagrant with libvirt provider**: Install Vagrant and the libvirt provider
   ```bash
   # Install Vagrant
   sudo apt install vagrant
   
   # Install libvirt provider
   vagrant plugin install vagrant-libvirt
   ```

2. **KVM support**: Ensure your system supports KVM and nested virtualization
   ```bash
   # Check KVM support
   lsmod | grep kvm
   
   # Enable nested virtualization (if not already enabled)
   echo 'options kvm_intel nested=1' | sudo tee /etc/modprobe.d/kvm-nested.conf
   sudo modprobe -r kvm_intel
   sudo modprobe kvm_intel
   ```

## Usage

### 1. Start the VM

```bash
# Start the VM (this will take a few minutes on first run)
vagrant up

# Check VM status
vagrant status

# SSH into the VM
vagrant ssh
```

### 2. Compile Kernel for Debugging

From the host machine, run:

```bash
# Compile the entire kernel (download, configure, build, install)
make vm-kernel

# Or run individual steps:
make vm-kernel-download    # Download kernel sources matching VM's version
make vm-kernel-config      # Configure kernel with debugging options
make vm-kernel-build       # Build kernel using docker containers
make vm-kernel-install     # Install the compiled kernel
```

### 3. Reboot to New Kernel

After compilation, reboot the VM to use the new kernel:

```bash
# From host
vagrant reload

# Or from inside VM
sudo reboot
```

### 4. Verify New Kernel

After reboot, check that you're running the debug kernel:

```bash
# SSH into VM
vagrant ssh

# Check kernel version (should show -rscaller-debug suffix)
uname -r

# Check if debugging features are enabled
cat /proc/config.gz | gunzip | grep -E "(KGDB|DEBUG|FRAME_POINTER)"
```

## Debugging Features Enabled

The compiled kernel includes the following debugging features:

- **READABLE_ASM=y**: Makes assembly code readable for debugging
- **GDB_SCRIPTS=y**: Enables GDB scripts for kernel debugging
- **CONFIG_LOCALVERSION=-rscaller-debug**: Distinguishes this kernel from stock
- **CONFIG_KGDB_KDB=y**: Kernel Debugger support
- **CONFIG_FRAME_POINTER=y**: Enables proper stack traces in GDB
- **CONFIG_DEBUG_INFO_BTF=y**: BTF debugging information
- **CONFIG_RANDOMIZE_BASE=n**: Disables KASLR for consistent debugging
- **CONFIG_PHYSICAL_START=0x1000000**: Fixed physical start address

## Directory Structure in VM

- `/home/vagrant/rscaller/`: Your project directory (mounted from host)
- `/home/vagrant/linux-kernel/`: Kernel source code
- `/home/vagrant/kernel-build-containers/`: Kernel build containers
- `/home/vagrant/kernel-builds/`: Kernel build output

## Troubleshooting

### VM Won't Start
- Check if KVM is available: `lsmod | grep kvm`
- Ensure nested virtualization is enabled
- Check libvirt service: `sudo systemctl status libvirtd`

### Kernel Compilation Fails
- Check if VM is running: `vagrant status`
- Check disk space in VM: `df -h`
- Check build logs in `/home/vagrant/kernel-builds/`

### New Kernel Won't Boot
- Check GRUB configuration: `sudo update-grub`
- Boot from previous kernel using GRUB menu
- Check kernel logs: `dmesg | tail -50`

## Development Workflow

1. **Start VM**: `vagrant up`
2. **Develop your code**: Edit files in the project directory
3. **Compile kernel**: `make vm-kernel` (when needed)
4. **Test your kernel module**: `make kmod` and `make kmod_reload`
5. **Debug**: Use GDB with the debug kernel for better debugging experience

## Cleanup

To remove the VM and free up resources:

```bash
# Stop and destroy VM
vagrant destroy

# Remove kernel build artifacts (optional)
rm -rf /home/vagrant/kernel-builds/
rm -rf /home/vagrant/linux-kernel/
```
