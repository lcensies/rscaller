#!/bin/bash

# Kernel debugging configuration script
# This script modifies an existing kernel .config file to add debugging options

set -e

CONFIG_FILE="$1"
if [ -z "$CONFIG_FILE" ]; then
    echo "Usage: $0 <path_to_.config>"
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file $CONFIG_FILE does not exist"
    exit 1
fi

echo "Configuring kernel for debugging with file: $CONFIG_FILE"

# Backup original config
cp "$CONFIG_FILE" "${CONFIG_FILE}.backup"

# Function to set config option
set_config() {
    local option="$1"
    local value="$2"
    
    if grep -q "^${option}=" "$CONFIG_FILE"; then
        # Option exists, replace it
        sed -i "s/^${option}=.*/${option}=${value}/" "$CONFIG_FILE"
    else
        # Option doesn't exist, add it
        echo "${option}=${value}" >> "$CONFIG_FILE"
    fi
}

# Function to unset config option (comment it out)
unset_config() {
    local option="$1"
    
    if grep -q "^${option}=" "$CONFIG_FILE"; then
        sed -i "s/^${option}=/# ${option} is not set/" "$CONFIG_FILE"
    fi
}

# Enable debugging options
echo "Setting debugging options..."

# Essential debugging options
set_config "CONFIG_READABLE_ASM" "y"
set_config "CONFIG_GDB_SCRIPTS" "y"
set_config "CONFIG_LOCALVERSION" '"-rscaller-debug"'
set_config "CONFIG_KGDB_KDB" "y"
set_config "CONFIG_KGDB" "y"
set_config "CONFIG_FRAME_POINTER" "y"

# Filesystem and virtualization support
set_config "CONFIG_EXT4_FS" "y"
set_config "CONFIG_VIRTIO_BLK" "y"
set_config "CONFIG_VIRTIO_PCI" "y"

# Disable KASLR and enable fixed memory layout
unset_config "CONFIG_RANDOMIZE_BASE"
unset_config "CONFIG_RELOCATABLE"
set_config "CONFIG_PHYSICAL_START" "0x1000000"
set_config "CONFIG_PHYSICAL_ALIGN" "0x1000000"

# BTF support
set_config "CONFIG_DEBUG_INFO_BTF" "y"
set_config "CONFIG_DEBUG_INFO" "y"
set_config "CONFIG_DEBUG_INFO_DWARF4" "y"

# Additional debugging options
set_config "CONFIG_DEBUG_KERNEL" "y"
set_config "CONFIG_DEBUG_INFO" "y"
set_config "CONFIG_KALLSYMS" "y"
set_config "CONFIG_KALLSYMS_ALL" "y"
set_config "CONFIG_DEBUG_FS" "y"
set_config "CONFIG_MAGIC_SYSRQ" "y"

# Ensure we have proper symbol information
set_config "CONFIG_KALLSYMS_EXTRA_PASS" "y"

echo "Kernel configuration updated for debugging"
echo "Backup saved as: ${CONFIG_FILE}.backup"
echo ""
echo "Key changes made:"
echo "- Enabled readable assembly (READABLE_ASM=y)"
echo "- Enabled GDB scripts (GDB_SCRIPTS=y)"
echo "- Set local version to -rscaller-debug"
echo "- Enabled KGDB and KDB"
echo "- Enabled frame pointers"
echo "- Disabled KASLR (RANDOMIZE_BASE=n)"
echo "- Set fixed physical start address"
echo "- Enabled BTF debugging info"
