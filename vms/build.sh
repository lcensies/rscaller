#!/usr/bin/env bash

# Packer build script for Ubuntu 24.04 kernel development VM
# This script builds a custom Vagrant box with all necessary tools for kernel development

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PACKER_CONFIG="ubuntu-24.04-kernel-dev.json"
BOX_NAME="ubuntu-24.04-kernel-dev.box"
OUTPUT_DIR="output-ubuntu-24.04-kernel-dev"

echo -e "${GREEN}=== Packer Build Script for Ubuntu 24.04 Kernel Development VM ===${NC}"

# Check if packer is installed
if ! command -v packer &>/dev/null; then
  echo -e "${RED}Error: Packer is not installed. Please install it first.${NC}"
  echo "Visit: https://www.packer.io/downloads"
  exit 1
fi

# Check if qemu is installed
if ! command -v qemu-system-x86_64 &>/dev/null; then
  echo -e "${RED}Error: QEMU is not installed. Please install it first.${NC}"
  echo "On Ubuntu/Debian: sudo apt install qemu-kvm qemu-utils"
  exit 1
fi

# Check if KVM is available
if ! lsmod | grep -q kvm; then
  echo -e "${YELLOW}Warning: KVM module not loaded. Building without hardware acceleration.${NC}"
fi

# Clean up previous builds
echo -e "${YELLOW}Cleaning up previous builds...${NC}"
rm -rf "$OUTPUT_DIR"
rm -f "$BOX_NAME"

# Validate packer configuration
echo -e "${YELLOW}Validating Packer configuration...${NC}"
packer validate "$PACKER_CONFIG"

if [ $? -ne 0 ]; then
  echo -e "${RED}Error: Packer configuration validation failed${NC}"
  exit 1
fi

# Build the VM
echo -e "${GREEN}Starting Packer build...${NC}"
echo "This will take 15-30 minutes depending on your internet connection and system performance."
echo ""

packer build -var "headless=true" "$PACKER_CONFIG"

if [ $? -eq 0 ]; then
  echo -e "${GREEN}=== Build completed successfully! ===${NC}"
  echo ""
  echo "Generated files:"
  echo "  - $BOX_NAME (Vagrant box)"
  echo "  - $OUTPUT_DIR/ (VM disk image)"
  echo ""
  echo "Next steps:"
  echo "  1. Add the box to Vagrant:"
  echo "     vagrant box add ubuntu-24.04-kernel-dev $BOX_NAME"
  echo ""
  echo "  2. Update your Vagrantfile to use this box:"
  echo "     config.vm.box = \"ubuntu-24.04-kernel-dev\""
  echo ""
  echo "  3. Start the VM:"
  echo "     vagrant up"
  echo ""
  echo "  4. Compile debug kernel:"
  echo "     make vm-kernel"
else
  echo -e "${RED}=== Build failed! ===${NC}"
  echo "Check the output above for error details."
  exit 1
fi
