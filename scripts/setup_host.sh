#!/usr/bin/env bash
set -euo pipefail

apt-get install -y build-essential linux-headers-$(uname -r) bpftool || \
  dnf install -y kernel-devel-$(uname -r) bpftool || \
  pacman -S --noconfirm linux-headers

# Init khook submodule
git -C "$(git rev-parse --show-toplevel)" submodule update --init lib/khook
