#!/usr/bin/env bash
set -euo pipefail
REPO="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
cd "$REPO"

echo "=== Test: codegen generates correct files ==="
TMPDIR="$(mktemp -d)"
trap "rm -rf '$TMPDIR'" EXIT

cargo run -p codegen -- --tbl-dir files --forwarded files/forwarded_syscalls --out "$TMPDIR" 2>/dev/null

[ -f "$TMPDIR/handler_wrappers.h" ] || { echo "FAIL: no handler_wrappers.h"; exit 1; }
[ -f "$TMPDIR/syscalls.c" ]          || { echo "FAIL: no syscalls.c"; exit 1; }
grep -q "SyscallParam"               "$TMPDIR/handler_wrappers.h" || { echo "FAIL: no SyscallParam"; exit 1; }
grep -q "fetch_param_variant"        "$TMPDIR/handler_wrappers.h" || { echo "FAIL: no fetch_param_variant"; exit 1; }
grep -q "signature__x64_sys_kill"    "$TMPDIR/handler_wrappers.h" || { echo "FAIL: no kill extern"; exit 1; }
grep -q "signature__x64_sys_execve"  "$TMPDIR/syscalls.c"         || { echo "FAIL: no execve sig"; exit 1; }
grep -q "n_params = 2"               "$TMPDIR/syscalls.c"         || { echo "FAIL: kill n_params != 2"; exit 1; }
echo "PASS"
