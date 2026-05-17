# rscaller — Agent & Developer Notes

## Kernel Compatibility

### proc_ops (5.6+)
`struct proc_ops` replaces `struct file_operations` for proc files starting in Linux 5.6.
Field names are prefixed `proc_` (e.g. `.proc_read`, `.proc_write`, `.proc_mmap`).
Guarded in `main.c` with `#ifdef HAVE_PROC_OPS` (defined when `LINUX_VERSION_CODE >= 5.6.0`).

### vm_flags_set / vm_flags_clear (6.3+)
`vma->vm_flags` became `const` in Linux 6.3 — direct `|=` assignment is a compile error.
Use `vm_flags_set(vma, flags)` / `vm_flags_clear(vma, flags)` on 6.3+.
Compat shim defined in `main.c` for kernels < 6.3.
**Note:** In Linux 6.15+ these helpers are GPL-only exports. Non-GPL modules on 6.15+ must use `vm_flags_reset()` instead.

### vm_insert_page (2.6.15+)
Safe to use on all supported kernels. Used in `rscaller_dev_mmap_new` instead of
`remap_pfn_range` because `remap_pfn_range` rejects normal RAM (struct-page-backed) PFNs
on Linux 6.x without additional setup.

### mmap size check
`mmap(len)` is rounded up to `PAGE_SIZE` by the kernel before reaching the driver's mmap
handler. Always compare against `PAGE_ALIGN(sizeof(ControlBuffer))`, not bare `sizeof`.

### sys_call_table write protection (5.4+)
On kernels ≥ 5.4, clearing CR0.WP is no longer sufficient to write to the sys_call_table —
kernels with PKS (Protection Key Supervisor) or CET enforce page-level write protection
independently of the WP bit, and `set_memory_rw` (even when looked up dynamically) may not
lift PKS protection either.  The reliable cross-version technique is a **vmap alias**: get
the physical page(s) backing the target address, `vmap()` them with `PAGE_KERNEL`
(read-write), write through the alias, then `vunmap()`.  This bypasses all protections on
the original mapping.  Keep `set_memory_rw` + CR0.WP fallback paths in `sct_set_rw/ro` for
kernels where vmap is unavailable or overkill.
**General rule:** prefer kernel-version-gated code over a single approach that silently
fails on newer kernels. Add a `LINUX_VERSION_CODE` guard any time a kernel API, struct
field, or memory-protection mechanism differs across supported versions. For GPL-only
symbols, prefer dynamic lookup via `lookup_kallsym()` over direct linking.

### khook_release timeout
The upstream khook `khook_release()` loops forever if `use_count > 0` (e.g. a process was
killed mid-syscall). Our fork (`lib/khook`) adds a 10-iteration / 10-second timeout with a
forced `atomic_set(&p->use_count, 0)` to prevent the module from getting stuck in
"Unloading" state permanently.

## Test Script Notes

### BECOME_PASS
`make test-remote` / `make deploy-remote` require sudo on the remote VM.
Set `BECOME_PASS=ubuntu` in `.env` or pass as env var. `.env` is gitignored.

### CLIENT variable
`make test-remote CLIENT=dev-vm-rscaller-2` runs rsclient on a separate VM.
rsclient must have access to `/proc/rscaller`, which only exists on the kmod host (REMOTE).
Currently CLIENT and REMOTE should be the same machine unless a remote /proc mount is configured.

### Cleanup order
Always kill rsclient before rmmod. If rsclient is killed mid-syscall (while inside the
khook stub), `use_count` leaks and rmmod hangs. The test script enforces:
`pkill -9 rsclient → sleep 0.5 → rmmod`.
