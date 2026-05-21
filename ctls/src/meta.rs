//! Syscall parameter metadata — used by backends to know which args are
//! pointers, their direction, and their size.
//!
//! This is the canonical source for the forwarded syscall set.  The C-codegen
//! tool (`tools/codegen`) has its own copy of equivalent data that it uses to
//! generate `kmod/syscalls.c`.  Keep both in sync when adding new syscalls.
//!
//! Size conventions:
//! - `SizeFrom::Arg(i)` — runtime size taken from `args[i]` (capped at `MAX_BUF`)
//! - `SizeFrom::Static(n)` — fixed `n` bytes
//! - `SizeFrom::Default` — pointer type's natural size (ptr: 8, char*: 4096)

use std::collections::HashMap;

/// Maximum bytes we'll copy for a single pointer argument.
pub const MAX_BUF: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Dir {
    In,
    Out,
    InOut,
}

#[derive(Debug, Clone, Copy)]
pub enum PtrType {
    /// NUL-terminated string; copied with strncpy semantics.
    Str,
    /// Opaque byte buffer.
    Buf,
}

#[derive(Debug, Clone, Copy)]
pub enum Size {
    /// Size is the value of `args[i]` at call time (capped at `MAX_BUF`).
    FromArg(usize),
    /// Fixed number of bytes.
    Static(usize),
}

/// Metadata for one pointer-type parameter.
#[derive(Debug, Clone)]
pub struct PtrParam {
    /// Argument index (0-5).
    pub idx: u8,
    pub dir: Dir,
    pub ptr_type: PtrType,
    pub size: Size,
}

/// Metadata for one forwarded syscall.
#[derive(Debug, Clone)]
pub struct SyscallMeta {
    /// Linux x86-64 syscall number.
    pub nr: u64,
    /// Only pointer parameters are listed; scalar args need no special handling.
    pub ptr_params: Vec<PtrParam>,
}

/// Build the metadata table for all forwarded syscalls.
///
/// Returns a `HashMap<nr, SyscallMeta>`.
pub fn build_table() -> HashMap<u64, SyscallMeta> {
    let entries = vec![
        // ── 0: read(fd, buf, count) ─────────────────────────────────────────
        SyscallMeta {
            nr: 0,
            ptr_params: vec![PtrParam {
                idx: 1,
                dir: Dir::Out,
                ptr_type: PtrType::Buf,
                size: Size::FromArg(2),
            }],
        },
        // ── 1: write(fd, buf, count) ────────────────────────────────────────
        SyscallMeta {
            nr: 1,
            ptr_params: vec![PtrParam {
                idx: 1,
                dir: Dir::In,
                ptr_type: PtrType::Buf,
                size: Size::FromArg(2),
            }],
        },
        // ── 2: open(filename, flags, mode) ──────────────────────────────────
        SyscallMeta {
            nr: 2,
            ptr_params: vec![PtrParam {
                idx: 0,
                dir: Dir::In,
                ptr_type: PtrType::Str,
                size: Size::Static(MAX_BUF),
            }],
        },
        // ── 3: close(fd) — no pointers ──────────────────────────────────────
        SyscallMeta { nr: 3, ptr_params: vec![] },
        // ── 4: stat(pathname, statbuf) ──────────────────────────────────────
        SyscallMeta {
            nr: 4,
            ptr_params: vec![
                PtrParam { idx: 0, dir: Dir::In,  ptr_type: PtrType::Str, size: Size::Static(MAX_BUF) },
                PtrParam { idx: 1, dir: Dir::Out, ptr_type: PtrType::Buf, size: Size::Static(144) },
            ],
        },
        // ── 5: fstat(fd, statbuf) ───────────────────────────────────────────
        SyscallMeta {
            nr: 5,
            ptr_params: vec![PtrParam {
                idx: 1,
                dir: Dir::Out,
                ptr_type: PtrType::Buf,
                size: Size::Static(144),
            }],
        },
        // ── 6: lstat(pathname, statbuf) ─────────────────────────────────────
        SyscallMeta {
            nr: 6,
            ptr_params: vec![
                PtrParam { idx: 0, dir: Dir::In,  ptr_type: PtrType::Str, size: Size::Static(MAX_BUF) },
                PtrParam { idx: 1, dir: Dir::Out, ptr_type: PtrType::Buf, size: Size::Static(144) },
            ],
        },
        // ── 62: kill(pid, sig) — no pointers ────────────────────────────────
        SyscallMeta { nr: 62, ptr_params: vec![] },
        // ── 78: getdents(fd, dirp, count) ───────────────────────────────────
        SyscallMeta {
            nr: 78,
            ptr_params: vec![PtrParam {
                idx: 1,
                dir: Dir::Out,
                ptr_type: PtrType::Buf,
                size: Size::FromArg(2),
            }],
        },
        // ── 80: chdir(path) ─────────────────────────────────────────────────
        SyscallMeta {
            nr: 80,
            ptr_params: vec![PtrParam {
                idx: 0,
                dir: Dir::In,
                ptr_type: PtrType::Str,
                size: Size::Static(MAX_BUF),
            }],
        },
        // ── 81: fchdir(fd) — no pointers ────────────────────────────────────
        SyscallMeta { nr: 81, ptr_params: vec![] },
        // ── 217: getdents64(fd, dirp, count) ────────────────────────────────
        SyscallMeta {
            nr: 217,
            ptr_params: vec![PtrParam {
                idx: 1,
                dir: Dir::Out,
                ptr_type: PtrType::Buf,
                size: Size::FromArg(2),
            }],
        },
        // ── 257: openat(dfd, filename, flags, mode) ─────────────────────────
        SyscallMeta {
            nr: 257,
            ptr_params: vec![PtrParam {
                idx: 1,
                dir: Dir::In,
                ptr_type: PtrType::Str,
                size: Size::Static(MAX_BUF),
            }],
        },
        // ── 262: newfstatat(dfd, filename, statbuf, flag) ───────────────────
        SyscallMeta {
            nr: 262,
            ptr_params: vec![
                PtrParam { idx: 1, dir: Dir::In,  ptr_type: PtrType::Str, size: Size::Static(MAX_BUF) },
                PtrParam { idx: 2, dir: Dir::Out, ptr_type: PtrType::Buf, size: Size::Static(144) },
            ],
        },
    ];

    entries.into_iter().map(|m| (m.nr, m)).collect()
}

/// Return the byte size of a pointer param given the current `args` array.
/// Caps at `MAX_BUF`.
pub fn resolve_size(param: &PtrParam, args: &[u64; 6]) -> usize {
    match param.size {
        Size::FromArg(i) => (args[i] as usize).min(MAX_BUF),
        Size::Static(n) => n,
    }
}
