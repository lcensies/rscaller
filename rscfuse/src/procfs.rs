use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use fuser::{FileAttr, FileType};
use rscaller_proto::types::SyscallBuf;

use crate::client::Client;
use crate::dirent::parse_dirent64;
use crate::stat::stat_bytes_to_attr;

pub const BEACON_PID_OFFSET: u64 = 10_000_000;

const AT_FDCWD: u64 = (-100i64) as u64;
const SYS_CLOSE: u64 = 3;
const SYS_PREAD64: u64 = 17;
const SYS_OPENAT: u64 = 257;
const SYS_NEWFSTATAT: u64 = 262;
const SYS_READLINKAT: u64 = 267;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

/// Classification of a /proc path for merged-proc routing.
pub enum ProcPathKind {
    /// The "/proc" directory itself.
    Root,
    /// "/proc/self" — virtual symlink to the local process's PID.
    ProcSelf,
    /// "/proc/<pid>[/rest]" where pid < BEACON_PID_OFFSET — serve from real local /proc.
    Local { pid: u32, rest: String },
    /// "/proc/<pid>[/rest]" where pid >= BEACON_PID_OFFSET — beacon process at real_pid.
    Beacon { real_pid: u32, rest: String },
    /// Any other /proc path (e.g. /proc/net, /proc/version) — proxy to beacon unchanged.
    Other,
}

/// Merged /proc handler.
///
/// For local PIDs, uses `real_proc_dirfd` (opened before the FUSE mount) as an
/// `openat(2)` anchor to bypass the FUSE mount point and read real local procfs
/// entries directly. For beacon PIDs (virtual PID = real_pid + BEACON_PID_OFFSET),
/// strips the offset and proxies to the beacon.
pub struct ProcFs {
    pub client: Arc<Client>,
    /// Opened to the real /proc before fuser::mount2 — survives bind-mount replacement.
    pub real_proc_dirfd: RawFd,
}

impl Drop for ProcFs {
    fn drop(&mut self) {
        unsafe { libc::close(self.real_proc_dirfd); }
    }
}

impl ProcFs {
    pub fn new(client: Arc<Client>, real_proc_dirfd: RawFd) -> Self {
        Self { client, real_proc_dirfd }
    }

    /// Classify a /proc path.  Returns `Other` if path doesn't start with "/proc".
    pub fn classify(path: &str) -> ProcPathKind {
        let rest = match path.strip_prefix("/proc") {
            Some(r) => r,
            None => return ProcPathKind::Other,
        };
        if rest.is_empty() {
            return ProcPathKind::Root;
        }
        if rest == "/self" {
            return ProcPathKind::ProcSelf;
        }
        let after_slash = match rest.strip_prefix('/') {
            Some(s) => s,
            None => return ProcPathKind::Other,
        };
        let (num_str, suffix) = match after_slash.find('/') {
            Some(i) => (&after_slash[..i], after_slash[i..].to_string()),
            None => (after_slash, String::new()),
        };
        if let Ok(pid) = num_str.parse::<u64>() {
            if pid == 0 {
                return ProcPathKind::Other;
            }
            if pid >= BEACON_PID_OFFSET {
                return ProcPathKind::Beacon { real_pid: (pid - BEACON_PID_OFFSET) as u32, rest: suffix };
            } else {
                return ProcPathKind::Local { pid: pid as u32, rest: suffix };
            }
        }
        ProcPathKind::Other
    }

    /// Translate a virtual beacon path to its real beacon-side path.
    pub fn beacon_path(real_pid: u32, rest: &str) -> String {
        format!("/proc/{}{}", real_pid, rest)
    }

    /// Build relative path for openat into real /proc.
    fn local_rel(pid: u32, rest: &str) -> String {
        if rest.is_empty() { pid.to_string() } else { format!("{}{}", pid, rest) }
    }

    /// List local PIDs by opening a fresh dir fd from real_proc_dirfd.
    pub fn local_pids(&self) -> Vec<u32> {
        let dirfd = unsafe {
            libc::openat(
                self.real_proc_dirfd,
                b".\0".as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if dirfd < 0 { return vec![]; }
        let mut pids = Vec::new();
        let mut buf = vec![0u8; 65536];
        loop {
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    dirfd as libc::c_long,
                    buf.as_mut_ptr() as libc::c_long,
                    buf.len() as libc::c_long,
                )
            };
            if ret <= 0 { break; }
            for e in parse_dirent64(&buf[..ret as usize]) {
                if let Ok(pid) = e.name.parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
        unsafe { libc::close(dirfd); }
        pids
    }

    /// Stat a local /proc entry.  `follow` controls symlink following.
    pub fn attr_local(&self, ino: u64, pid: u32, rest: &str, follow: bool) -> anyhow::Result<FileAttr> {
        let rel = Self::local_rel(pid, rest);
        let rel_cstr = std::ffi::CString::new(rel.as_str()).unwrap();
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
        let ret = unsafe { libc::fstatat(self.real_proc_dirfd, rel_cstr.as_ptr(), &mut st, flags) };
        if ret < 0 {
            anyhow::bail!("local fstatat({:?}): {}", rel, std::io::Error::last_os_error());
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(&st as *const _ as *const u8, std::mem::size_of::<libc::stat>())
        };
        Ok(stat_bytes_to_attr(ino, bytes))
    }

    /// Open a local /proc entry via real_proc_dirfd. Returns a local fd.
    pub fn open_local(&self, pid: u32, rest: &str, flags: i32) -> anyhow::Result<RawFd> {
        let rel = Self::local_rel(pid, rest);
        let rel_cstr = std::ffi::CString::new(rel.as_str()).unwrap();
        let open_flags = (flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC)) | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(self.real_proc_dirfd, rel_cstr.as_ptr(), open_flags, 0u32) };
        if fd < 0 {
            anyhow::bail!("local openat({:?}): {}", rel, std::io::Error::last_os_error());
        }
        Ok(fd)
    }

    /// Readlink on a local /proc entry.
    pub fn readlink_local(&self, pid: u32, rest: &str) -> anyhow::Result<Vec<u8>> {
        let rel = Self::local_rel(pid, rest);
        let rel_cstr = std::ffi::CString::new(rel.as_str()).unwrap();
        let mut buf = vec![0u8; 4096];
        let ret = unsafe {
            libc::readlinkat(
                self.real_proc_dirfd,
                rel_cstr.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if ret < 0 {
            anyhow::bail!("local readlinkat({:?}): {}", rel, std::io::Error::last_os_error());
        }
        Ok(buf[..ret as usize].to_vec())
    }

    /// Stat a path on the beacon.  `follow` controls symlink following.
    pub fn stat_beacon(&self, path: &str, follow: bool) -> anyhow::Result<Vec<u8>> {
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);
        let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
        let (ret, out_bufs) = self.client.syscall(
            SYS_NEWFSTATAT,
            [AT_FDCWD, 0, 0, flags, 0, 0],
            vec![SyscallBuf { arg_idx: 1, data: path_bytes }],
            vec![(2, 144)],
        )?;
        if ret < 0 {
            anyhow::bail!("beacon newfstatat({}) returned {}", path, ret);
        }
        Ok(out_bufs.into_iter().find(|b| b.arg_idx == 2).map(|b| b.data).unwrap_or_default())
    }

    /// Open a path on the beacon. Returns a remote fd.
    pub fn open_beacon(&self, path: &str, flags: i32) -> anyhow::Result<i64> {
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);
        let open_flags = (flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC)) as u64;
        let (ret, _) = self.client.syscall(
            SYS_OPENAT,
            [AT_FDCWD, 0, open_flags, 0, 0, 0],
            vec![SyscallBuf { arg_idx: 1, data: path_bytes }],
            vec![],
        )?;
        if ret < 0 {
            anyhow::bail!("beacon openat({}) returned {}", path, ret);
        }
        Ok(ret)
    }

    /// Readlink on a beacon path.
    pub fn readlink_beacon(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);
        const BUF_SZ: u64 = 4096;
        let (ret, out_bufs) = self.client.syscall(
            SYS_READLINKAT,
            [AT_FDCWD, 0, 0, BUF_SZ, 0, 0],
            vec![SyscallBuf { arg_idx: 1, data: path_bytes }],
            vec![(2, BUF_SZ)],
        )?;
        if ret < 0 {
            anyhow::bail!("beacon readlinkat({}) returned {}", path, ret);
        }
        let bytes = ret as usize;
        let buf = out_bufs.into_iter().find(|b| b.arg_idx == 2).map(|b| b.data).unwrap_or_default();
        Ok(buf[..bytes.min(buf.len())].to_vec())
    }

    /// Read the full content of a beacon file: opens, pread64-loops, closes.
    pub fn read_beacon_file(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let rfd = self.open_beacon(path, libc::O_RDONLY)?;
        let mut content = Vec::new();
        let chunk: u64 = 4096;
        let mut off: u64 = 0;
        loop {
            match self.client.syscall(
                SYS_PREAD64,
                [rfd as u64, 0, chunk, off, 0, 0],
                vec![],
                vec![(1, chunk)],
            ) {
                Ok((ret, bufs)) if ret > 0 => {
                    let data = bufs.into_iter().find(|b| b.arg_idx == 1)
                        .map(|b| b.data).unwrap_or_default();
                    let n = ret as usize;
                    content.extend_from_slice(&data[..n.min(data.len())]);
                    off += n as u64;
                    if n < chunk as usize { break; }
                }
                _ => break,
            }
        }
        let _ = self.client.syscall(SYS_CLOSE, [rfd as u64, 0, 0, 0, 0, 0], vec![], vec![]);
        Ok(content)
    }

    /// Synthetic FileAttr for /proc/self (a symlink with no meaningful size).
    pub fn proc_self_attr(ino: u64) -> FileAttr {
        let epoch = UNIX_EPOCH + Duration::from_secs(0);
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: epoch,
            mtime: epoch,
            ctime: epoch,
            crtime: epoch,
            kind: FileType::Symlink,
            perm: 0o777,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }
}
