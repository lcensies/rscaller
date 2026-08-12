use crate::client::Client;
use crate::dirent::parse_dirent64;
use crate::fh::FhTable;
use crate::inode::InodeTable;
use crate::procfs::{ProcFs, ProcPathKind, BEACON_PID_OFFSET};
use crate::stat::stat_bytes_to_attr;
use anyhow::Result;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
    consts::FOPEN_DIRECT_IO,
};
use rscaller_proto::types::SyscallBuf;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// AT_FDCWD = -100
const AT_FDCWD: u64 = (-100i64) as u64;
// AT_SYMLINK_NOFOLLOW flag for newfstatat
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

// Syscall numbers (x86-64) — derived from libc, not handwritten.
const SYS_CLOSE: u64 = libc::SYS_close as u64;
const SYS_LSEEK: u64 = libc::SYS_lseek as u64;
const SYS_PREAD64: u64 = libc::SYS_pread64 as u64;
const SYS_PWRITE64: u64 = libc::SYS_pwrite64 as u64;
const SYS_GETDENTS64: u64 = libc::SYS_getdents64 as u64;
const SYS_OPENAT: u64 = libc::SYS_openat as u64;
const SYS_NEWFSTATAT: u64 = libc::SYS_newfstatat as u64;
const SYS_READLINKAT: u64 = libc::SYS_readlinkat as u64;
const SYS_FCHMODAT: u64 = libc::SYS_fchmodat as u64;
const SYS_FCHOWNAT: u64 = libc::SYS_fchownat as u64;
const SYS_UNLINKAT: u64 = libc::SYS_unlinkat as u64;
const SYS_RENAMEAT: u64 = libc::SYS_renameat as u64;
const SYS_MKDIRAT: u64 = libc::SYS_mkdirat as u64;
const SYS_SYMLINKAT: u64 = libc::SYS_symlinkat as u64;
const SYS_LINKAT: u64 = libc::SYS_linkat as u64;
const SYS_FTRUNCATE: u64 = libc::SYS_ftruncate as u64;
const SYS_UTIMENSAT: u64 = libc::SYS_utimensat as u64;

const TTL: Duration = Duration::from_secs(1);

pub struct RscFs {
    pub client: Arc<Client>,
    pub inodes: Arc<Mutex<InodeTable>>,
    pub fhs: Arc<Mutex<FhTable>>,
    /// When Some, merged /proc mode is active: local PIDs served from real local
    /// procfs; beacon PIDs (virtual = real_pid + BEACON_PID_OFFSET) from beacon.
    pub proc_fs: Option<ProcFs>,
}

impl RscFs {
    fn path_for(&self, ino: u64) -> Option<String> {
        self.inodes.lock().unwrap().get_path(ino).map(|s| s.to_string())
    }

    /// Issue newfstatat(262) for `path`. If `follow` is true, follows symlinks.
    fn stat_path(&self, path: &str, follow: bool) -> Result<(Vec<u8>, libc::stat)> {
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0); // null-terminate

        let flags: u64 = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };

        let (ret, out_bufs) = self.client.syscall(
            SYS_NEWFSTATAT,
            [AT_FDCWD, 0, 0, flags, 0, 0],
            vec![SyscallBuf {
                arg_idx: 1,
                data: path_bytes,
            }],
            vec![(2, 144)],
        )?;

        if ret < 0 {
            anyhow::bail!("newfstatat returned {}", ret);
        }

        let buf = out_bufs
            .into_iter()
            .find(|b| b.arg_idx == 2)
            .map(|b| b.data)
            .unwrap_or_default();

        if buf.len() < std::mem::size_of::<libc::stat>() {
            anyhow::bail!(
                "stat buf too small: {} bytes",
                buf.len()
            );
        }

        let st: libc::stat =
            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const libc::stat) };

        Ok((buf, st))
    }

    fn attr_for_path(&self, ino: u64, path: &str, follow: bool) -> Result<FileAttr> {
        let (buf, st) = self.stat_path(path, follow)?;
        let is_block = (st.st_mode & libc::S_IFMT) == libc::S_IFBLK;
        let mut attr = stat_bytes_to_attr(ino, &buf);
        if is_block {
            if let Some(size) = self.block_device_size(path) {
                attr.size = size;
                attr.blocks = size / u64::from(std::cmp::max(attr.blksize, 1));
            }
            // Libvirt/QEMU may run as a non-root user (libvirt-qemu).  Report
            // the device as world-accessible so the kernel allows the open to
            // reach rscfuse; the real permission check happens on the beacon.
            attr.perm = 0o666;
        }
        Ok(attr)
    }

    /// Open a remote path, returning a remote fd.
    fn remote_open(&self, path: &str, flags: i32, mode: u32) -> Result<i64> {
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);

        let (ret, _) = self.client.syscall(
            SYS_OPENAT,
            [AT_FDCWD, 0, flags as u64, mode as u64, 0, 0],
            vec![SyscallBuf {
                arg_idx: 1,
                data: path_bytes,
            }],
            vec![],
        )?;

        if ret < 0 {
            anyhow::bail!("openat returned {}", ret);
        }
        Ok(ret)
    }

    /// Close a remote fd.
    fn remote_close(&self, rfd: i64) {
        if let Err(e) = self
            .client
            .syscall(SYS_CLOSE, [rfd as u64, 0, 0, 0, 0, 0], vec![], vec![])
        {
            tracing::warn!("remote close fd={} failed: {}", rfd, e);
        }
    }

    /// Best-effort block-device size by opening the path on the beacon and
    /// lseeking to the end.  Block devices report st_size=0 in a plain stat,
    /// but consumers like QEMU's raw driver need a non-zero size.
    fn block_device_size(&self, path: &str) -> Option<u64> {
        let fd = self.remote_open(path, libc::O_RDWR, 0).ok()?;
        let ret = self
            .client
            .syscall(SYS_LSEEK, [fd as u64, 0, libc::SEEK_END as u64, 0, 0, 0], vec![], vec![])
            .ok()?
            .0;
        self.remote_close(fd);
        if ret < 0 {
            return None;
        }
        Some(ret as u64)
    }

    /// True if `path` resolves to a block device on the beacon.
    fn is_block_device(&self, path: &str) -> bool {
        self.stat_path(path, true)
            .map(|(_, st)| (st.st_mode & libc::S_IFMT) == libc::S_IFBLK)
            .unwrap_or(false)
    }
}

impl Filesystem for RscFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(libc::EINVAL); return; }
        };

        let path = {
            let inodes = self.inodes.lock().unwrap();
            inodes.join(parent, name_str)
        };

        let path = match path {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

        // Merged /proc dispatch
        if let Some(proc_fs) = self.proc_fs.as_ref() {
            if path.starts_with("/proc") {
                match ProcFs::classify(&path) {
                    ProcPathKind::ProcSelf => {
                        let ino = self.inodes.lock().unwrap().get_or_create(&path);
                        reply.entry(&TTL, &ProcFs::proc_self_attr(ino), 0);
                        return;
                    }
                    ProcPathKind::Local { pid, rest } => {
                        let ino = self.inodes.lock().unwrap().get_or_create(&path);
                        match proc_fs.attr_local(ino, pid, &rest, true) {
                            Ok(attr) => reply.entry(&TTL, &attr, 0),
                            Err(e) => {
                                tracing::debug!("lookup local {:?}: {}", path, e);
                                reply.error(libc::ENOENT);
                            }
                        }
                        return;
                    }
                    ProcPathKind::Beacon { real_pid, rest } => {
                        let bpath = ProcFs::beacon_path(real_pid, &rest);
                        match proc_fs.stat_beacon(&bpath, true) {
                            Ok(buf) if buf.len() >= std::mem::size_of::<libc::stat>() => {
                                let ino = self.inodes.lock().unwrap().get_or_create(&path);
                                reply.entry(&TTL, &stat_bytes_to_attr(ino, &buf), 0);
                            }
                            Ok(_) => reply.error(libc::EIO),
                            Err(e) => {
                                tracing::debug!("lookup beacon {:?}: {}", path, e);
                                reply.error(libc::ENOENT);
                            }
                        }
                        return;
                    }
                    ProcPathKind::Root | ProcPathKind::Other => {} // fall through to beacon
                }
            }
        }

        match self.attr_for_path(0, &path, true) {
            Ok(attr) => {
                let ino = self.inodes.lock().unwrap().get_or_create(&path);
                let mut attr = attr;
                attr.ino = ino;
                reply.entry(&TTL, &attr, 0);
            }
            Err(e) => {
                tracing::debug!("lookup {:?}: {}", path, e);
                reply.error(libc::ENOENT);
            }
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

        // Merged /proc dispatch
        if let Some(proc_fs) = self.proc_fs.as_ref() {
            if path.starts_with("/proc") {
                match ProcFs::classify(&path) {
                    ProcPathKind::ProcSelf => {
                        reply.attr(&TTL, &ProcFs::proc_self_attr(ino));
                        return;
                    }
                    ProcPathKind::Local { pid, rest } => {
                        match proc_fs.attr_local(ino, pid, &rest, false) {
                            Ok(attr) => reply.attr(&TTL, &attr),
                            Err(e) => {
                                tracing::debug!("getattr local {:?}: {}", path, e);
                                reply.error(libc::EIO);
                            }
                        }
                        return;
                    }
                    ProcPathKind::Beacon { real_pid, rest } => {
                        let bpath = ProcFs::beacon_path(real_pid, &rest);
                        match proc_fs.stat_beacon(&bpath, false) {
                            Ok(buf) if buf.len() >= std::mem::size_of::<libc::stat>() => {
                                reply.attr(&TTL, &stat_bytes_to_attr(ino, &buf));
                            }
                            _ => reply.error(libc::EIO),
                        }
                        return;
                    }
                    ProcPathKind::Root | ProcPathKind::Other => {} // fall through
                }
            }
        }

        match self.attr_for_path(ino, &path, false) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => {
                tracing::debug!("getattr ino={} path={:?}: {}", ino, path, e);
                reply.error(libc::EIO);
            }
        }
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

        // Merged /proc dispatch
        if let Some(proc_fs) = self.proc_fs.as_ref() {
            if path.starts_with("/proc") {
                match ProcFs::classify(&path) {
                    ProcPathKind::Local { pid, rest } => {
                        match proc_fs.open_local(pid, &rest, flags) {
                            Ok(local_fd) => {
                                let fh = self.fhs.lock().unwrap().alloc_local(local_fd);
                                reply.opened(fh, FOPEN_DIRECT_IO);
                            }
                            Err(e) => {
                                tracing::debug!("open local {:?}: {}", path, e);
                                reply.error(libc::EIO);
                            }
                        }
                        return;
                    }
                    ProcPathKind::Beacon { real_pid, rest } => {
                        let bpath = ProcFs::beacon_path(real_pid, &rest);
                        // Read all beacon proc files into a local memfd at open time.
                        // This covers stat/status PID patching and avoids keeping remote
                        // fds open for files that procfs regenerates on every read anyway.
                        match proc_fs.read_beacon_file(&bpath) {
                            Ok(raw) => {
                                let stem = rest.rsplit('/').next().unwrap_or("");
                                let content = match stem {
                                    "stat"   => patch_beacon_stat(&raw, real_pid),
                                    "status" => patch_beacon_status(&raw, real_pid),
                                    "children" => patch_beacon_children(&raw),
                                    _ => raw,
                                };
                                match make_memfd(&content) {
                                    Ok(memfd) => {
                                        let fh = self.fhs.lock().unwrap().alloc_local(memfd);
                                        reply.opened(fh, FOPEN_DIRECT_IO);
                                        return;
                                    }
                                    Err(e) => tracing::debug!("make_memfd {:?}: {}", bpath, e),
                                }
                            }
                            Err(e) => tracing::debug!("read_beacon_file {:?}: {}", bpath, e),
                        }
                        // Fallback: proxy via remote fd (e.g. write-opened files).
                        let open_flags = flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC);
                        match proc_fs.open_beacon(&bpath, open_flags) {
                            Ok(rfd) => {
                                let fh = self.fhs.lock().unwrap().alloc(rfd);
                                reply.opened(fh, FOPEN_DIRECT_IO);
                            }
                            Err(e) => {
                                tracing::debug!("open beacon {:?}: {}", path, e);
                                reply.error(libc::EIO);
                            }
                        }
                        return;
                    }
                    _ => {} // Root, ProcSelf, Other: fall through
                }
            }
        }

        // Strip O_CREAT etc. that don't make sense for an existing file open.
        let mut open_flags = flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC);

        // Block devices forwarded through FUSE cannot honor O_DIRECT: the host
        // FUSE layer and the remote beacon fd both expect ordinary buffered
        // read/write paths.  Strip it before forwarding the open.
        if self.is_block_device(&path) {
            open_flags &= !libc::O_DIRECT;
        }

        match self.remote_open(&path, open_flags, 0) {
            Ok(rfd) => {
                let fh = self.fhs.lock().unwrap().alloc(rfd);
                // FOPEN_DIRECT_IO bypasses the kernel page cache so every read
                // reaches our handler.  Required for /proc files which report
                // st_size=0 and would otherwise be served as empty from cache.
                reply.opened(fh, FOPEN_DIRECT_IO);
            }
            Err(e) => {
                tracing::debug!("open ino={}: {}", ino, e);
                reply.error(libc::EIO);
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        // Local fh: read from real /proc via local pread.
        if let Some(local_fd) = self.fhs.lock().unwrap().get_local(fh) {
            let mut buf = vec![0u8; size as usize];
            let ret = unsafe {
                libc::pread(
                    local_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    size as libc::size_t,
                    offset as libc::off_t,
                )
            };
            if ret < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                reply.error(errno);
            } else {
                reply.data(&buf[..ret as usize]);
            }
            return;
        }

        let rfd = match self.fhs.lock().unwrap().get(fh) {
            Some(fd) => fd,
            None => { reply.error(libc::EBADF); return; }
        };

        let sz = size as u64;
        match self.client.syscall(
            SYS_PREAD64,
            [rfd as u64, 0, sz, offset as u64, 0, 0],
            vec![],
            vec![(1, sz)],
        ) {
            Ok((ret, out_bufs)) => {
                if ret < 0 {
                    reply.error((-ret) as i32);
                    return;
                }
                let bytes_read = ret as usize;
                let data = out_bufs
                    .into_iter()
                    .find(|b| b.arg_idx == 1)
                    .map(|b| b.data)
                    .unwrap_or_default();
                reply.data(&data[..bytes_read.min(data.len())]);
            }
            Err(e) => {
                tracing::debug!("read fh={}: {}", fh, e);
                reply.error(libc::EIO);
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let rfd = match self.fhs.lock().unwrap().get(fh) {
            Some(fd) => fd,
            None => { reply.error(libc::EBADF); return; }
        };

        let len = data.len() as u64;
        match self.client.syscall(
            SYS_PWRITE64,
            [rfd as u64, 0, len, offset as u64, 0, 0],
            vec![SyscallBuf { arg_idx: 1, data: data.to_vec() }],
            vec![],
        ) {
            Ok((ret, _)) => {
                if ret < 0 {
                    reply.error((-ret) as i32);
                } else {
                    reply.written(ret as u32);
                }
            }
            Err(e) => {
                tracing::debug!("write fh={}: {}", fh, e);
                reply.error(libc::EIO);
            }
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // Extract under lock then drop the guard before any further locking.
        let local_fd = self.fhs.lock().unwrap().release_local(fh);
        if let Some(lfd) = local_fd {
            unsafe { libc::close(lfd); }
        } else {
            let rfd = self.fhs.lock().unwrap().release(fh);
            if let Some(rfd) = rfd {
                self.remote_close(rfd);
            }
        }
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

        // Merged /proc dispatch
        if let Some(proc_fs) = self.proc_fs.as_ref() {
            if path.starts_with("/proc") {
                match ProcFs::classify(&path) {
                    ProcPathKind::Local { pid, rest } => {
                        match proc_fs.open_local(pid, &rest, libc::O_RDONLY | libc::O_DIRECTORY) {
                            Ok(local_fd) => {
                                let fh = self.fhs.lock().unwrap().alloc_local(local_fd);
                                reply.opened(fh, 0);
                            }
                            Err(e) => {
                                tracing::debug!("opendir local {:?}: {}", path, e);
                                reply.error(libc::EIO);
                            }
                        }
                        return;
                    }
                    ProcPathKind::Beacon { real_pid, rest } => {
                        let bpath = ProcFs::beacon_path(real_pid, &rest);
                        match proc_fs.open_beacon(&bpath, libc::O_RDONLY | libc::O_DIRECTORY) {
                            Ok(rfd) => {
                                let fh = self.fhs.lock().unwrap().alloc(rfd);
                                reply.opened(fh, 0);
                            }
                            Err(e) => {
                                tracing::debug!("opendir beacon {:?}: {}", path, e);
                                reply.error(libc::EIO);
                            }
                        }
                        return;
                    }
                    _ => {} // Root, ProcSelf, Other: fall through to beacon open
                }
            }
        }

        // O_RDONLY | O_DIRECTORY
        match self.remote_open(&path, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(rfd) => {
                let fh = self.fhs.lock().unwrap().alloc(rfd);
                reply.opened(fh, 0);
            }
            Err(e) => {
                tracing::debug!("opendir ino={}: {}", ino, e);
                reply.error(libc::EIO);
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        // Local fh: enumerate a real local /proc/<pid>/ directory.
        if let Some(local_fd) = self.fhs.lock().unwrap().get_local(fh) {
            let mut all_entries = Vec::new();
            let mut buf = vec![0u8; 65536];
            loop {
                let ret = unsafe {
                    libc::syscall(
                        libc::SYS_getdents64,
                        local_fd as libc::c_long,
                        buf.as_mut_ptr() as libc::c_long,
                        buf.len() as libc::c_long,
                    )
                };
                if ret <= 0 { break; }
                let mut parsed = parse_dirent64(&buf[..ret as usize]);
                all_entries.append(&mut parsed);
            }
            for (i, entry) in all_entries.iter().enumerate() {
                if (i as i64) < offset { continue; }
                let kind = dirent_type_to_filetype(entry.file_type);
                if reply.add(entry.ino, (i + 1) as i64, kind, OsStr::new(&entry.name)) {
                    break;
                }
            }
            reply.ok();
            return;
        }

        // Merged /proc root: emit beacon PIDs (with offset) + local PIDs.
        if self.proc_fs.is_some() {
            let is_proc_root = {
                let inodes = self.inodes.lock().unwrap();
                inodes.get_path(ino).map(|p| p == "/proc").unwrap_or(false)
            };
            if is_proc_root {
                let rfd = match self.fhs.lock().unwrap().get(fh) {
                    Some(fd) => fd,
                    None => { reply.error(libc::EBADF); return; }
                };

                let mut all_entries: Vec<(u64, FileType, String)> = Vec::new();
                loop {
                    let res = self.client.syscall(
                        SYS_GETDENTS64,
                        [rfd as u64, 0, 65536, 0, 0, 0],
                        vec![],
                        vec![(1, 65536)],
                    );
                    match res {
                        Ok((ret, out_bufs)) => {
                            if ret <= 0 { break; }
                            let buf = out_bufs.into_iter().find(|b| b.arg_idx == 1)
                                .map(|b| b.data).unwrap_or_default();
                            for e in parse_dirent64(&buf[..(ret as usize).min(buf.len())]) {
                                if e.name == "." || e.name == ".." { continue; }
                                let kind = dirent_type_to_filetype(e.file_type);
                                if let Ok(pid) = e.name.parse::<u64>() {
                                    if pid > 0 {
                                        let virt = pid + BEACON_PID_OFFSET;
                                        all_entries.push((virt, kind, virt.to_string()));
                                    }
                                } else {
                                    // Non-PID entry (net, sys, version, etc.)
                                    all_entries.push((e.ino, kind, e.name));
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("merged-proc getdents64: {}", e);
                            reply.error(libc::EIO);
                            return;
                        }
                    }
                }

                // Append local PIDs
                for pid in self.proc_fs.as_ref().unwrap().local_pids() {
                    all_entries.push((pid as u64, FileType::Directory, pid.to_string()));
                }

                for (i, (entry_ino, kind, name)) in all_entries.iter().enumerate() {
                    if (i as i64) < offset { continue; }
                    if reply.add(*entry_ino, (i + 1) as i64, *kind, OsStr::new(name)) {
                        break;
                    }
                }
                reply.ok();
                return;
            }
        }

        // Normal remote readdir.
        let rfd = match self.fhs.lock().unwrap().get(fh) {
            Some(fd) => fd,
            None => { reply.error(libc::EBADF); return; }
        };

        // Collect ALL entries via getdents64 loop, then emit from `offset`.
        let mut all_entries = Vec::new();
        loop {
            let res = self.client.syscall(
                SYS_GETDENTS64,
                [rfd as u64, 0, 65536, 0, 0, 0],
                vec![],
                vec![(1, 65536)],
            );
            match res {
                Ok((ret, out_bufs)) => {
                    if ret <= 0 {
                        break;
                    }
                    let buf = out_bufs
                        .into_iter()
                        .find(|b| b.arg_idx == 1)
                        .map(|b| b.data)
                        .unwrap_or_default();
                    let bytes = ret as usize;
                    let mut parsed = parse_dirent64(&buf[..bytes.min(buf.len())]);
                    all_entries.append(&mut parsed);
                }
                Err(e) => {
                    tracing::debug!("getdents64 fh={}: {}", fh, e);
                    reply.error(libc::EIO);
                    return;
                }
            }
        }

        // Emit entries after `offset` (offset is the d_off of the last-seen entry).
        // offset=0 means "start from the beginning".
        for (i, entry) in all_entries.iter().enumerate() {
            if (i as i64) < offset {
                continue;
            }

            let kind = dirent_type_to_filetype(entry.file_type);

            let next_offset = (i + 1) as i64;
            if reply.add(entry.ino, next_offset, kind, OsStr::new(&entry.name)) {
                break; // buffer full
            }
        }

        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        let local_fd = self.fhs.lock().unwrap().release_local(fh);
        if let Some(lfd) = local_fd {
            unsafe { libc::close(lfd); }
        } else {
            let rfd = self.fhs.lock().unwrap().release(fh);
            if let Some(rfd) = rfd {
                self.remote_close(rfd);
            }
        }
        reply.ok();
    }

    fn readlink(&mut self, req: &Request, ino: u64, reply: ReplyData) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

        // Merged /proc dispatch
        if let Some(proc_fs) = self.proc_fs.as_ref() {
            if path.starts_with("/proc") {
                match ProcFs::classify(&path) {
                    ProcPathKind::ProcSelf => {
                        // Return the PID of the process that issued this FUSE request,
                        // not rscfuse's own PID — callers like `tail` use /proc/self/fd/N
                        // to access their own file descriptors.
                        reply.data(req.pid().to_string().as_bytes());
                        return;
                    }
                    ProcPathKind::Local { pid, rest } => {
                        match proc_fs.readlink_local(pid, &rest) {
                            Ok(data) => reply.data(&data),
                            Err(e) => {
                                tracing::debug!("readlink local {:?}: {}", path, e);
                                reply.error(libc::EINVAL);
                            }
                        }
                        return;
                    }
                    ProcPathKind::Beacon { real_pid, rest } => {
                        let bpath = ProcFs::beacon_path(real_pid, &rest);
                        match proc_fs.readlink_beacon(&bpath) {
                            Ok(data) => reply.data(&data),
                            Err(e) => {
                                tracing::debug!("readlink beacon {:?}: {}", path, e);
                                reply.error(libc::EINVAL);
                            }
                        }
                        return;
                    }
                    ProcPathKind::Root | ProcPathKind::Other => {} // fall through
                }
            }
        }

        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);

        const BUF_SZ: u64 = 4096;
        match self.client.syscall(
            SYS_READLINKAT,
            [AT_FDCWD, 0, 0, BUF_SZ, 0, 0],
            vec![SyscallBuf { arg_idx: 1, data: path_bytes }],
            vec![(2, BUF_SZ)],
        ) {
            Ok((ret, out_bufs)) => {
                if ret < 0 {
                    reply.error((-ret) as i32);
                    return;
                }
                let bytes = ret as usize;
                let buf = out_bufs
                    .into_iter()
                    .find(|b| b.arg_idx == 2)
                    .map(|b| b.data)
                    .unwrap_or_default();
                reply.data(&buf[..bytes.min(buf.len())]);
            }
            Err(e) => {
                tracing::debug!("readlink ino={}: {}", ino, e);
                reply.error(libc::EIO);
            }
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(libc::EINVAL); return; }
        };

        let path = {
            let inodes = self.inodes.lock().unwrap();
            inodes.join(parent, name_str)
        };
        let path = match path {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

        let open_flags = flags | libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC;

        match self.remote_open(&path, open_flags, mode) {
            Ok(rfd) => {
                let fh = self.fhs.lock().unwrap().alloc(rfd);
                match self.stat_path(&path, false) {
                    Ok((buf, _)) => {
                        let ino = self.inodes.lock().unwrap().get_or_create(&path);
                        let attr = stat_bytes_to_attr(ino, &buf);
                        reply.created(&TTL, &attr, 0, fh, 0);
                    }
                    Err(e) => {
                        tracing::debug!("create stat {:?}: {}", path, e);
                        // Still have the open fd — just return EIO.
                        self.fhs.lock().unwrap().release(fh);
                        self.remote_close(rfd);
                        reply.error(libc::EIO);
                    }
                }
            }
            Err(e) => {
                tracing::debug!("create open {:?}: {}", path, e);
                reply.error(libc::EIO);
            }
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(libc::EINVAL); return; }
        };

        let path = {
            let inodes = self.inodes.lock().unwrap();
            inodes.join(parent, name_str)
        };
        let path = match path {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);

        match self.client.syscall(
            SYS_MKDIRAT,
            [AT_FDCWD, 0, mode as u64, 0, 0, 0],
            vec![SyscallBuf { arg_idx: 1, data: path_bytes }],
            vec![],
        ) {
            Ok((ret, _)) => {
                if ret < 0 {
                    reply.error((-ret) as i32);
                    return;
                }
                match self.stat_path(&path, false) {
                    Ok((buf, _)) => {
                        let ino = self.inodes.lock().unwrap().get_or_create(&path);
                        let attr = stat_bytes_to_attr(ino, &buf);
                        reply.entry(&TTL, &attr, 0);
                    }
                    Err(_) => reply.error(libc::EIO),
                }
            }
            Err(e) => {
                tracing::debug!("mkdir {:?}: {}", path, e);
                reply.error(libc::EIO);
            }
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.unlink_or_rmdir(parent, name, 0, reply);
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.unlink_or_rmdir(parent, name, libc::AT_REMOVEDIR, reply);
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let src = self.make_path(parent, name);
        let dst = self.make_path(newparent, newname);

        let (src, dst) = match (src, dst) {
            (Some(s), Some(d)) => (s, d),
            _ => { reply.error(libc::ENOENT); return; }
        };

        let mut src_bytes = src.as_bytes().to_vec(); src_bytes.push(0);
        let mut dst_bytes = dst.as_bytes().to_vec(); dst_bytes.push(0);

        match self.client.syscall(
            SYS_RENAMEAT,
            [AT_FDCWD, 0, AT_FDCWD, 0, 0, 0],
            vec![
                SyscallBuf { arg_idx: 1, data: src_bytes },
                SyscallBuf { arg_idx: 3, data: dst_bytes },
            ],
            vec![],
        ) {
            Ok((ret, _)) => {
                if ret < 0 { reply.error((-ret) as i32); } else { reply.ok(); }
            }
            Err(e) => {
                tracing::debug!("rename {:?}->{:?}: {}", src, dst, e);
                reply.error(libc::EIO);
            }
        }
    }

    fn symlink(
        &mut self,
        _req: &Request,
        parent: u64,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        let name_str = match link_name.to_str() {
            Some(s) => s,
            None => { reply.error(libc::EINVAL); return; }
        };
        let target_str = match target.to_str() {
            Some(s) => s,
            None => { reply.error(libc::EINVAL); return; }
        };

        let path = {
            let inodes = self.inodes.lock().unwrap();
            inodes.join(parent, name_str)
        };
        let path = match path {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

        let mut target_bytes = target_str.as_bytes().to_vec(); target_bytes.push(0);
        let mut path_bytes = path.as_bytes().to_vec(); path_bytes.push(0);

        // symlinkat(target, AT_FDCWD, linkpath)
        match self.client.syscall(
            SYS_SYMLINKAT,
            [0, AT_FDCWD, 0, 0, 0, 0],
            vec![
                SyscallBuf { arg_idx: 0, data: target_bytes },
                SyscallBuf { arg_idx: 2, data: path_bytes },
            ],
            vec![],
        ) {
            Ok((ret, _)) => {
                if ret < 0 {
                    reply.error((-ret) as i32);
                    return;
                }
                match self.stat_path(&path, false) {
                    Ok((buf, _)) => {
                        let ino = self.inodes.lock().unwrap().get_or_create(&path);
                        let attr = stat_bytes_to_attr(ino, &buf);
                        reply.entry(&TTL, &attr, 0);
                    }
                    Err(_) => reply.error(libc::EIO),
                }
            }
            Err(e) => {
                tracing::debug!("symlink {:?}: {}", path, e);
                reply.error(libc::EIO);
            }
        }
    }

    fn link(
        &mut self,
        _req: &Request,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let src = match self.path_for(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };
        let dst = self.make_path(newparent, newname);
        let dst = match dst {
            Some(d) => d,
            None => { reply.error(libc::ENOENT); return; }
        };

        let mut src_bytes = src.as_bytes().to_vec(); src_bytes.push(0);
        let mut dst_bytes = dst.as_bytes().to_vec(); dst_bytes.push(0);

        // linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0)
        match self.client.syscall(
            SYS_LINKAT,
            [AT_FDCWD, 0, AT_FDCWD, 0, 0, 0],
            vec![
                SyscallBuf { arg_idx: 1, data: src_bytes },
                SyscallBuf { arg_idx: 3, data: dst_bytes },
            ],
            vec![],
        ) {
            Ok((ret, _)) => {
                if ret < 0 {
                    reply.error((-ret) as i32);
                    return;
                }
                match self.stat_path(&dst, false) {
                    Ok((buf, _)) => {
                        let new_ino = self.inodes.lock().unwrap().get_or_create(&dst);
                        let attr = stat_bytes_to_attr(new_ino, &buf);
                        reply.entry(&TTL, &attr, 0);
                    }
                    Err(_) => reply.error(libc::EIO),
                }
            }
            Err(e) => {
                tracing::debug!("link {:?}->{:?}: {}", src, dst, e);
                reply.error(libc::EIO);
            }
        }
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

        // chmod
        if let Some(m) = mode {
            let mut path_bytes = path.as_bytes().to_vec(); path_bytes.push(0);
            if let Ok((ret, _)) = self.client.syscall(
                SYS_FCHMODAT,
                [AT_FDCWD, 0, m as u64, 0, 0, 0],
                vec![SyscallBuf { arg_idx: 1, data: path_bytes }],
                vec![],
            ) {
                if ret < 0 { reply.error((-ret) as i32); return; }
            }
        }

        // chown
        if uid.is_some() || gid.is_some() {
            let u = uid.unwrap_or(u32::MAX) as u64;
            let g = gid.unwrap_or(u32::MAX) as u64;
            let mut path_bytes = path.as_bytes().to_vec(); path_bytes.push(0);
            if let Ok((ret, _)) = self.client.syscall(
                SYS_FCHOWNAT,
                [AT_FDCWD, 0, u, g, 0, 0],
                vec![SyscallBuf { arg_idx: 1, data: path_bytes }],
                vec![],
            ) {
                if ret < 0 { reply.error((-ret) as i32); return; }
            }
        }

        // truncate — prefer fd-based if we have one
        if let Some(sz) = size {
            let ret = if let Some(fh_val) = fh {
                let rfd = self.fhs.lock().unwrap().get(fh_val);
                if let Some(rfd) = rfd {
                    self.client.syscall(
                        SYS_FTRUNCATE,
                        [rfd as u64, sz, 0, 0, 0, 0],
                        vec![],
                        vec![],
                    ).map(|(r, _)| r).unwrap_or(-1)
                } else {
                    -1
                }
            } else {
                -1
            };

            if ret < 0 {
                // Fall back to truncate via openat+ftruncate.
                match self.remote_open(&path, libc::O_WRONLY, 0) {
                    Ok(rfd) => {
                        let r = self.client.syscall(
                            SYS_FTRUNCATE,
                            [rfd as u64, sz, 0, 0, 0, 0],
                            vec![],
                            vec![],
                        ).map(|(r, _)| r).unwrap_or(-1);
                        self.remote_close(rfd);
                        if r < 0 { reply.error((-r) as i32); return; }
                    }
                    Err(_) => { reply.error(libc::EIO); return; }
                }
            }
        }

        // utimensat
        if atime.is_some() || mtime.is_some() {
            let to_timespec = |t: fuser::TimeOrNow| -> (i64, i64) {
                match t {
                    fuser::TimeOrNow::SpecificTime(st) => {
                        let dur = st.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                        (dur.as_secs() as i64, dur.subsec_nanos() as i64)
                    }
                    fuser::TimeOrNow::Now => (0, libc::UTIME_NOW as i64),
                }
            };

            let (at_sec, at_nsec) = atime.map(to_timespec).unwrap_or((0, libc::UTIME_OMIT as i64));
            let (mt_sec, mt_nsec) = mtime.map(to_timespec).unwrap_or((0, libc::UTIME_OMIT as i64));

            // Pack two timespec structs (each 16 bytes on 64-bit): [at_sec, at_nsec, mt_sec, mt_nsec]
            let mut times_buf = Vec::with_capacity(32);
            times_buf.extend_from_slice(&at_sec.to_le_bytes());
            times_buf.extend_from_slice(&at_nsec.to_le_bytes());
            times_buf.extend_from_slice(&mt_sec.to_le_bytes());
            times_buf.extend_from_slice(&mt_nsec.to_le_bytes());

            let mut path_bytes = path.as_bytes().to_vec(); path_bytes.push(0);

            if let Ok((ret, _)) = self.client.syscall(
                SYS_UTIMENSAT,
                [AT_FDCWD, 0, 0, 0, 0, 0],
                vec![
                    SyscallBuf { arg_idx: 1, data: path_bytes },
                    SyscallBuf { arg_idx: 2, data: times_buf },
                ],
                vec![],
            ) {
                if ret < 0 { reply.error((-ret) as i32); return; }
            }
        }

        // Return updated attrs.
        match self.attr_for_path(ino, &path, false) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(_) => reply.error(libc::EIO),
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

impl RscFs {
    fn make_path(&self, parent: u64, name: &OsStr) -> Option<String> {
        let name_str = name.to_str()?;
        self.inodes.lock().unwrap().join(parent, name_str)
    }

    fn unlink_or_rmdir(&mut self, parent: u64, name: &OsStr, extra_flags: i32, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(libc::EINVAL); return; }
        };

        let path = {
            let inodes = self.inodes.lock().unwrap();
            inodes.join(parent, name_str)
        };
        let path = match path {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);

        match self.client.syscall(
            SYS_UNLINKAT,
            [AT_FDCWD, 0, extra_flags as u64, 0, 0, 0],
            vec![SyscallBuf { arg_idx: 1, data: path_bytes }],
            vec![],
        ) {
            Ok((ret, _)) => {
                if ret < 0 { reply.error((-ret) as i32); } else { reply.ok(); }
            }
            Err(e) => {
                tracing::debug!("unlink/rmdir {:?}: {}", path, e);
                reply.error(libc::EIO);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Beacon /proc/<pid>/stat and /proc/<pid>/status PID patching
//
// procps-ng validates that stat[0] (pid field in the file) matches the
// directory name.  Beacon processes appear at virtual PIDs (real + offset),
// so we rewrite those two files at open time and serve them from a memfd.
// ---------------------------------------------------------------------------

/// Add BEACON_PID_OFFSET to a non-zero PID string; leave "0" unchanged.
fn virt_pid(s: &str) -> String {
    match s.trim().parse::<u64>() {
        Ok(0) | Err(_) => s.to_string(),
        Ok(n) => (n + BEACON_PID_OFFSET).to_string(),
    }
}

/// Rewrite /proc/<real_pid>/stat so field 0 and the ppid/pgrp/session fields
/// carry virtual PIDs.  The comm field "(name)" may contain spaces, so we
/// locate it by the first '(' and last ')' rather than splitting on spaces.
fn patch_beacon_stat(content: &[u8], real_pid: u32) -> Vec<u8> {
    let s = match std::str::from_utf8(content) { Ok(s) => s, Err(_) => return content.to_vec() };
    let open  = match s.find('(')  { Some(i) => i, None => return content.to_vec() };
    let close = match s.rfind(')') { Some(i) => i, None => return content.to_vec() };
    if close <= open { return content.to_vec(); }
    let comm = &s[open..=close]; // "(name)" — verbatim, may contain spaces
    // Fields after ')': <state> <ppid> <pgrp> <session> <tty_nr> ...
    let after: Vec<&str> = s[close + 1..].split_whitespace().collect();
    if after.len() < 4 { return content.to_vec(); }
    let state   = after[0];
    let ppid    = virt_pid(after[1]);
    let pgrp    = virt_pid(after[2]);
    let session = virt_pid(after[3]);
    let rest: Vec<&str> = after[4..].to_vec();
    let virtual_pid = real_pid as u64 + BEACON_PID_OFFSET;
    let mut out = format!("{} {} {} {} {} {}", virtual_pid, comm, state, ppid, pgrp, session);
    for f in &rest { out.push(' '); out.push_str(f); }
    out.push('\n');
    out.into_bytes()
}

/// Rewrite /proc/<real_pid>/status so Pid/Tgid/PPid/TracerPid carry virtual PIDs.
fn patch_beacon_status(content: &[u8], real_pid: u32) -> Vec<u8> {
    let s = match std::str::from_utf8(content) { Ok(s) => s, Err(_) => return content.to_vec() };
    let mut out = String::with_capacity(s.len() + 64);
    for line in s.lines() {
        let colon = match line.find(':') { Some(i) => i, None => { out.push_str(line); out.push('\n'); continue; } };
        let key = &line[..colon];
        let raw_val = &line[colon + 1..];
        match key {
            "Pid" => out.push_str(&format!("Pid:\t{}\n", real_pid as u64 + BEACON_PID_OFFSET)),
            "Tgid" | "PPid" | "TracerPid" => {
                out.push_str(&format!("{}:\t{}\n", key, virt_pid(raw_val)));
            }
            _ => { out.push_str(line); out.push('\n'); }
        }
    }
    out.into_bytes()
}

/// Rewrite /proc/<pid>/task/<tid>/children — space-separated child PIDs — adding the offset.
fn patch_beacon_children(content: &[u8]) -> Vec<u8> {
    let s = match std::str::from_utf8(content) { Ok(s) => s, Err(_) => return content.to_vec() };
    let out: Vec<String> = s.split_whitespace().map(virt_pid).collect();
    if out.is_empty() {
        return content.to_vec();
    }
    let mut result = out.join(" ");
    result.push('\n');
    result.into_bytes()
}

/// Create an anonymous memfd containing `content`; returns the fd.
fn make_memfd(content: &[u8]) -> anyhow::Result<std::os::unix::io::RawFd> {
    let name = std::ffi::CString::new("proc-patch").unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0u64) } as i32;
    if fd < 0 { anyhow::bail!("memfd_create: {}", std::io::Error::last_os_error()); }
    let mut written = 0;
    while written < content.len() {
        let ret = unsafe {
            libc::write(fd, content[written..].as_ptr() as *const libc::c_void, content.len() - written)
        };
        if ret <= 0 { unsafe { libc::close(fd); } anyhow::bail!("memfd write"); }
        written += ret as usize;
    }
    Ok(fd)
}

fn dirent_type_to_filetype(d_type: u8) -> FileType {
    // DT_* constants
    match d_type {
        4 => FileType::Directory,
        8 => FileType::RegularFile,
        10 => FileType::Symlink,
        2 => FileType::CharDevice,
        6 => FileType::BlockDevice,
        1 => FileType::NamedPipe,
        12 => FileType::Socket,
        _ => FileType::RegularFile,
    }
}
