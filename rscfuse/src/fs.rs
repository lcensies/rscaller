use crate::client::Client;
use crate::dirent::parse_dirent64;
use crate::fh::FhTable;
use crate::inode::InodeTable;
use crate::stat::stat_bytes_to_attr;
use anyhow::Result;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use rscaller_proto::types::SyscallBuf;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// AT_FDCWD = -100
const AT_FDCWD: u64 = (-100i64) as u64;
// AT_SYMLINK_NOFOLLOW flag for newfstatat
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

// Syscall numbers (x86-64)
const SYS_CLOSE: u64 = 3;
const SYS_PREAD64: u64 = 17;
const SYS_PWRITE64: u64 = 18;
const SYS_GETDENTS64: u64 = 217;
const SYS_OPENAT: u64 = 257;
const SYS_NEWFSTATAT: u64 = 262;
const SYS_READLINKAT: u64 = 267;
const SYS_FCHMODAT: u64 = 268;
const SYS_FCHOWNAT: u64 = 260;
const SYS_UNLINKAT: u64 = 263;
const SYS_RENAMEAT: u64 = 264;
const SYS_MKDIRAT: u64 = 258;
const SYS_SYMLINKAT: u64 = 266;
const SYS_LINKAT: u64 = 265;
const SYS_FTRUNCATE: u64 = 77;
const SYS_UTIMENSAT: u64 = 280;

const TTL: Duration = Duration::from_secs(1);

pub struct RscFs {
    pub client: Arc<Client>,
    pub inodes: Arc<Mutex<InodeTable>>,
    pub fhs: Arc<Mutex<FhTable>>,
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
        let (buf, _st) = self.stat_path(path, follow)?;
        Ok(stat_bytes_to_attr(ino, &buf))
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

        match self.stat_path(&path, true) {
            Ok((buf, _)) => {
                let ino = self.inodes.lock().unwrap().get_or_create(&path);
                let attr = stat_bytes_to_attr(ino, &buf);
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

        // Strip O_CREAT etc. that don't make sense for an existing file open.
        let open_flags = flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC);

        match self.remote_open(&path, open_flags, 0) {
            Ok(rfd) => {
                let fh = self.fhs.lock().unwrap().alloc(rfd);
                reply.opened(fh, 0);
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
        if let Some(rfd) = self.fhs.lock().unwrap().release(fh) {
            self.remote_close(rfd);
        }
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

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
        _ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
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

            // Get or create inode for this entry name.
            // We don't have the parent path here easily, but we can use the
            // entry name with an inode from the kernel's d_ino.
            let full_path = {
                // We need parent path — retrieve from the fh's inode.
                // Since we don't track fh→ino, use the kernel ino directly
                // and register it in our table keyed by the d_ino number.
                // This is a best-effort mapping.
                entry.ino
            };
            let _ = full_path; // used below via entry.ino

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
        if let Some(rfd) = self.fhs.lock().unwrap().release(fh) {
            self.remote_close(rfd);
        }
        reply.ok();
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };

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
