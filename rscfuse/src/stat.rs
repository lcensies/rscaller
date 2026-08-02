use fuser::{FileAttr, FileType};
use std::time::{Duration, UNIX_EPOCH};

/// Convert raw `struct stat` bytes (144 bytes on x86-64) to fuser::FileAttr.
///
/// # Safety
/// `buf` must be at least `size_of::<libc::stat>()` bytes and contain a
/// valid kernel-populated stat structure.
pub fn stat_bytes_to_attr(ino: u64, buf: &[u8]) -> FileAttr {
    assert!(
        buf.len() >= std::mem::size_of::<libc::stat>(),
        "stat buf too small: {} < {}",
        buf.len(),
        std::mem::size_of::<libc::stat>()
    );

    // SAFETY: buf is aligned-enough for a read via raw pointer cast; we copy
    // fields out immediately rather than holding the reference.
    let st: libc::stat = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const libc::stat) };

    // Block devices must be reported as regular files in the FUSE view.
    // If the kernel sees a real block-device rdev it will bypass FUSE and
    // attempt I/O against the local device with that major:minor, which
    // returns zero bytes for a remote beacon device.
    let kind = match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => FileType::RegularFile,
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFBLK => FileType::RegularFile,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile, // fallback
    };

    let perm = (st.st_mode & 0o7777) as u16;

    let atime = UNIX_EPOCH + Duration::new(st.st_atime as u64, st.st_atime_nsec as u32);
    let mtime = UNIX_EPOCH + Duration::new(st.st_mtime as u64, st.st_mtime_nsec as u32);
    let ctime = UNIX_EPOCH + Duration::new(st.st_ctime as u64, st.st_ctime_nsec as u32);

    // /proc and other virtual files report st_size=0.  The kernel uses the
    // cached inode size to gate reads: if size=0, read() returns 0 without
    // ever calling our read handler, even with FOPEN_DIRECT_IO.  Return a
    // large sentinel so the kernel issues the read; the actual EOF is signalled
    // when our handler returns 0 bytes.
    let size = if kind == FileType::RegularFile && st.st_size == 0 {
        1 << 22 // 4 MiB — enough for any /proc file
    } else {
        st.st_size as u64
    };

    FileAttr {
        ino,
        size,
        blocks: st.st_blocks as u64,
        atime,
        mtime,
        ctime,
        crtime: ctime, // Linux has no birth time in stat
        kind,
        perm,
        nlink: st.st_nlink as u32,
        uid: st.st_uid,
        gid: st.st_gid,
        // Block devices are exposed as regular files; zero rdev so the kernel
        // does not attempt to use a local device with the same major:minor.
        rdev: if (st.st_mode & libc::S_IFMT) == libc::S_IFBLK {
            0
        } else {
            st.st_rdev as u32
        },
        blksize: st.st_blksize as u32,
        flags: 0,
    }
}
