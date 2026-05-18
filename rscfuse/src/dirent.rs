use std::ffi::CStr;

/// A single directory entry parsed from getdents64 output.
pub struct DirEntry {
    pub ino: u64,
    pub offset: i64,
    pub file_type: u8,
    pub name: String,
}

/// Parse raw getdents64 output buffer into a list of DirEntry.
///
/// linux_dirent64 on-wire layout (x86-64):
///   offset  0: d_ino    (u64)
///   offset  8: d_off    (i64)
///   offset 16: d_reclen (u16)
///   offset 18: d_type   (u8)
///   offset 19: d_name   (null-terminated string)
pub fn parse_dirent64(buf: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    let mut pos = 0usize;

    while pos < buf.len() {
        // Need at least the fixed header (20 bytes) before the name.
        if pos + 20 > buf.len() {
            break;
        }

        // Read d_reclen at offset+16 (u16 little-endian).
        let reclen = u16::from_le_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
        if reclen == 0 || pos + reclen > buf.len() {
            break;
        }

        let ino = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
        let offset = i64::from_le_bytes(buf[pos + 8..pos + 16].try_into().unwrap());
        let d_type = buf[pos + 18];

        // d_name starts at offset+19, null-terminated, within the record.
        let name_bytes = &buf[pos + 19..pos + reclen];
        let name = CStr::from_bytes_until_nul(name_bytes)
            .ok()
            .and_then(|c| c.to_str().ok())
            .unwrap_or("")
            .to_string();

        entries.push(DirEntry {
            ino,
            offset,
            file_type: d_type,
            name,
        });

        pos += reclen;
    }

    entries
}
