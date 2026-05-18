//! Parser for kernel tracefs format files (sys_enter_*/format).
//!
//! Extracts syscall parameter names and types directly from
//! /sys/kernel/tracing/events/syscalls/sys_enter_{name}/format
//! and infers ParamMeta (direction, static/dynamic buffer size).

use crate::codegen::{CType, ParamDir, ParamMeta};

#[derive(Debug, Clone)]
pub struct FormatField {
    pub name: String,
    pub type_str: String, // e.g. "const char *", "int", "umode_t"
    pub size: usize,      // field size in bytes
}

/// Parse the text content of a sys_enter_*/format file.
/// Returns only the syscall parameter fields (skipping common_* and __syscall_nr).
pub fn parse_format(content: &str) -> Vec<FormatField> {
    let mut fields = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with("field:") {
            continue;
        }
        // Format: field:TYPE NAME;\toffset:N;\tsize:N;\tsigned:N;
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.is_empty() {
            continue;
        }
        let field_decl = parts[0]
            .trim_end_matches(';')
            .trim_start_matches("field:")
            .trim();
        // Split on last space to get (type, name); handle "type [arr]" forms
        let (type_str, name) = if let Some(pos) = field_decl.rfind(' ') {
            let raw_name = field_decl[pos + 1..].trim();
            // Strip array suffix from name, e.g. "name[64]"
            let name = raw_name.split('[').next().unwrap_or(raw_name).trim();
            (field_decl[..pos].trim(), name)
        } else {
            continue;
        };
        if name.starts_with("common_") || name == "__syscall_nr" {
            continue;
        }
        let size = parts
            .iter()
            .find(|p| p.trim().starts_with("size:"))
            .and_then(|p| {
                p.trim()
                    .trim_start_matches("size:")
                    .trim_end_matches(';')
                    .parse::<usize>()
                    .ok()
            })
            .unwrap_or(8);
        fields.push(FormatField {
            name: name.to_string(),
            type_str: type_str.to_string(),
            size,
        });
    }
    fields
}

/// Map a C type string to CType. Defaults to Long when ambiguous.
pub fn map_ctype(type_str: &str) -> CType {
    let t = type_str.trim();
    // Pointer types
    if t.contains('*') {
        if t.contains("char") {
            return CType::CharPtr;
        }
        return CType::VoidPtr;
    }
    match t {
        "int" => CType::Int,
        "long" => CType::Long,
        "unsigned int" | "umode_t" | "unsigned" | "u32" | "__u32" => CType::UnsignedInt,
        "unsigned long" | "size_t" | "off_t" | "loff_t" | "u64" | "__u64" => CType::UnsignedLong,
        _ if t.starts_with("unsigned") => CType::UnsignedLong,
        _ => CType::Long,
    }
}

/// Whether a parameter name looks like a size/count parameter.
fn is_size_name(name: &str) -> bool {
    matches!(
        name,
        "count" | "len" | "length" | "size" | "nbytes" | "bufsiz" | "nr_bytes"
    )
}

/// Infer parameter direction for a pointer param based on syscall + param name.
fn infer_ptr_direction(syscall_name: &str, param_name: &str, next_is_size: bool) -> ParamDir {
    // Path/filename params are always IN
    if matches!(
        param_name,
        "filename" | "pathname" | "path" | "name" | "oldname" | "newname" | "from" | "to"
    ) {
        return ParamDir::In;
    }
    // write-like syscalls: buf feeds data IN
    if matches!(
        syscall_name,
        "write" | "pwrite64" | "send" | "sendto" | "writev" | "pwritev"
    ) {
        return ParamDir::In;
    }
    // read-like syscalls: buf receives data OUT
    if next_is_size
        && matches!(
            syscall_name,
            "read" | "pread64" | "recv" | "recvfrom" | "getdents64" | "getdents" | "readv" | "preadv"
        )
    {
        return ParamDir::Out;
    }
    // stat-like OUT structs (no following size)
    if matches!(
        param_name,
        "statbuf" | "stat" | "buf" | "info" | "dirp" | "dirent"
    ) && !next_is_size
    {
        return ParamDir::Out;
    }
    ParamDir::In
}

/// A ParamMeta enriched with size hints derived from tracefs introspection.
#[derive(Debug, Clone)]
pub struct InferredParam {
    pub meta: ParamMeta,
    /// If Some(i), the actual buffer size comes from params[i] at runtime.
    pub size_from_arg: Option<usize>,
    /// If Some(n), use this fixed byte count for the buffer.
    pub static_buf_bytes: Option<usize>,
}

/// Convert format fields to inferred parameter metadata for one syscall.
pub fn infer_params(syscall_name: &str, fields: &[FormatField]) -> Vec<InferredParam> {
    let n = fields.len();
    let mut result = Vec::with_capacity(n);
    for i in 0..n {
        let f = &fields[i];
        let ctype = map_ctype(&f.type_str);
        let is_ptr = f.type_str.contains('*');
        if !is_ptr {
            result.push(InferredParam {
                meta: ParamMeta {
                    ctype,
                    dir: ParamDir::In,
                    size_from_arg: None,
                    static_buf_bytes: None,
                },
                size_from_arg: None,
                static_buf_bytes: None,
            });
            continue;
        }
        // Pointer param — figure out direction and size source.
        let next_is_size = (i + 1 < n) && is_size_name(&fields[i + 1].name);
        let dir = infer_ptr_direction(syscall_name, &f.name, next_is_size);
        let size_from_arg = if next_is_size { Some(i + 1) } else { None };

        // For struct-like OUT pointers without a size arg (statbuf etc.) use
        // 144 (sizeof(struct stat) on x86-64) as a conservative default.
        let static_buf_bytes = if size_from_arg.is_none() {
            if matches!(
                f.name.as_str(),
                "statbuf" | "stat" | "info" | "dirent"
            ) {
                Some(144)
            } else {
                Some(4096)
            }
        } else {
            None
        };

        result.push(InferredParam {
            meta: ParamMeta {
                ctype,
                dir,
                size_from_arg,
                static_buf_bytes,
            },
            size_from_arg,
            static_buf_bytes,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const READ_FORMAT: &str = "name: sys_enter_read
ID: 67
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;
\tfield:unsigned int fd;\toffset:16;\tsize:8;\tsigned:0;
\tfield:char * buf;\toffset:24;\tsize:8;\tsigned:0;
\tfield:size_t count;\toffset:32;\tsize:8;\tsigned:0;
";

    #[test]
    fn test_parse_format_skips_common_and_syscall_nr() {
        let fields = parse_format(READ_FORMAT);
        assert_eq!(fields.len(), 3, "expected 3 fields (fd, buf, count)");
        assert_eq!(fields[0].name, "fd");
        assert_eq!(fields[1].name, "buf");
        assert_eq!(fields[2].name, "count");
    }

    #[test]
    fn test_infer_read_buf_is_out() {
        let fields = parse_format(READ_FORMAT);
        let inferred = infer_params("read", &fields);
        assert_eq!(inferred.len(), 3);
        assert!(matches!(inferred[1].meta.dir, ParamDir::Out));
        assert_eq!(inferred[1].size_from_arg, Some(2));
    }
}
