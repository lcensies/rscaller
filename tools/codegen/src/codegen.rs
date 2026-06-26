use std::collections::HashMap;
use anyhow::Result;

// ---------------------------------------------------------------------------
// Metadata types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum CType {
    Int,
    UnsignedInt,
    Long,
    UnsignedLong,
    CharPtr,   // char* (pointer)
    VoidPtr,   // void** or void* (pointer)
}

impl CType {
    /// C declaration string (e.g. "char *")
    pub fn c_decl(&self) -> &'static str {
        match self {
            CType::Int         => "int",
            CType::UnsignedInt => "unsigned int",
            CType::Long        => "long",
            CType::UnsignedLong => "unsigned long",
            CType::CharPtr     => "char *",
            CType::VoidPtr     => "void *",
        }
    }

    /// Union member name (e.g. "int_type")
    pub fn union_member(&self) -> &'static str {
        match self {
            CType::Int         => "int_type",
            CType::UnsignedInt => "uint_type",
            CType::Long        => "long_type",
            CType::UnsignedLong => "ulong_type",
            CType::CharPtr     => "char_ptr_type",
            CType::VoidPtr     => "void_ptr_type",
        }
    }

    /// ParamType enum value name (e.g. "INT_TYPE")
    pub fn enum_variant(&self) -> &'static str {
        match self {
            CType::Int         => "INT_TYPE",
            CType::UnsignedInt => "UINT_TYPE",
            CType::Long        => "LONG_TYPE",
            CType::UnsignedLong => "ULONG_TYPE",
            CType::CharPtr     => "CHAR_PTR_TYPE",
            CType::VoidPtr     => "VOID_PTR_TYPE",
        }
    }

    pub fn is_ptr(&self) -> bool {
        matches!(self, CType::CharPtr | CType::VoidPtr)
    }

    /// Size expression used in SyscallSignature params_meta
    pub fn size_expr(&self) -> &'static str {
        match self {
            CType::CharPtr => "4096",
            CType::VoidPtr => "sizeof(void *)",
            CType::Int     => "sizeof(int)",
            CType::UnsignedInt => "sizeof(unsigned int)",
            CType::Long    => "sizeof(long)",
            CType::UnsignedLong => "sizeof(unsigned long)",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ParamDir { In, Out, InOut }

#[derive(Debug, Clone)]
pub struct ParamMeta {
    pub ctype: CType,
    pub dir: ParamDir,
    /// If Some(i), buffer size is determined at runtime from params[i].
    pub size_from_arg: Option<usize>,
    /// If Some(n), use this fixed byte count for the buffer (overrides ctype default).
    pub static_buf_bytes: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct SyscallMeta {
    pub name: String,
    pub params: Vec<ParamMeta>,
    /// Index of the buffer argument (-1 if none)
    pub buf_idx: i32,
}

// ---------------------------------------------------------------------------
// Hardcoded metadata — used as a fallback when tracefs is unavailable.
// Prefer tracefs introspection; this is kept for tests and offline builds.
// ---------------------------------------------------------------------------

/// Convenience constructor for non-pointer params (no size hints).
fn pm(ctype: CType, dir: ParamDir) -> ParamMeta {
    ParamMeta { ctype, dir, size_from_arg: None, static_buf_bytes: None }
}

/// Convenience constructor for pointer params with a runtime size source.
fn pm_dynbuf(ctype: CType, dir: ParamDir, size_from_arg: usize) -> ParamMeta {
    ParamMeta { ctype, dir, size_from_arg: Some(size_from_arg), static_buf_bytes: None }
}

/// Convenience constructor for pointer params with a static byte size.
fn pm_staticbuf(ctype: CType, dir: ParamDir, bytes: usize) -> ParamMeta {
    ParamMeta { ctype, dir, size_from_arg: None, static_buf_bytes: Some(bytes) }
}

pub fn hardcoded_syscall_metadata() -> Vec<SyscallMeta> {
    vec![
        SyscallMeta {
            name: "read".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                              // fd
                pm_dynbuf(CType::CharPtr, ParamDir::Out, 2),                // buf (size = arg2)
                pm(CType::UnsignedLong, ParamDir::In),                     // count
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "write".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                              // fd
                pm_dynbuf(CType::CharPtr, ParamDir::In, 2),                 // buf (size = arg2)
                pm(CType::UnsignedLong, ParamDir::In),                     // count
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "close".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                              // fd
            ],
            buf_idx: -1,
        },
        SyscallMeta {
            name: "kill".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),  // pid
                pm(CType::Int, ParamDir::In),  // sig
            ],
            buf_idx: -1,
        },
        SyscallMeta {
            name: "execve".to_string(),
            params: vec![
                pm_staticbuf(CType::CharPtr, ParamDir::In, 4096),   // filename
                pm(CType::VoidPtr, ParamDir::In),                   // argv
                pm(CType::VoidPtr, ParamDir::In),                   // envp
            ],
            buf_idx: 0,
        },
        SyscallMeta {
            name: "open".to_string(),
            params: vec![
                pm_staticbuf(CType::CharPtr, ParamDir::In, 4096),  // filename
                pm(CType::Int, ParamDir::In),                      // flags
                pm(CType::UnsignedInt, ParamDir::In),              // mode
            ],
            buf_idx: 0,
        },
        SyscallMeta {
            name: "openat".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                       // dfd
                pm_staticbuf(CType::CharPtr, ParamDir::In, 4096),   // filename
                pm(CType::Int, ParamDir::In),                       // flags
                pm(CType::UnsignedInt, ParamDir::In),               // mode
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "stat".to_string(),
            params: vec![
                pm_staticbuf(CType::CharPtr, ParamDir::In, 4096),   // pathname
                pm_staticbuf(CType::VoidPtr, ParamDir::Out, 144),   // statbuf
            ],
            buf_idx: 0,
        },
        SyscallMeta {
            name: "fstat".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                       // fd
                pm_staticbuf(CType::VoidPtr, ParamDir::Out, 144),   // statbuf
            ],
            buf_idx: -1,
        },
        SyscallMeta {
            name: "lstat".to_string(),
            params: vec![
                pm_staticbuf(CType::CharPtr, ParamDir::In, 4096),   // pathname
                pm_staticbuf(CType::VoidPtr, ParamDir::Out, 144),   // statbuf
            ],
            buf_idx: 0,
        },
        SyscallMeta {
            name: "getdents64".to_string(),
            params: vec![
                pm(CType::UnsignedInt, ParamDir::In),               // fd
                pm_dynbuf(CType::VoidPtr, ParamDir::Out, 2),         // dirp (size = arg2)
                pm(CType::UnsignedInt, ParamDir::In),               // count
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "newfstatat".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                       // dfd
                pm_staticbuf(CType::CharPtr, ParamDir::In, 4096),   // filename
                pm_staticbuf(CType::VoidPtr, ParamDir::Out, 144),   // statbuf
                pm(CType::Int, ParamDir::In),                       // flag
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "chdir".to_string(),
            params: vec![
                pm_staticbuf(CType::CharPtr, ParamDir::In, 4096),   // path
            ],
            buf_idx: 0,
        },
        SyscallMeta {
            name: "fchdir".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),  // fd
            ],
            buf_idx: -1,
        },
        SyscallMeta {
            name: "socket".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),  // family
                pm(CType::Int, ParamDir::In),  // type
                pm(CType::Int, ParamDir::In),  // protocol
            ],
            buf_idx: -1,
        },
        SyscallMeta {
            name: "connect".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                        // fd
                pm_staticbuf(CType::VoidPtr, ParamDir::In, 128),     // uservaddr (sockaddr)
                pm(CType::UnsignedInt, ParamDir::In),                // addrlen
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "bind".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                        // fd
                pm_staticbuf(CType::VoidPtr, ParamDir::In, 128),     // umyaddr (sockaddr)
                pm(CType::UnsignedInt, ParamDir::In),                // addrlen
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "accept4".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                        // fd
                pm_staticbuf(CType::VoidPtr, ParamDir::Out, 128),    // upeer_sockaddr
                pm_staticbuf(CType::VoidPtr, ParamDir::InOut, 4),    // upeer_addrlen (socklen_t*)
                pm(CType::Int, ParamDir::In),                        // flags
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "sendto".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                        // fd
                pm_dynbuf(CType::VoidPtr, ParamDir::In, 2),          // buff (size = arg2)
                pm(CType::UnsignedLong, ParamDir::In),               // len
                pm(CType::UnsignedInt, ParamDir::In),                // flags
                pm_staticbuf(CType::VoidPtr, ParamDir::In, 128),     // addr (sockaddr, optional)
                pm(CType::UnsignedInt, ParamDir::In),                // addr_len
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "recvfrom".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                        // fd
                pm_dynbuf(CType::VoidPtr, ParamDir::Out, 2),         // ubuf (size = arg2)
                pm(CType::UnsignedLong, ParamDir::In),               // size
                pm(CType::UnsignedInt, ParamDir::In),                // flags
                pm_staticbuf(CType::VoidPtr, ParamDir::Out, 128),    // addr (sockaddr, optional)
                pm_staticbuf(CType::VoidPtr, ParamDir::InOut, 4),    // addr_len (socklen_t*)
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "sendmsg".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                        // fd
                pm_staticbuf(CType::VoidPtr, ParamDir::In, 56),      // msg (struct msghdr)
                pm(CType::UnsignedInt, ParamDir::In),                // flags
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "recvmsg".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                        // fd
                pm_staticbuf(CType::VoidPtr, ParamDir::InOut, 56),   // msg (struct msghdr)
                pm(CType::UnsignedInt, ParamDir::In),                // flags
            ],
            buf_idx: 1,
        },
        SyscallMeta {
            name: "getsockopt".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                        // fd
                pm(CType::Int, ParamDir::In),                        // level
                pm(CType::Int, ParamDir::In),                        // optname
                pm_staticbuf(CType::VoidPtr, ParamDir::Out, 128),    // optval
                pm_staticbuf(CType::VoidPtr, ParamDir::InOut, 4),    // optlen (socklen_t*)
            ],
            buf_idx: 3,
        },
        SyscallMeta {
            name: "setsockopt".to_string(),
            params: vec![
                pm(CType::Int, ParamDir::In),                        // fd
                pm(CType::Int, ParamDir::In),                        // level
                pm(CType::Int, ParamDir::In),                        // optname
                pm_staticbuf(CType::VoidPtr, ParamDir::In, 128),     // optval
                pm(CType::UnsignedInt, ParamDir::In),                // optlen
            ],
            buf_idx: 3,
        },
    ]
}

/// Metadata map keyed by syscall name
pub fn metadata_map() -> HashMap<String, SyscallMeta> {
    hardcoded_syscall_metadata()
        .into_iter()
        .map(|m| (m.name.clone(), m))
        .collect()
}

// ---------------------------------------------------------------------------
// All union members in a fixed canonical order
// ---------------------------------------------------------------------------

fn all_union_members() -> Vec<(&'static str, &'static str)> {
    // (c_type_decl, member_name) — order matches task spec
    vec![
        ("long",         "long_type"),
        ("unsigned long","ulong_type"),
        ("int",          "int_type"),
        ("unsigned int", "uint_type"),
        ("char *",       "char_ptr_type"),
        ("void *",       "void_ptr_type"),
    ]
}

fn all_enum_variants() -> Vec<(&'static str, u32)> {
    vec![
        ("LONG_TYPE",     0),
        ("ULONG_TYPE",    1),
        ("INT_TYPE",      2),
        ("UINT_TYPE",     3),
        ("CHAR_PTR_TYPE", 4),
        ("VOID_PTR_TYPE", 5),
    ]
}

// ---------------------------------------------------------------------------
// Header generator
// ---------------------------------------------------------------------------

pub fn generate_header(
    forwarded: &[String],
    name_to_num: &HashMap<String, u32>,
    meta_map: &HashMap<String, SyscallMeta>,
) -> Result<String> {
    let mut out = String::new();

    // 1. Include guard + auto-generated comment
    out.push_str("#ifndef HANDLER_WRAPPERS_H\n");
    out.push_str("#define HANDLER_WRAPPERS_H\n\n");
    out.push_str("/* AUTO-GENERATED FILE — do not edit manually */\n");
    out.push_str("/* Generated by tools/codegen */\n\n");
    out.push_str("#include <linux/types.h>\n\n");

    // 2. SyscallParam union
    out.push_str("typedef union {\n");
    for (ctype, member) in all_union_members() {
        out.push_str(&format!("\t{} {};\n", ctype, member));
    }
    out.push_str("} SyscallParam;\n\n");

    // 3. ParamType enum
    out.push_str("enum ParamType {\n");
    for (variant, val) in all_enum_variants() {
        out.push_str(&format!("\t{} = {},\n", variant, val));
    }
    out.push_str("};\n\n");

    // 4. fetch_param_variant function
    out.push_str("static inline void fetch_param_variant(SyscallParam *src, int param_type,\n");
    out.push_str("                                        void **param, size_t *param_size) {\n");
    out.push_str("\tswitch (param_type) {\n");
    for (variant, _) in all_enum_variants() {
        // derive member name from variant: LONG_TYPE -> long_type etc.
        let member = variant_to_member(variant);
        out.push_str(&format!(
            "\t\tcase {}: *param = &src->{}; *param_size = sizeof(src->{}); return;\n",
            variant, member, member
        ));
    }
    out.push_str("\t}\n");
    out.push_str("\t*param = (void*)&src->char_ptr_type; param_type = sizeof(src->char_ptr_type);\n");
    out.push_str("}\n\n");

    // 5. extern SyscallSignature declarations + dispatch function declaration
    for name in forwarded {
        out.push_str(&format!(
            "extern SyscallSignature signature__x64_sys_{};\n",
            name
        ));
    }
    out.push('\n');
    out.push_str("const SyscallSignature *rscaller_find_signature(unsigned int nr);\n");
    out.push_str("void rscaller_patch_ptr_params(int nr, const unsigned long *params, int slot_idx);\n\n");

    // 6. Handler wrapper functions
    for name in forwarded {
        let syscall_num = name_to_num
            .get(name.as_str())
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Syscall '{}' not found in .tbl", name))?;

        let meta = meta_map
            .get(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("No metadata for syscall '{}'", name))?;

        // buf_idx and syscall_num are kept for future use but the dead wrapper
        // functions (handle_syscall_N) are intentionally omitted — they were
        // __unused__ and referenced an undefined handler_entry_wrapper() symbol
        // which caused -Wimplicit-function-declaration errors in the kernel build.
        let _ = (syscall_num, meta.buf_idx);
    }

    out.push_str("#endif /* HANDLER_WRAPPERS_H */\n");
    Ok(out)
}

fn variant_to_member(variant: &str) -> &'static str {
    match variant {
        "LONG_TYPE"      => "long_type",
        "ULONG_TYPE"     => "ulong_type",
        "INT_TYPE"       => "int_type",
        "UINT_TYPE"      => "uint_type",
        "CHAR_PTR_TYPE"  => "char_ptr_type",
        "VOID_PTR_TYPE"  => "void_ptr_type",
        _                => "long_type",
    }
}

// ---------------------------------------------------------------------------
// Source file generator
// ---------------------------------------------------------------------------

pub fn generate_source(
    forwarded: &[String],
    name_to_num: &HashMap<String, u32>,
    meta_map: &HashMap<String, SyscallMeta>,
) -> Result<String> {
    let mut out = String::new();

    out.push_str("#include \"types.h\"\n");
    out.push_str("#include \"buffer.h\"\n");
    out.push_str("#include \"handler_wrappers.h\"\n");
    out.push_str("#ifndef __USERSPACE__\n");
    out.push_str("#include <linux/kernel.h>\n");
    out.push_str("#include <linux/string.h>\n");
    out.push_str("#include <linux/uaccess.h>\n");
    out.push_str("#endif\n\n");

    for name in forwarded {
        let meta = meta_map
            .get(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("No metadata for syscall '{}'", name))?;

        out.push_str(&format!(
            "SyscallSignature signature__x64_sys_{} = {{\n",
            name
        ));
        out.push_str(&format!("\t.n_params = {},\n", meta.params.len()));
        out.push_str("\t.params_meta = {\n");

        for param in &meta.params {
            let enum_val = param.ctype.enum_variant();
            // Prefer static_buf_bytes when present, else fall back to ctype's
            // default size expression.
            let size_expr = if let Some(n) = param.static_buf_bytes {
                format!("{}", n)
            } else {
                param.ctype.size_expr().to_string()
            };
            let is_ptr = if param.ctype.is_ptr() { "true" } else { "false" };
            let dir_val = match param.dir {
                ParamDir::In    => "PARAM_DIR_IN",
                ParamDir::Out   => "PARAM_DIR_OUT",
                ParamDir::InOut => "PARAM_DIR_INOUT",
            };
            out.push_str(&format!(
                "\t\t{{ {}, {}, {}, {} }},\n",
                enum_val, size_expr, is_ptr, dir_val
            ));
        }

        out.push_str("\t},\n");
        out.push_str("};\n\n");
    }

    // Dispatch table: maps syscall number → signature pointer.
    // Used by rscaller_find_signature() in main.c instead of a hand-written switch.
    out.push_str("static const struct { unsigned int nr; const SyscallSignature *sig; }\n");
    out.push_str("dispatch_table[] = {\n");
    for name in forwarded {
        let nr = name_to_num
            .get(name.as_str())
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Syscall '{}' not found in .tbl", name))?;
        out.push_str(&format!("\t{{ {}, &signature__x64_sys_{} }},\n", nr, name));
    }
    out.push_str("};\n\n");

    out.push_str("const SyscallSignature *rscaller_find_signature(unsigned int nr) {\n");
    out.push_str("\tsize_t i;\n");
    out.push_str("\tfor (i = 0; i < sizeof(dispatch_table)/sizeof(dispatch_table[0]); i++)\n");
    out.push_str("\t\tif (dispatch_table[i].nr == nr)\n");
    out.push_str("\t\t\treturn dispatch_table[i].sig;\n");
    out.push_str("\treturn NULL;\n");
    out.push_str("}\n\n");

    // rscaller_patch_ptr_params: populate per-slot ParamBuf entries for
    // syscalls with pointer args, based on the generated metadata.
    out.push_str("/* AUTO-GENERATED: patch pointer-param ParamBufs before save_syscall(). */\n");
    out.push_str("void rscaller_patch_ptr_params(int nr, const unsigned long *params, int slot_idx)\n");
    out.push_str("{\n");
    out.push_str("#ifndef __USERSPACE__\n");
    out.push_str("\tParamBuf *pb;\n");
    out.push_str("\tsize_t sz;\n");
    out.push_str("\t(void)pb; (void)sz;\n");
    out.push_str("\tswitch (nr) {\n");

    for name in forwarded {
        let nr = name_to_num
            .get(name.as_str())
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Syscall '{}' not found in .tbl", name))?;
        let meta = meta_map
            .get(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("No metadata for syscall '{}'", name))?;

        // Skip syscalls with no pointer params — nothing to patch.
        let has_ptr = meta.params.iter().any(|p| p.ctype.is_ptr());
        if !has_ptr {
            continue;
        }

        out.push_str(&format!("\tcase {}: /* {} */\n", nr, name));
        for (i, param) in meta.params.iter().enumerate() {
            if !param.ctype.is_ptr() {
                continue;
            }
            let dir_str = match param.dir {
                ParamDir::In => "PARAM_DIR_IN",
                ParamDir::Out => "PARAM_DIR_OUT",
                ParamDir::InOut => "PARAM_DIR_INOUT",
            };
            let is_in = matches!(param.dir, ParamDir::In | ParamDir::InOut);
            let is_charptr = matches!(param.ctype, CType::CharPtr);

            match (param.size_from_arg, param.static_buf_bytes) {
                (Some(j), _) => {
                    // Dynamic size from another arg.
                    out.push_str(&format!(
                        "\t\tsz = min((unsigned long)params[{}], (unsigned long)MAX_PARAM_BUF);\n",
                        j
                    ));
                    out.push_str(&format!(
                        "\t\tpb = &global_ctl_buffer->bufs[slot_idx].params[{}];\n",
                        i
                    ));
                    out.push_str(&format!(
                        "\t\tpb->user_ptr = params[{}]; pb->size = (uint32_t)sz; pb->direction = {};\n",
                        i, dir_str
                    ));
                    if is_in {
                        out.push_str(&format!(
                            "\t\tif (sz && params[{}]) copy_from_user(pb->data, (const void __user *)params[{}], sz);\n",
                            i, i
                        ));
                    } else {
                        out.push_str("\t\tmemset(pb->data, 0, sz);\n");
                    }
                }
                (None, Some(bytes)) => {
                    out.push_str(&format!(
                        "\t\tpb = &global_ctl_buffer->bufs[slot_idx].params[{}];\n",
                        i
                    ));
                    if is_in && is_charptr {
                        // NUL-terminated string copy.
                        out.push_str(&format!(
                            "\t\tpb->user_ptr = params[{}]; pb->size = (uint32_t){}; pb->direction = {};\n",
                            i, bytes, dir_str
                        ));
                        out.push_str(&format!(
                            "\t\tif (params[{}]) strncpy_from_user((char *)pb->data, (const char __user *)params[{}], {});\n",
                            i, i, bytes
                        ));
                    } else if is_in {
                        out.push_str(&format!(
                            "\t\tpb->user_ptr = params[{}]; pb->size = (uint32_t){}; pb->direction = {};\n",
                            i, bytes, dir_str
                        ));
                        out.push_str(&format!(
                            "\t\tif (params[{}]) copy_from_user(pb->data, (const void __user *)params[{}], {});\n",
                            i, i, bytes
                        ));
                    } else {
                        out.push_str(&format!(
                            "\t\tpb->user_ptr = params[{}]; pb->size = (uint32_t){}; pb->direction = {};\n",
                            i, bytes, dir_str
                        ));
                        out.push_str(&format!("\t\tmemset(pb->data, 0, {});\n", bytes));
                    }
                }
                (None, None) => {
                    // No size hint — best-effort default: treat as IN string (4096).
                    out.push_str(&format!(
                        "\t\tpb = &global_ctl_buffer->bufs[slot_idx].params[{}];\n",
                        i
                    ));
                    out.push_str(&format!(
                        "\t\tpb->user_ptr = params[{}]; pb->size = (uint32_t)MAX_PARAM_BUF; pb->direction = {};\n",
                        i, dir_str
                    ));
                    if is_in && is_charptr {
                        out.push_str(&format!(
                            "\t\tif (params[{}]) strncpy_from_user((char *)pb->data, (const char __user *)params[{}], MAX_PARAM_BUF);\n",
                            i, i
                        ));
                    }
                }
            }
        }
        out.push_str("\t\tbreak;\n");
    }

    out.push_str("\tdefault:\n");
    out.push_str("\t\tbreak;\n");
    out.push_str("\t}\n");
    out.push_str("#else\n");
    out.push_str("\t(void)nr; (void)params; (void)slot_idx;\n");
    out.push_str("#endif\n");
    out.push_str("}\n");

    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall_table::{build_name_map, parse_tbl};
    use std::path::PathBuf;

    fn tbl_name_map() -> HashMap<String, u32> {
        let path = PathBuf::from("../../files/syscall_64_6_13.tbl");
        let entries = parse_tbl(&path).expect("parse failed");
        build_name_map(&entries)
    }

    #[test]
    fn test_generate_header_contains_union() {
        let name_map = tbl_name_map();
        let meta = metadata_map();
        let forwarded = vec!["kill".to_string(), "execve".to_string()];

        let header = generate_header(&forwarded, &name_map, &meta).expect("codegen failed");

        assert!(header.contains("SyscallParam"), "Missing SyscallParam union");
        assert!(header.contains("fetch_param_variant"), "Missing fetch_param_variant");
        assert!(
            header.contains("signature__x64_sys_kill"),
            "Missing kill extern"
        );
        assert!(
            header.contains("signature__x64_sys_execve"),
            "Missing execve extern"
        );
        assert!(
            header.contains("rscaller_patch_ptr_params"),
            "Missing rscaller_patch_ptr_params decl"
        );
    }

    #[test]
    fn test_generate_source_contains_signatures() {
        let name_map = tbl_name_map();
        let meta = metadata_map();
        let forwarded = vec!["kill".to_string(), "read".to_string()];

        let src = generate_source(&forwarded, &name_map, &meta).expect("codegen failed");

        assert!(
            src.contains("signature__x64_sys_kill"),
            "Missing signature definition"
        );
        assert!(src.contains("n_params = 2"), "kill should have 2 params");
        assert!(
            src.contains("rscaller_patch_ptr_params"),
            "Missing rscaller_patch_ptr_params definition"
        );
        // read's buf is OUT and its size comes from params[2]
        assert!(src.contains("params[2]"), "read patch should reference params[2]");
    }
}
