use std::collections::HashMap;
use anyhow::{bail, Result};

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
}

#[derive(Debug, Clone)]
pub struct SyscallMeta {
    pub name: String,
    pub params: Vec<ParamMeta>,
    /// Index of the buffer argument (-1 if none)
    pub buf_idx: i32,
}

// ---------------------------------------------------------------------------
// Hardcoded metadata for the 4 forwarded syscalls
// ---------------------------------------------------------------------------

pub fn hardcoded_syscall_metadata() -> Vec<SyscallMeta> {
    vec![
        SyscallMeta {
            name: "kill".to_string(),
            params: vec![
                ParamMeta { ctype: CType::Int, dir: ParamDir::In },  // pid
                ParamMeta { ctype: CType::Int, dir: ParamDir::In },  // sig
            ],
            buf_idx: -1,
        },
        SyscallMeta {
            name: "execve".to_string(),
            params: vec![
                ParamMeta { ctype: CType::CharPtr, dir: ParamDir::In },  // filename (buf_idx=0)
                ParamMeta { ctype: CType::VoidPtr, dir: ParamDir::In }, // argv
                ParamMeta { ctype: CType::VoidPtr, dir: ParamDir::In }, // envp
            ],
            buf_idx: 0,
        },
        SyscallMeta {
            name: "open".to_string(),
            params: vec![
                ParamMeta { ctype: CType::CharPtr, dir: ParamDir::In },  // filename (buf_idx=0)
                ParamMeta { ctype: CType::Int, dir: ParamDir::In },  // flags
                ParamMeta { ctype: CType::UnsignedInt, dir: ParamDir::In }, // mode
            ],
            buf_idx: 0,
        },
        SyscallMeta {
            name: "openat".to_string(),
            params: vec![
                ParamMeta { ctype: CType::Int, dir: ParamDir::In },  // dfd
                ParamMeta { ctype: CType::CharPtr, dir: ParamDir::In },  // filename (buf_idx=1)
                ParamMeta { ctype: CType::Int, dir: ParamDir::In },  // flags
                ParamMeta { ctype: CType::UnsignedInt, dir: ParamDir::In }, // mode
            ],
            buf_idx: 1,
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

    // 5. extern SyscallSignature declarations
    for name in forwarded {
        out.push_str(&format!(
            "extern SyscallSignature signature__x64_sys_{};\n",
            name
        ));
    }
    out.push('\n');

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
    meta_map: &HashMap<String, SyscallMeta>,
) -> Result<String> {
    let mut out = String::new();

    out.push_str("#include \"types.h\"\n\n");

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
            let size_expr = param.ctype.size_expr();
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
    }

    #[test]
    fn test_generate_source_contains_signatures() {
        let meta = metadata_map();
        let forwarded = vec!["kill".to_string()];

        let src = generate_source(&forwarded, &meta).expect("codegen failed");

        assert!(
            src.contains("signature__x64_sys_kill"),
            "Missing signature definition"
        );
        assert!(src.contains("n_params = 2"), "kill should have 2 params");
    }
}
