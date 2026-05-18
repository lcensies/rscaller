use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;

use codegen::codegen::{generate_header, generate_source, metadata_map, ParamMeta, SyscallMeta};
use codegen::syscall_table::{build_name_map, parse_tbl};
use codegen::tracefs::{infer_params, parse_format};
use codegen::version::{select_tbl_path, KernelVersion};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "codegen", about = "Generate kmod C files from syscall tables")]
struct Args {
    /// Directory containing the .tbl files (e.g. files/)
    #[arg(long, default_value = "files")]
    tbl_dir: PathBuf,

    /// File listing forwarded syscalls (one name per line)
    #[arg(long, default_value = "files/forwarded_syscalls")]
    forwarded: PathBuf,

    /// Output directory (kmod/ by default)
    #[arg(long, default_value = "kmod")]
    out: PathBuf,

    /// Override kernel version (e.g. "6.14.0"); detected via uname -r if omitted
    #[arg(long)]
    kernel_version: Option<String>,

    /// Tracefs format directory (typically /sys/kernel/tracing/events/syscalls
    /// or a snapshot of it fetched from a remote VM). If unset or files are
    /// missing the codegen falls back to hardcoded metadata.
    #[arg(long, default_value = "/sys/kernel/tracing/events/syscalls")]
    tracefs_dir: PathBuf,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let args = Args::parse();

    // 1. Detect / parse kernel version
    let kver = if let Some(ref v) = args.kernel_version {
        KernelVersion::parse(v).with_context(|| format!("Invalid kernel version: {}", v))?
    } else {
        KernelVersion::from_uname().context("Failed to detect kernel version via uname -r")?
    };

    eprintln!("Kernel version: {}.{}.{}", kver.major, kver.minor, kver.patch);

    // 2. Select and parse .tbl
    let tbl_path = select_tbl_path(&args.tbl_dir, &kver);
    eprintln!("Using tbl: {}", tbl_path.display());

    let tbl_entries = parse_tbl(&tbl_path)
        .with_context(|| format!("Failed to parse {}", tbl_path.display()))?;
    let name_map = build_name_map(&tbl_entries);

    // 3. Read forwarded syscalls
    let forwarded_content = fs::read_to_string(&args.forwarded)
        .with_context(|| format!("Failed to read {}", args.forwarded.display()))?;
    let forwarded: Vec<String> = forwarded_content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();

    eprintln!("Forwarded syscalls: {:?}", forwarded);

    // 4. Build metadata: prefer tracefs, fall back to hardcoded per-syscall.
    let meta = build_metadata(&forwarded, &args.tracefs_dir);

    // 5. Generate files
    let header = generate_header(&forwarded, &name_map, &meta)
        .context("Failed to generate handler_wrappers.h")?;
    let source = generate_source(&forwarded, &name_map, &meta)
        .context("Failed to generate syscalls.c")?;

    // 6. Write output
    fs::create_dir_all(&args.out)
        .with_context(|| format!("Failed to create output dir {}", args.out.display()))?;

    let header_path = args.out.join("handler_wrappers.h");
    let source_path = args.out.join("syscalls.c");

    fs::write(&header_path, &header)
        .with_context(|| format!("Failed to write {}", header_path.display()))?;
    fs::write(&source_path, &source)
        .with_context(|| format!("Failed to write {}", source_path.display()))?;

    eprintln!("Generated: {}", header_path.display());
    eprintln!("Generated: {}", source_path.display());

    Ok(())
}

/// Build the per-syscall metadata map. For each forwarded syscall try tracefs
/// first; on failure, fall back to hardcoded metadata. Syscalls missing from
/// both are skipped with a warning.
fn build_metadata(forwarded: &[String], tracefs_dir: &Path) -> HashMap<String, SyscallMeta> {
    let fallback = metadata_map();
    let mut out: HashMap<String, SyscallMeta> = HashMap::new();

    for name in forwarded {
        let format_path = tracefs_dir
            .join(format!("sys_enter_{}", name))
            .join("format");
        match fs::read_to_string(&format_path) {
            Ok(content) => {
                let fields = parse_format(&content);
                if fields.is_empty() {
                    eprintln!(
                        "warning: tracefs format empty for '{}'; falling back to hardcoded",
                        name
                    );
                    if let Some(m) = fallback.get(name) {
                        out.insert(name.clone(), m.clone());
                    }
                    continue;
                }
                let inferred = infer_params(name, &fields);
                let params: Vec<ParamMeta> = inferred.into_iter().map(|ip| ip.meta).collect();
                // buf_idx: first pointer param, or -1
                let buf_idx = params
                    .iter()
                    .position(|p| p.ctype.is_ptr())
                    .map(|i| i as i32)
                    .unwrap_or(-1);
                eprintln!(
                    "tracefs: '{}' -> {} params (buf_idx={})",
                    name,
                    params.len(),
                    buf_idx
                );
                out.insert(
                    name.clone(),
                    SyscallMeta {
                        name: name.clone(),
                        params,
                        buf_idx,
                    },
                );
            }
            Err(_) => {
                if let Some(m) = fallback.get(name) {
                    eprintln!(
                        "tracefs: '{}' not found at {}; using hardcoded fallback",
                        name,
                        format_path.display()
                    );
                    out.insert(name.clone(), m.clone());
                } else {
                    eprintln!(
                        "warning: no metadata for syscall '{}' (tracefs + fallback both missing)",
                        name
                    );
                }
            }
        }
    }

    out
}
