mod codegen;
mod syscall_table;
mod version;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use codegen::{generate_header, generate_source, metadata_map};
use syscall_table::{build_name_map, parse_tbl};
use version::{select_tbl_path, KernelVersion};

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

    // 4. Load hardcoded metadata
    let meta = metadata_map();

    // 5. Generate files
    let header = generate_header(&forwarded, &name_map, &meta)
        .context("Failed to generate handler_wrappers.h")?;
    let source = generate_source(&forwarded, &meta)
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
