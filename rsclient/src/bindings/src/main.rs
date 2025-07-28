use std::os::unix::io::AsRawFd;
use std::{fs, io, env};
use std::process::Command;
use std::path::PathBuf;
use bindings::generate_bindings;

const GENERATED_FILE: &str = "generated.rs";
// const KMOD_HEADER_FILE: &str = "kmod/vmlinux.h";

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <kmod_header_file>", args[0]);
        std::process::exit(1);
    }


    let kmod_header_file = &args[1];
    let _ = generate_bindings(kmod_header_file, GENERATED_FILE);

    Ok(())
}
