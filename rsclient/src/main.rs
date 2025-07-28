use io_uring::{IoUring, opcode, types};
use std::os::unix::io::AsRawFd;
use std::{fs, io};
use std::mem;
// use bindings::*;
// use crate::bindings::System;

// use bindings::bindings::Syscall;

use std::path::PathBuf;

use utils::*;
use std::ffi::OsStr;
// use libloading::{Library, Symbol};

use bindings::bindings::Bindings;

const IO_URING: &str = "/tmp/uring";


fn main() -> io::Result<()> {
    let git_root = get_git_root().unwrap();
    let so_path = format!("{}/kmod/rsc_userspace_buffer.so", git_root);
    
    // let library_path: &OsStr = OsStr::new(kek.as_str());
    // let lib = unsafe {Library::new(library_path).unwrap() };
    unsafe {Bindings::load_from_path(so_path).unwrap()};

    
    
    // let plugin = unsafe { Plugin::new(library_path) };
    
    Ok(())
}
