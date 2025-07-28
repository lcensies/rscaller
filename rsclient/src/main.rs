use io_uring::{IoUring, opcode, types};
use std::os::unix::io::AsRawFd;
use std::{fs, io};
use std::mem;
// use bindings::*;
// use crate::bindings::System;

use bindings::bindings::Syscall;

use std::path::PathBuf;

const IO_URING: &str = "/tmp/uring";


fn main() -> io::Result<()> {

    Ok(())
}
