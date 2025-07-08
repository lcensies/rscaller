use io_uring::{IoUring, opcode, types};
use std::os::unix::io::AsRawFd;
use std::{fs, io};
use std::process::Command;
use std::mem;
use bindings::bindings;
use bindings::System

use std::path::PathBuf;

const IO_URING: &str = "/tmp/uring";

// Function to get the Git root directory
fn get_git_root() -> io::Result<PathBuf> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()?;

    let git_root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(git_root))
}

fn main() -> io::Result<()> {
    
    let received_syscall: SystemCall;

    let mut ring = IoUring::new(8)?;

    let fd = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(IO_URING)?;
    let fd = fs::File::open(IO_URING)?;
    let mut buf = vec![0; 1024];

    let read_e = opcode::Read::new(types::Fd(fd.as_raw_fd()), buf.as_mut_ptr(), buf.len() as _)
        .build()
        .user_data(0x42);

    // Note that the developer needs to ensure
    // that the entry pushed into submission queue is valid (e.g. fd, buffer).
    unsafe {
        ring.submission()
            .push(&read_e)
            .expect("submission queue is full");
    }

    ring.submit_and_wait(1)?;

    let cqe = ring.completion().next().expect("completion queue is empty");

    println!("{:?}", cqe);
    // Decode the system call information from the completion queue
    let system_call: SystemCall = unsafe { mem::transmute(cqe.user_data()) };

    // Print the decoded system call information
    // println!("Decoded System Call Information: {:?}", system_call);

    // assert_eq!(cqe.user_data(), 0x42);
    // assert!(cqe.result() >= 0, "read error: {}", cqe.result());

    Ok(())
}
