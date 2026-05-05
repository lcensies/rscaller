use rsclient::kmod::{ControlBuffer, KmodSyscall, MemoryQueue, SyscallParam};
use std::mem;

#[test]
fn test_syscall_param_size() {
    assert_eq!(
        mem::size_of::<SyscallParam>(),
        8,
        "SyscallParam must be 8 bytes (largest union member is u64)"
    );
}

#[test]
fn test_kmod_syscall_size() {
    // 3×i32 (12) + 1×i32 pad (4) + 6×8 (48) = 64
    assert_eq!(
        mem::size_of::<KmodSyscall>(),
        64,
        "KmodSyscall must be 64 bytes"
    );
}

#[test]
fn test_memory_queue_size() {
    // 4×i32 (16) + 10×64 (640) = 656
    let expected = 4 * mem::size_of::<i32>() + 10 * mem::size_of::<KmodSyscall>();
    assert_eq!(
        mem::size_of::<MemoryQueue>(),
        expected,
        "MemoryQueue must be {} bytes",
        expected
    );
}

#[test]
fn test_control_buffer_size() {
    assert_eq!(
        mem::size_of::<ControlBuffer>(),
        2 * mem::size_of::<MemoryQueue>(),
        "ControlBuffer must be exactly 2 MemoryQueues"
    );
}

#[test]
fn print_layout_sizes() {
    println!("SyscallParam  : {} bytes", mem::size_of::<SyscallParam>());
    println!("KmodSyscall   : {} bytes", mem::size_of::<KmodSyscall>());
    println!("MemoryQueue   : {} bytes", mem::size_of::<MemoryQueue>());
    println!("ControlBuffer : {} bytes", mem::size_of::<ControlBuffer>());
}

#[test]
fn test_syscall_param_default_zeroed() {
    let p = SyscallParam::default();
    assert_eq!(unsafe { p.ulong_type }, 0);
}
