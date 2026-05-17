use rsclient::kmod::{ControlBuffer, KmodSyscall, MemoryQueue, ParamBuf, SlotBufs, SyscallParam, BUFFER_SIZE};
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
fn test_param_buf_size() {
    // 8 + 4 + 4 + 4096 = 4112
    assert_eq!(mem::size_of::<ParamBuf>(), 4112, "ParamBuf must be 4112 bytes");
}

#[test]
fn test_slot_bufs_size() {
    // 6 * 4112 = 24672
    assert_eq!(mem::size_of::<SlotBufs>(), 6 * 4112, "SlotBufs must be 24672 bytes");
}

#[test]
fn test_control_buffer_size() {
    let expected = 2 * mem::size_of::<MemoryQueue>() + BUFFER_SIZE * mem::size_of::<SlotBufs>();
    assert_eq!(
        mem::size_of::<ControlBuffer>(),
        expected,
        "ControlBuffer must be 2 MemoryQueues + BUFFER_SIZE SlotBufs"
    );
}

#[test]
fn print_layout_sizes() {
    println!("SyscallParam  : {} bytes", mem::size_of::<SyscallParam>());
    println!("KmodSyscall   : {} bytes", mem::size_of::<KmodSyscall>());
    println!("MemoryQueue   : {} bytes", mem::size_of::<MemoryQueue>());
    println!("ParamBuf      : {} bytes", mem::size_of::<ParamBuf>());
    println!("SlotBufs      : {} bytes", mem::size_of::<SlotBufs>());
    println!("ControlBuffer : {} bytes", mem::size_of::<ControlBuffer>());
}

#[test]
fn test_syscall_param_default_zeroed() {
    let p = SyscallParam::default();
    assert_eq!(unsafe { p.ulong_type }, 0);
}
