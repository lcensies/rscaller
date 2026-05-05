use rsclient::kmod::{ControlBuffer, KmodSyscall, MemoryQueue, SyscallParam};
use rsclient::relay::Relay;
use rscaller_proto::types::SyscallRequest;
use std::mem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a zeroed heap-allocated ControlBuffer.
fn zeroed_control_buffer() -> Box<ControlBuffer> {
    // Safety: ControlBuffer is #[repr(C)] with all integer fields; zero is valid.
    unsafe { Box::new(mem::zeroed()) }
}

/// Push a KmodSyscall into the kernel_to_user queue of a ControlBuffer.
/// Mirrors what the kmod does: write to nodes[tail_idx], advance tail, increment size.
fn push_syscall(cb: &mut ControlBuffer, sc: KmodSyscall) {
    let q = &mut cb.kernel_to_user;
    assert!(q.size < q.max_size, "queue full");
    let slot = q.tail_idx as usize;
    q.nodes[slot] = sc;
    q.tail_idx = (q.tail_idx + 1) % 10;
    q.size += 1;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_to_request_basic_conversion() {
    let sc = KmodSyscall {
        number: 62, // kill
        n_params: 2,
        ret: 0,
        _pad: 0,
        param_bufs: {
            let mut p = [SyscallParam::default(); 6];
            // pid = 1234
            p[0] = SyscallParam { ulong_type: 1234 };
            // sig = 9
            p[1] = SyscallParam { ulong_type: 9 };
            p
        },
    };

    let req: SyscallRequest = Relay::<tokio::io::DuplexStream, tokio::io::DuplexStream>::to_request(7, &sc);

    assert_eq!(req.slot_idx, 7, "slot_idx must match");
    assert_eq!(req.number, 62, "syscall number must match kill(62)");
    assert_eq!(req.args[0], 1234, "first arg should be pid");
    assert_eq!(req.args[1], 9, "second arg should be sig");
    assert_eq!(req.args[2], 0, "unused args should be zero");
}

#[test]
fn test_to_request_execve() {
    // execve: number=59, filename pointer, argv pointer, envp pointer
    let fake_ptr: u64 = 0xDEAD_BEEF_0000_0000;
    let sc = KmodSyscall {
        number: 59,
        n_params: 3,
        ret: 0,
        _pad: 0,
        param_bufs: {
            let mut p = [SyscallParam::default(); 6];
            p[0] = SyscallParam { ulong_type: fake_ptr };
            p[1] = SyscallParam { ulong_type: fake_ptr + 1 };
            p[2] = SyscallParam { ulong_type: fake_ptr + 2 };
            p
        },
    };

    let req = Relay::<tokio::io::DuplexStream, tokio::io::DuplexStream>::to_request(0, &sc);

    assert_eq!(req.number, 59);
    assert_eq!(req.args[0], fake_ptr);
    assert_eq!(req.args[1], fake_ptr + 1);
    assert_eq!(req.args[2], fake_ptr + 2);
}

#[test]
fn test_control_buffer_queue_push_pop_via_raw() {
    let mut cb = zeroed_control_buffer();

    // Initialize queue metadata (mirrors kmod mem_queue_init)
    cb.kernel_to_user.max_size = 10;
    cb.kernel_to_user.size = 0;
    cb.kernel_to_user.head_idx = 0;
    cb.kernel_to_user.tail_idx = 0;

    // Push one syscall
    let sc = KmodSyscall {
        number: 62,
        n_params: 2,
        ret: 0,
        _pad: 0,
        param_bufs: {
            let mut p = [SyscallParam::default(); 6];
            p[0] = SyscallParam { ulong_type: 42 };
            p[1] = SyscallParam { ulong_type: 0 };
            p
        },
    };
    push_syscall(&mut cb, sc);

    assert_eq!(cb.kernel_to_user.size, 1, "queue size should be 1 after push");
    assert_eq!(cb.kernel_to_user.tail_idx, 1, "tail_idx should advance");
    assert_eq!(cb.kernel_to_user.nodes[0].number, 62);
    assert_eq!(unsafe { cb.kernel_to_user.nodes[0].param_bufs[0].ulong_type }, 42);
}

#[test]
fn test_multiple_pushes_wrap_around() {
    let mut cb = zeroed_control_buffer();
    cb.kernel_to_user.max_size = 10;

    // Push 10 syscalls to fill the ring buffer
    for i in 0..10u32 {
        let mut sc: KmodSyscall = unsafe { mem::zeroed() };
        sc.number = i as i32;
        push_syscall(&mut cb, sc);
    }

    assert_eq!(cb.kernel_to_user.size, 10);
    assert_eq!(cb.kernel_to_user.tail_idx, 0, "tail_idx wraps back to 0 after 10 entries");

    // Verify all numbers stored correctly
    for i in 0..10 {
        assert_eq!(cb.kernel_to_user.nodes[i].number, i as i32);
    }
}
