use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::{SyscallRequest, SyscallResponse};
use rsbeacon::executor::execute_syscall;
use rsbeacon::net_backend::direct::DirectBackend;
use tokio::net::{TcpListener, TcpStream};

#[test]
fn test_execute_getpid() {
    let req = SyscallRequest {
        slot_idx: 0,
        number: libc::SYS_getpid as u64,
        args: [0; 6],
        in_bufs: Vec::new(),
        out_sizes: Vec::new(),
    };
    let resp = execute_syscall(&req, &DirectBackend::new());
    assert!(
        resp.ret > 0,
        "getpid should return positive PID, got {}",
        resp.ret
    );
    assert_eq!(resp.slot_idx, 0);
}

#[test]
fn test_execute_kill_sig0() {
    // kill(getpid(), 0) — no signal sent, just checks process exists
    let pid = unsafe { libc::getpid() } as u64;
    let req = SyscallRequest {
        slot_idx: 1,
        number: libc::SYS_kill as u64,
        args: [pid, 0, 0, 0, 0, 0],
        in_bufs: Vec::new(),
        out_sizes: Vec::new(),
    };
    let resp = execute_syscall(&req, &DirectBackend::new());
    assert_eq!(resp.ret, 0, "kill(self, 0) should succeed");
}

#[test]
fn test_blocked_syscall_returns_eperm() {
    let req = SyscallRequest {
        slot_idx: 99,
        number: 169, // reboot
        args: [0; 6],
        in_bufs: Vec::new(),
        out_sizes: Vec::new(),
    };
    let resp = execute_syscall(&req, &DirectBackend::new());
    assert_eq!(resp.ret, -(libc::EPERM as i64));
    assert_eq!(resp.slot_idx, 99);
}

#[tokio::test]
async fn test_beacon_roundtrip_plain() {
    // Bind on random port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        // Serve one request then exit
        let req: SyscallRequest = read_message(&mut reader).await.unwrap();
        let resp = execute_syscall(&req, &DirectBackend::new());
        write_message(&mut writer, &resp).await.unwrap();
    });

    // Client side
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);

    let req = SyscallRequest {
        slot_idx: 42,
        number: libc::SYS_getpid as u64,
        args: [0; 6],
        in_bufs: Vec::new(),
        out_sizes: Vec::new(),
    };
    write_message(&mut writer, &req).await.unwrap();

    let resp: SyscallResponse = read_message(&mut reader).await.unwrap();
    assert_eq!(resp.slot_idx, 42);
    assert!(resp.ret > 0);
}
