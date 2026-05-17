use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::{SyscallRequest, SyscallResponse};
use tokio::io::duplex;

#[tokio::test]
async fn test_roundtrip_request() {
    let (mut client, mut server) = duplex(1024);
    let req = SyscallRequest {
        slot_idx: 3,
        number: 59,
        args: [1, 2, 3, 4, 5, 6],
        in_bufs: Vec::new(),
        out_sizes: Vec::new(),
    };
    write_message(&mut client, &req).await.unwrap();
    drop(client);
    let decoded: SyscallRequest = read_message(&mut server).await.unwrap();
    assert_eq!(decoded.slot_idx, 3);
    assert_eq!(decoded.number, 59);
    assert_eq!(decoded.args[0], 1);
}

#[tokio::test]
async fn test_roundtrip_response() {
    let (mut client, mut server) = duplex(1024);
    let resp = SyscallResponse { slot_idx: 3, ret: 42, out_bufs: Vec::new() };
    write_message(&mut client, &resp).await.unwrap();
    drop(client);
    let decoded: SyscallResponse = read_message(&mut server).await.unwrap();
    assert_eq!(decoded.slot_idx, 3);
    assert_eq!(decoded.ret, 42);
}
