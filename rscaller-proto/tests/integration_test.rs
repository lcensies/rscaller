use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::{SyscallRequest, SyscallResponse};
use tokio::io::duplex;

// ---------------------------------------------------------------------------
// Codec integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_codec_multiple_frames_in_order() {
    let (mut writer_side, mut reader_side) = duplex(4096);

    let reqs: Vec<SyscallRequest> = (0..3)
        .map(|i| SyscallRequest {
            slot_idx: i,
            number: 59 + i,
            args: [i; 6],
        })
        .collect();

    // Write all three back-to-back
    for req in &reqs {
        write_message(&mut writer_side, req).await.unwrap();
    }
    drop(writer_side);

    // Read them back and verify order
    for (i, expected) in reqs.iter().enumerate() {
        let decoded: SyscallRequest = read_message(&mut reader_side).await.unwrap();
        assert_eq!(decoded.slot_idx, expected.slot_idx, "frame {} slot_idx mismatch", i);
        assert_eq!(decoded.number, expected.number, "frame {} number mismatch", i);
        assert_eq!(decoded.args, expected.args, "frame {} args mismatch", i);
    }
}

#[tokio::test]
async fn test_codec_response_negative_ret() {
    let (mut writer_side, mut reader_side) = duplex(1024);

    let resp = SyscallResponse { slot_idx: 7, ret: -1 };
    write_message(&mut writer_side, &resp).await.unwrap();
    drop(writer_side);

    let decoded: SyscallResponse = read_message(&mut reader_side).await.unwrap();
    assert_eq!(decoded.slot_idx, 7);
    assert_eq!(decoded.ret, -1, "negative return value must survive roundtrip");
}

#[tokio::test]
async fn test_codec_max_args() {
    let (mut writer_side, mut reader_side) = duplex(1024);

    let req = SyscallRequest {
        slot_idx: u64::MAX,
        number: u64::MAX,
        args: [u64::MAX; 6],
    };
    write_message(&mut writer_side, &req).await.unwrap();
    drop(writer_side);

    let decoded: SyscallRequest = read_message(&mut reader_side).await.unwrap();
    assert_eq!(decoded.slot_idx, u64::MAX);
    assert_eq!(decoded.number, u64::MAX);
    assert_eq!(decoded.args, [u64::MAX; 6]);
}

#[tokio::test]
async fn test_codec_interleaved_request_response() {
    // Simulate a full request→response cycle over an in-memory channel
    let (mut client_w, mut server_r) = duplex(4096);
    let (mut server_w, mut client_r) = duplex(4096);

    let req = SyscallRequest { slot_idx: 11, number: 62, args: [0; 6] };

    // Client sends request
    write_message(&mut client_w, &req).await.unwrap();

    // Server reads and echoes back
    let decoded_req: SyscallRequest = read_message(&mut server_r).await.unwrap();
    let resp = SyscallResponse { slot_idx: decoded_req.slot_idx, ret: 0 };
    write_message(&mut server_w, &resp).await.unwrap();

    // Client reads response
    let decoded_resp: SyscallResponse = read_message(&mut client_r).await.unwrap();
    assert_eq!(decoded_resp.slot_idx, 11);
    assert_eq!(decoded_resp.ret, 0);
}

/// TLS integration test — skipped unless certs are present.
/// Generate with: bash scripts/gen_certs.sh certs/
/// Then run: cargo test -p rscaller-proto -- --ignored test_tls_roundtrip
#[tokio::test]
#[ignore = "requires certs/ directory — run scripts/gen_certs.sh first"]
async fn test_tls_roundtrip() {
    use rscaller_proto::transport::tls;
    use std::net::SocketAddr;
    use tokio::net::{TcpListener, TcpStream};

    let cert_pem = std::fs::read("certs/server.crt").expect("certs/server.crt missing");
    let key_pem  = std::fs::read("certs/server.key").expect("certs/server.key missing");
    let ca_pem   = std::fs::read("certs/ca.crt").expect("certs/ca.crt missing");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let cert_pem2 = cert_pem.clone();
    let key_pem2  = key_pem.clone();

    // Server task
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls_stream = tls::accept_tls(tcp, &cert_pem2, &key_pem2).await.unwrap();
        let (mut r, mut w) = tokio::io::split(tls_stream);
        let req: SyscallRequest = read_message(&mut r).await.unwrap();
        let resp = SyscallResponse { slot_idx: req.slot_idx, ret: 42 };
        write_message(&mut w, &resp).await.unwrap();
    });

    // Client
    let (mut r, mut w) = tls::connect_tls(addr, "rsbeacon", &ca_pem).await.unwrap();
    let req = SyscallRequest { slot_idx: 5, number: 39, args: [0; 6] };
    write_message(&mut w, &req).await.unwrap();

    let resp: SyscallResponse = read_message(&mut r).await.unwrap();
    assert_eq!(resp.slot_idx, 5);
    assert_eq!(resp.ret, 42);
}
