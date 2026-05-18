use anyhow::{Context, Result};
use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::{SyscallBuf, SyscallRequest, SyscallResponse};
use std::net::SocketAddr;
use std::sync::mpsc;
use tokio::runtime::Runtime;

pub enum Transport {
    Tcp,
    Uds,
}

pub enum Encryption {
    None,
    Tls { ca_cert_pem: Vec<u8> },
}

/// Message sent from the sync caller to the async I/O task.
struct Req {
    request: SyscallRequest,
    reply_tx: mpsc::SyncSender<Result<SyscallResponse>>,
}

/// Synchronous rsbeacon client.
///
/// Wraps a dedicated tokio Runtime. An async task inside the runtime owns the
/// transport connection and processes one request at a time.
pub struct Client {
    tx: mpsc::SyncSender<Req>,
    // Keep runtime alive for the lifetime of Client.
    _runtime: Runtime,
}

impl Client {
    pub fn new(
        beacon: SocketAddr,
        transport: Transport,
        encryption: Encryption,
    ) -> Result<Self> {
        let rt = Runtime::new().context("creating tokio runtime")?;

        // Bounded channel: backpressure prevents runaway queuing.
        let (tx, rx) = mpsc::sync_channel::<Req>(64);

        // Spawn the async I/O loop inside the runtime.
        rt.spawn(async move {
            if let Err(e) = io_task(beacon, transport, encryption, rx).await {
                tracing::error!("rscfuse client I/O task exited: {:#}", e);
            }
        });

        Ok(Client {
            tx,
            _runtime: rt,
        })
    }

    /// Execute a raw syscall on rsbeacon.
    /// Returns `(ret_val, out_bufs)`.
    pub fn syscall(
        &self,
        nr: u64,
        args: [u64; 6],
        in_bufs: Vec<SyscallBuf>,
        out_sizes: Vec<(u8, u64)>,
    ) -> Result<(i64, Vec<SyscallBuf>)> {
        let request = SyscallRequest {
            slot_idx: 0,
            number: nr,
            args,
            in_bufs,
            out_sizes,
        };

        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.tx
            .send(Req { request, reply_tx })
            .context("sending request to I/O task (task may have exited)")?;

        let resp = reply_rx
            .recv()
            .context("waiting for response (I/O task may have exited)")??;

        Ok((resp.ret, resp.out_bufs))
    }
}

/// Async I/O loop: owns the transport connection, serialises requests.
async fn io_task(
    beacon: SocketAddr,
    transport: Transport,
    encryption: Encryption,
    rx: mpsc::Receiver<Req>,
) -> Result<()> {
    match (transport, encryption) {
        (Transport::Tcp, Encryption::None) => {
            use tokio::net::TcpStream;
            let stream = TcpStream::connect(beacon)
                .await
                .context("TCP connect to beacon")?;
            let (mut reader, mut writer) = tokio::io::split(stream);
            run_loop(&mut reader, &mut writer, rx).await
        }
        (Transport::Tcp, Encryption::Tls { ca_cert_pem }) => {
            use rscaller_proto::transport::tls::connect_tls;
            // Use the beacon host as the server name for TLS SNI.
            let server_name = beacon.ip().to_string();
            let (mut reader, mut writer) =
                connect_tls(beacon, &server_name, &ca_cert_pem).await?;
            run_loop(&mut reader, &mut writer, rx).await
        }
        (Transport::Uds, Encryption::None) => {
            // For UDS, the SocketAddr is not meaningful; callers should arrange
            // for a path. We accept the display string as a best-effort path.
            let path = beacon.to_string();
            use tokio::net::UnixStream;
            let stream = UnixStream::connect(&path)
                .await
                .context("UDS connect to beacon")?;
            let (mut reader, mut writer) = tokio::io::split(stream);
            run_loop(&mut reader, &mut writer, rx).await
        }
        (Transport::Uds, Encryption::Tls { .. }) => {
            anyhow::bail!("TLS over UDS not supported")
        }
    }
}

/// Core request/response loop: read from `rx`, write to transport, read reply,
/// forward to caller.  Runs sequentially — one in-flight request at a time.
///
/// Uses `block_in_place` to perform blocking mpsc::recv without starving the
/// tokio thread pool.
async fn run_loop<R, W>(
    reader: &mut R,
    writer: &mut W,
    rx: mpsc::Receiver<Req>,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        // Pull next request from the sync side without blocking the executor.
        let req: Option<Req> = tokio::task::block_in_place(|| rx.recv().ok());

        let req = match req {
            Some(r) => r,
            None => break, // sender dropped → clean shutdown
        };

        // Send request to beacon.
        if let Err(e) = write_message(writer, &req.request).await {
            let _ = req.reply_tx.send(Err(e));
            break;
        }

        // Read response.
        let resp_result: Result<SyscallResponse> = read_message(reader).await;
        let _ = req.reply_tx.send(resp_result);
    }

    Ok(())
}
