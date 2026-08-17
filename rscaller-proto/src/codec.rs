use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest framed message accepted on the wire (64 MiB covers max syscall I/O buffers).
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

/// Read a length-prefixed bincode message from an async reader.
pub async fn read_message<T, R>(reader: &mut R) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("reading message length")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    // Cap allocation: length prefix is attacker-controlled on untrusted links.
    if len > MAX_MESSAGE_SIZE {
        anyhow::bail!("message length {len} exceeds MAX_MESSAGE_SIZE {MAX_MESSAGE_SIZE}");
    }

    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .context("reading message body")?;

    let msg = bincode::deserialize(&buf).context("deserializing message")?;
    Ok(msg)
}

/// Write a length-prefixed bincode message to an async writer.
/// Serializes into a single buffer (len ++ body) so the kernel sends one TCP segment.
pub async fn write_message<T, W>(writer: &mut W, msg: &T) -> Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let body = bincode::serialize(msg).context("serializing message")?;
    let len = body.len() as u32;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    writer.write_all(&frame).await.context("writing framed message")?;
    Ok(())
}
