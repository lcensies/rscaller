use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .context("reading message body")?;

    let msg = bincode::deserialize(&buf).context("deserializing message")?;
    Ok(msg)
}

/// Write a length-prefixed bincode message to an async writer.
pub async fn write_message<T, W>(writer: &mut W, msg: &T) -> Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let buf = bincode::serialize(msg).context("serializing message")?;
    let len = buf.len() as u32;
    writer
        .write_all(&len.to_le_bytes())
        .await
        .context("writing message length")?;
    writer
        .write_all(&buf)
        .await
        .context("writing message body")?;
    writer.flush().await.context("flushing writer")?;
    Ok(())
}
