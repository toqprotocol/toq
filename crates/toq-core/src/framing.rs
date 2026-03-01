use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::{Keypair, PublicKey};
use crate::envelope::Envelope;
use crate::error::Error;

/// Write a length-prefixed payload (4-byte big-endian u32 + data).
pub async fn write_length_prefixed<S>(stream: &mut S, data: &[u8]) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    let len = (data.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(())
}

/// Read a length-prefixed payload with a maximum size limit.
pub async fn read_length_prefixed<S>(stream: &mut S, max_size: usize) -> Result<Vec<u8>, Error>
where
    S: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_size {
        return Err(Error::InvalidEnvelope("payload too large".into()));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(buf)
}

/// Send a signed envelope over the stream.
pub async fn send_envelope<S>(
    stream: &mut S,
    envelope: &mut Envelope,
    keypair: &Keypair,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    envelope.sign(keypair)?;
    let data = serde_json::to_vec(envelope)?;
    write_length_prefixed(stream, &data).await
}

/// Receive and verify an envelope from the stream.
pub async fn recv_envelope<S>(
    stream: &mut S,
    peer_key: &PublicKey,
    max_size: usize,
) -> Result<Envelope, Error>
where
    S: AsyncReadExt + Unpin,
{
    let data = read_length_prefixed(stream, max_size).await?;
    let envelope: Envelope =
        serde_json::from_slice(&data).map_err(|e| Error::InvalidEnvelope(e.to_string()))?;
    envelope.verify(peer_key)?;
    Ok(envelope)
}

/// Receive, verify, and check replay prevention on an envelope.
pub async fn recv_envelope_checked<S>(
    stream: &mut S,
    peer_key: &PublicKey,
    max_size: usize,
    sequence_tracker: &mut crate::replay::SequenceTracker,
    dedup: &mut crate::delivery::DedupSet,
) -> Result<Envelope, Error>
where
    S: AsyncReadExt + Unpin,
{
    let envelope = recv_envelope(stream, peer_key, max_size).await?;
    if !sequence_tracker.check(envelope.sequence) {
        return Err(Error::InvalidEnvelope("sequence violation".into()));
    }
    if dedup.is_duplicate(&envelope.id) {
        return Err(Error::InvalidEnvelope("duplicate message".into()));
    }
    Ok(envelope)
}
