use std::io;
use std::net::SocketAddr;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;
use tokio_util::codec::length_delimited::LengthDelimitedCodecError;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use crate::error::{Error, Result};
use crate::keys::PublicKey;

/// Frame layout inside the TLS stream: `u32 BE length`, then the packet.
fn codec(max_packet_size: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_type::<u32>()
        .big_endian()
        .max_frame_length(max_packet_size)
        .new_codec()
}

/// The codec reports an oversized frame (on either encode or decode) as an
/// `io::Error` wrapping [`LengthDelimitedCodecError`].
fn map_io(err: io::Error, max_packet_size: usize) -> Error {
    if err
        .get_ref()
        .is_some_and(|inner| inner.is::<LengthDelimitedCodecError>())
    {
        return Error::PacketTooLarge {
            limit: max_packet_size,
        };
    }
    err.into()
}

/// Mutually authenticated TLS 1.3 connection carrying length-framed packets.
pub struct Channel {
    reader: ChannelReader,
    writer: ChannelWriter,
}

impl Channel {
    pub(crate) fn new(
        stream: TlsStream<TcpStream>,
        peer_public_key: PublicKey,
        peer_addr: SocketAddr,
        max_packet_size: usize,
    ) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        Self {
            reader: ChannelReader {
                inner: FramedRead::new(read_half, codec(max_packet_size)),
                max_packet_size,
                peer_public_key,
                peer_addr,
            },
            writer: ChannelWriter {
                inner: FramedWrite::new(write_half, codec(max_packet_size)),
                max_packet_size,
                peer_public_key,
                peer_addr,
            },
        }
    }

    pub fn peer_public_key(&self) -> &PublicKey {
        &self.reader.peer_public_key
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.reader.peer_addr
    }

    /// See [`ChannelWriter::send`].
    pub async fn send(&mut self, packet: impl Into<Bytes>) -> Result<()> {
        self.writer.send(packet).await
    }

    /// See [`ChannelReader::recv`].
    pub async fn recv(&mut self) -> Result<Bytes> {
        self.reader.recv().await
    }

    /// Sends TLS `close_notify` and shuts down the TCP write side.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.writer.shutdown().await
    }

    /// Splits the channel so that sending and receiving can run concurrently.
    pub fn split(self) -> (ChannelReader, ChannelWriter) {
        (self.reader, self.writer)
    }
}

pub struct ChannelReader {
    inner: FramedRead<ReadHalf<TlsStream<TcpStream>>, LengthDelimitedCodec>,
    max_packet_size: usize,
    peer_public_key: PublicKey,
    peer_addr: SocketAddr,
}

impl ChannelReader {
    pub fn peer_public_key(&self) -> &PublicKey {
        &self.peer_public_key
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Receives the next packet.
    ///
    /// Cancel safe: partially received frames stay buffered inside the
    /// codec, so dropping the future (for example in `tokio::select!`) loses
    /// nothing and the next call continues the same frame.
    ///
    /// Returns [`Error::Closed`] when the peer closed the connection cleanly
    /// (TLS `close_notify`) between frames. Any other error leaves the
    /// channel unusable.
    pub async fn recv(&mut self) -> Result<Bytes> {
        match self.inner.next().await {
            Some(Ok(frame)) => Ok(frame.freeze()),
            Some(Err(err)) => Err(map_io(err, self.max_packet_size)),
            None => Err(Error::Closed),
        }
    }
}

pub struct ChannelWriter {
    inner: FramedWrite<WriteHalf<TlsStream<TcpStream>>, LengthDelimitedCodec>,
    max_packet_size: usize,
    peer_public_key: PublicKey,
    peer_addr: SocketAddr,
}

impl ChannelWriter {
    pub fn peer_public_key(&self) -> &PublicKey {
        &self.peer_public_key
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Sends one packet.
    ///
    /// Cancel safe in the sense that framing is never corrupted: the frame
    /// is encoded into the codec's buffer atomically, and if the future is
    /// dropped before the buffer is flushed, the next `send` or `shutdown`
    /// flushes it. The peer either receives the whole packet or (if the
    /// future was dropped before encoding) nothing.
    pub async fn send(&mut self, packet: impl Into<Bytes>) -> Result<()> {
        self.inner
            .send(packet.into())
            .await
            .map_err(|err| map_io(err, self.max_packet_size))
    }

    /// Flushes any buffered frame, then sends TLS `close_notify` and shuts
    /// down the TCP write side so the peer's `recv` returns [`Error::Closed`].
    pub async fn shutdown(&mut self) -> Result<()> {
        self.inner.close().await?;
        Ok(())
    }
}
