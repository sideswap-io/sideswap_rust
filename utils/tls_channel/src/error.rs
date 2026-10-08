use std::time::Duration;

use crate::keys::PublicKey;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(std::io::Error),

    #[error("timeout after {0:?}")]
    Timeout(Duration),

    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("handshake failed: {0}")]
    Handshake(&'static str),

    #[error("client public key {public_key} is not allowed")]
    ClientRejected { public_key: PublicKey },

    #[error("packet too large, limit is {limit} bytes")]
    PacketTooLarge { limit: usize },

    #[error("connection closed by peer")]
    Closed,

    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),
}

/// tokio-rustls reports TLS failures as `io::Error` wrapping a `rustls::Error`;
/// unwrap those so callers can match on [`Error::Tls`].
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        if err
            .get_ref()
            .is_some_and(|inner| inner.is::<rustls::Error>())
        {
            let inner = err.into_inner().expect("checked above");
            let tls = inner.downcast::<rustls::Error>().expect("checked above");
            return Error::Tls(*tls);
        }
        Error::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
