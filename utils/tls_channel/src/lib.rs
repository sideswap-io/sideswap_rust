//! Mutually authenticated TLS 1.3 channel using RFC 7250 raw public keys.
//!
//! No certificates are involved: both peers are identified by bare Ed25519
//! public keys. The client must know the server's public key in advance. The
//! server checks the client's public key during the handshake with the
//! [`IsClientValid`] it was given; [`AllowedClients`] is a ready-made allow
//! list.
//!
//! The TLS stream carries length-framed packets. Each side enforces its own
//! [`Config::max_packet_size`] on both sent and received packets.
//!
//! ```no_run
//! # async fn example() -> tls_channel::Result<()> {
//! use std::sync::Arc;
//! use tls_channel::{AllowedClients, Config, SecretKey, Server, connect};
//!
//! let server_key = SecretKey::generate();
//! let client_key = SecretKey::generate();
//! let allowed = Arc::new(AllowedClients::new());
//! allowed.add(client_key.public_key());
//!
//! let server = Server::bind(&server_key, "127.0.0.1:0", Config::default(), allowed).await?;
//! let addr = server.local_addr()?;
//!
//! tokio::spawn(async move {
//!     loop {
//!         let incoming = server.accept().await?;
//!         tokio::spawn(async move {
//!             // Fails with `Error::ClientRejected` for unknown clients.
//!             let mut channel = incoming.handshake().await?;
//!             let packet = channel.recv().await?;
//!             channel.send(packet).await
//!         });
//!     }
//!     #[allow(unreachable_code)]
//!     tls_channel::Result::Ok(())
//! });
//!
//! let mut channel = connect(&client_key, server_key.public_key(), addr, Config::default()).await?;
//! channel.send(&b"ping"[..]).await?;
//! assert_eq!(channel.recv().await?, &b"ping"[..]);
//! # Ok(())
//! # }
//! ```

mod access;
mod channel;
mod error;
mod keys;
mod verifier;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ServerConfig};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub use access::{AllowedClients, IsClientValid};
pub use channel::{Channel, ChannelReader, ChannelWriter};
pub use error::{Error, Result};
pub use keys::{PublicKey, SecretKey};

/// Hard upper bound for [`Config::max_packet_size`].
pub const MAX_PACKET_SIZE: usize = 100 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Config {
    /// Largest packet this side will send or accept.
    /// Must not exceed [`MAX_PACKET_SIZE`].
    pub max_packet_size: usize,
    /// On the server this limits the TLS handshake. On the client it limits
    /// TCP connect plus TLS handshake.
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_packet_size: 1024 * 1024,
            timeout: Duration::from_secs(15),
        }
    }
}

impl Config {
    fn validate(&self) -> Result<()> {
        if self.max_packet_size == 0 {
            return Err(Error::InvalidConfig("max_packet_size must be positive"));
        }
        if self.max_packet_size > MAX_PACKET_SIZE {
            return Err(Error::InvalidConfig(
                "max_packet_size exceeds MAX_PACKET_SIZE",
            ));
        }
        Ok(())
    }
}

fn provider() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// Wraps our Ed25519 key as the RFC 7250 "certificate" (the bare SPKI) plus
/// the matching signing key.
fn certified_key(secret_key: &SecretKey) -> Result<Arc<CertifiedKey>> {
    let pkcs8 = PrivatePkcs8KeyDer::from(secret_key.pkcs8_der());
    let signing_key = rustls::crypto::ring::sign::any_eddsa_type(&pkcs8)?;
    let spki = CertificateDer::from(secret_key.public_key().spki_der());
    Ok(Arc::new(CertifiedKey::new(vec![spki], signing_key)))
}

fn server_config(
    secret_key: &SecretKey,
    is_client_valid: Arc<dyn IsClientValid>,
) -> Result<ServerConfig> {
    let provider = provider();
    let client_verifier = verifier::ClientKeyVerifier::new(
        provider.signature_verification_algorithms,
        is_client_valid,
    );
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(client_verifier))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
            certified_key(secret_key)?,
        )));
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(config)
}

fn client_config(secret_key: &SecretKey, server_public_key: &PublicKey) -> Result<ClientConfig> {
    let provider = provider();
    let server_verifier = verifier::ExpectedServerKey::new(
        server_public_key,
        provider.signature_verification_algorithms,
    );
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(server_verifier))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
            certified_key(secret_key)?,
        )));
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

pub struct Server {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    public_key: PublicKey,
    config: Config,
}

impl Server {
    /// `is_client_valid` is consulted during every handshake, so changes to
    /// a shared [`AllowedClients`] apply to new connections immediately.
    pub async fn bind(
        secret_key: &SecretKey,
        addr: impl ToSocketAddrs,
        config: Config,
        is_client_valid: Arc<dyn IsClientValid>,
    ) -> Result<Self> {
        config.validate()?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config(secret_key, is_client_valid)?));
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            acceptor,
            public_key: secret_key.public_key(),
            config,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Accepts a TCP connection. The handshake is done separately with
    /// [`Incoming::handshake`] so that a slow or malicious client cannot
    /// stall the accept loop; spawn a task per connection.
    pub async fn accept(&self) -> Result<Incoming> {
        let (stream, peer_addr) = self.listener.accept().await?;
        Ok(Incoming {
            stream,
            peer_addr,
            acceptor: self.acceptor.clone(),
            config: self.config.clone(),
        })
    }
}

/// Accepted TCP connection that has not completed the TLS handshake yet.
pub struct Incoming {
    stream: TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    config: Config,
}

impl Incoming {
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Runs the TLS handshake within [`Config::timeout`]. The client's key
    /// is checked by the server's [`IsClientValid`] as part of the handshake;
    /// a rejected client yields [`Error::ClientRejected`]. The accepted key is
    /// available as [`Channel::peer_public_key`].
    pub async fn handshake(self) -> Result<Channel> {
        let timeout = self.config.timeout;
        let tls = tokio::time::timeout(timeout, async {
            self.stream.set_nodelay(true)?;
            Ok::<_, Error>(self.acceptor.accept(self.stream).await?)
        })
        .await
        .map_err(|_| Error::Timeout(timeout))?
        .map_err(client_rejected)?;

        let client_public_key = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|spki| PublicKey::from_spki_der(spki.as_ref()))
            .ok_or(Error::Handshake("client did not present a raw public key"))?;

        Ok(Channel::new(
            tls.into(),
            client_public_key,
            self.peer_addr,
            self.config.max_packet_size,
        ))
    }
}

/// Surfaces the verifier's rejection (carried through rustls as
/// `CertificateError::Other`) as [`Error::ClientRejected`].
fn client_rejected(err: Error) -> Error {
    if let Error::Tls(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other))) =
        &err
        && let Some(rejected) = other.0.downcast_ref::<verifier::ClientRejected>()
    {
        return Error::ClientRejected {
            public_key: rejected.0,
        };
    }
    err
}

/// Connects to `addr` and authenticates the server against
/// `server_public_key`. TCP connect and TLS handshake share [`Config::timeout`].
///
/// In TLS 1.3 the client finishes its handshake before the server has checked
/// the client's key, so a client the server rejects still gets a channel
/// here; its first `recv` or `send` then fails with the server's TLS alert.
pub async fn connect(
    secret_key: &SecretKey,
    server_public_key: PublicKey,
    addr: SocketAddr,
    config: Config,
) -> Result<Channel> {
    config.validate()?;
    let connector = TlsConnector::from(Arc::new(client_config(secret_key, &server_public_key)?));
    // Raw public keys make the server name irrelevant for authentication; it
    // is only needed to satisfy the TLS API. No SNI is sent for IP addresses.
    let server_name = ServerName::IpAddress(addr.ip().into());

    let timeout = config.timeout;
    let tls = tokio::time::timeout(timeout, async {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok::<_, Error>(connector.connect(server_name, stream).await?)
    })
    .await
    .map_err(|_| Error::Timeout(timeout))??;

    Ok(Channel::new(
        tls.into(),
        server_public_key,
        addr,
        config.max_packet_size,
    ))
}
