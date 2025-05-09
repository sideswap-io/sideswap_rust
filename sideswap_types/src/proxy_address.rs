use std::{
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyAddress {
    /// A SOCKS v5 proxy address (“host:port” resolved to `SocketAddr`).
    Socks5 { address: SocketAddr },
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unsupported proxy scheme `{0}`")]
    UnsupportedScheme(String),
    #[error("username/password in URI are not supported")]
    CredentialsNotSupported,
    #[error("invalid proxy address syntax")]
    InvalidSyntax,
    #[error("invalid port number")]
    InvalidPort,
    #[error("failed to resolve host: {0}")]
    ResolveFailed(#[source] std::io::Error),
}

impl FromStr for ProxyAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // split optional <scheme>://rest
        let (scheme, rest) = match s.find("://") {
            Some(pos) => (&s[..pos], &s[pos + 3..]),
            None => ("", s),
        };

        match scheme {
            "" | "socks" | "socks5" => {}
            other => return Err(Error::UnsupportedScheme(other.to_owned())),
        }

        // forbid credentials user@host
        if rest.contains('@') {
            return Err(Error::CredentialsNotSupported);
        }

        // fast path: numeric “host:port” that `SocketAddr::from_str` groks
        if let Ok(addr) = SocketAddr::from_str(rest) {
            return Ok(ProxyAddress::Socks5 { address: addr });
        }

        //  host:port (split on *last* ':' to keep potential colons in hostnames)
        let colon = rest.rfind(':').ok_or(Error::InvalidSyntax)?;

        let (host_part, port_part) = { (&rest[..colon], &rest[colon + 1..]) };

        if host_part.is_empty() {
            return Err(Error::InvalidSyntax);
        }

        let port: u16 = port_part.parse().map_err(|_| Error::InvalidPort)?;

        // resolve host (DNS or numeric) via ToSocketAddrs
        let mut addrs = (host_part, port)
            .to_socket_addrs()
            .map_err(Error::ResolveFailed)?;

        let address = addrs.next().ok_or_else(|| {
            Error::ResolveFailed(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "no addresses returned",
            ))
        })?;

        Ok(ProxyAddress::Socks5 { address })
    }
}

impl std::fmt::Display for ProxyAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // `SocketAddr`’s Display already puts IPv6 in “[ ]”.
            ProxyAddress::Socks5 { address } => write!(f, "socks5://{address}"),
        }
    }
}

#[cfg(test)]
mod tests;
