use std::fmt;
use std::str::FromStr;

use hex_literal::hex;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// PKCS#8 v1 `PrivateKeyInfo` header for an Ed25519 key (RFC 8410 section
/// 10.3), followed by the 32-byte seed. ring and rustls only load private keys
/// from PKCS#8, and ring has no API to wrap an existing seed, so we add the
/// fixed header ourselves.
const PKCS8_PREFIX: [u8; 16] = hex!("302e020100300506032b657004220420");

/// `SubjectPublicKeyInfo` header for an Ed25519 key (RFC 8410 section 4),
/// followed by the 32-byte public key. This is exactly what RFC 7250 puts on
/// the wire in place of a certificate.
const SPKI_PREFIX: [u8; 12] = hex!("302a300506032b6570032100");

/// Ed25519 identity key. TLS authenticates peers with signatures, so unlike
/// the custom protocol the identity key cannot be X25519; X25519 is still
/// used for the TLS 1.3 key exchange.
#[derive(Clone)]
pub struct SecretKey {
    seed: [u8; 32],
}

impl SecretKey {
    pub fn generate() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let seed = ring::rand::generate::<[u8; 32]>(&rng)
            .expect("system RNG failed")
            .expose();
        Self { seed }
    }

    pub fn from_bytes(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    pub fn public_key(&self) -> PublicKey {
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(&self.seed).expect("32-byte seed is always valid");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(key_pair.public_key().as_ref());
        PublicKey(bytes)
    }

    pub(crate) fn pkcs8_der(&self) -> Vec<u8> {
        let mut der = Vec::with_capacity(PKCS8_PREFIX.len() + 32);
        der.extend_from_slice(&PKCS8_PREFIX);
        der.extend_from_slice(&self.seed);
        der
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn spki_der(&self) -> Vec<u8> {
        let mut der = Vec::with_capacity(SPKI_PREFIX.len() + 32);
        der.extend_from_slice(&SPKI_PREFIX);
        der.extend_from_slice(&self.0);
        der
    }

    /// Accepts only an Ed25519 `SubjectPublicKeyInfo`.
    pub(crate) fn from_spki_der(der: &[u8]) -> Option<Self> {
        let key = der.strip_prefix(&SPKI_PREFIX)?;
        let bytes: [u8; 32] = key.try_into().ok()?;
        Some(Self(bytes))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl FromStr for PublicKey {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}
