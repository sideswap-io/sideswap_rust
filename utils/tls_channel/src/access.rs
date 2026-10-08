use std::collections::HashSet;
use std::sync::Mutex;

use crate::keys::PublicKey;

/// Decides, during the TLS handshake, whether a client public key is
/// accepted. Rejected clients never get a [`crate::Channel`]; the server's
/// [`crate::Incoming::handshake`] returns [`crate::Error::ClientRejected`]
/// instead and the client sees a TLS alert.
pub trait IsClientValid: Send + Sync {
    fn is_client_valid(&self, public_key: &PublicKey) -> bool;
}

/// Simple allow list that can be changed at runtime.
#[derive(Debug, Default)]
pub struct AllowedClients {
    keys: Mutex<HashSet<PublicKey>>,
}

impl AllowedClients {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the key was not in the list before.
    pub fn add(&self, public_key: PublicKey) -> bool {
        self.keys.lock().unwrap().insert(public_key)
    }

    /// Returns `true` if the key was in the list.
    pub fn remove(&self, public_key: &PublicKey) -> bool {
        self.keys.lock().unwrap().remove(public_key)
    }

    pub fn contains(&self, public_key: &PublicKey) -> bool {
        self.keys.lock().unwrap().contains(public_key)
    }

    pub fn len(&self) -> usize {
        self.keys.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FromIterator<PublicKey> for AllowedClients {
    fn from_iter<I: IntoIterator<Item = PublicKey>>(iter: I) -> Self {
        Self {
            keys: Mutex::new(iter.into_iter().collect()),
        }
    }
}

impl IsClientValid for AllowedClients {
    fn is_client_valid(&self, public_key: &PublicKey) -> bool {
        self.contains(public_key)
    }
}
