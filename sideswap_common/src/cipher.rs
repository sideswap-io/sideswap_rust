pub trait Cipher {
    type Error: std::error::Error + 'static;

    fn encrypt(&mut self, data: &[u8]) -> Vec<u8>;

    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

pub mod aes;

pub enum Info {}

impl Info {
    pub fn data() {}
}

/// ikm - input key material, must be a high‑entropy secret (not a password)
/// info - descriptive label for domain separation (constant)
pub fn derive_key(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("must not fail");
    okm
}

#[cfg(test)]
mod tests;
