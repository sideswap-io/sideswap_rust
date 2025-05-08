use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::error::fn_err;
use aes_gcm_siv::aead::{AeadInPlace, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use bitcoin::bip32::Xpub;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Network, NetworkKind};
use rand::Rng;

use crate::Result;

pub trait Decryptable {
    fn decrypt(self, cipher: &Aes256GcmSiv) -> Result<Vec<u8>>;
}

impl Decryptable for &mut File {
    fn decrypt(self, cipher: &Aes256GcmSiv) -> Result<Vec<u8>> {
        let mut buf = Vec::<u8>::new();
        self.seek(SeekFrom::Start(0))?;
        self.read_to_end(&mut buf)?;
        buf.decrypt(cipher)
    }
}

impl Decryptable for Vec<u8> {
    fn decrypt(self, cipher: &Aes256GcmSiv) -> Result<Vec<u8>> {
        let mut iter = self.into_iter();

        let nonce = Nonce::from_exact_iter(iter.by_ref().take(12))
            .ok_or_else(fn_err("vector should be longer than 12 bytes"))?;
        let mut rest = iter.collect::<Vec<_>>();

        cipher.decrypt_in_place(&nonce, b"", &mut rest)?;
        Ok(rest)
    }
}

pub trait Encryptable {
    fn encrypt(self, key: &Aes256GcmSiv) -> Result<([u8; 12], Vec<u8>)>;
}

impl Encryptable for Vec<u8> {
    fn encrypt(mut self, cipher: &Aes256GcmSiv) -> Result<([u8; 12], Vec<u8>)> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        cipher.encrypt_in_place(nonce, b"", &mut self)?;
        Ok((nonce_bytes, self))
    }
}

pub trait ToCipher {
    fn to_cipher(self) -> Result<Aes256GcmSiv>;
}

impl ToCipher for Xpub {
    fn to_cipher(self) -> Result<Aes256GcmSiv> {
        let mut enc_key_data = vec![];
        enc_key_data.extend(&self.to_pub().to_bytes());
        enc_key_data.extend(&self.chain_code.to_bytes());
        let mut v = match self.network {
            NetworkKind::Main => Network::Bitcoin.magic(),
            NetworkKind::Test => Network::Testnet.magic(),
        }
        .to_bytes()
        .to_vec();
        v.reverse(); // test_hardcoded_decryption fail otherwise
        enc_key_data.extend(&v);
        let hash = sha256::Hash::hash(&enc_key_data);
        let key_bytes = hash.as_ref();
        let key = Key::from_slice(&key_bytes);
        Ok(Aes256GcmSiv::new(&key))
    }
}
