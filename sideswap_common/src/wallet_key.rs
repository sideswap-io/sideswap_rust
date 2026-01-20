use elements::{
    bitcoin::{self, secp256k1::Message},
    hashes::{Hash, HashEngine},
    schnorr::{Keypair, XOnlyPublicKey},
    secp256k1_zkp::{self, SECP256K1},
};

pub struct WalletKey {
    keypair: Keypair,
}

use bitcoin::hashes::sha256t_hash_newtype;
use sideswap_types::network::Network;

sha256t_hash_newtype! {
    pub struct WalletKeyTag = hash_str("sideswap/wallet_key");
    pub struct WalletKeyHash(_);
}

sha256t_hash_newtype! {
    pub struct WalletSignTag = hash_str("sideswap/sign");
    pub struct WalletSignHash(_);
}

pub fn get_sign_message_hash(challenge: &str) -> Message {
    let text = format!("sideswap login, nonce: {challenge}");
    let hash = WalletSignHash::hash(text.as_bytes());
    Message::from_digest(hash.to_byte_array())
}

fn network_salt(network: Network) -> &'static [u8; 32] {
    match network {
        Network::Liquid => {
            &hex_literal::hex!("3f101e5de26db05ca3b4dc4e964b7889ff4bcb7006a89b14f5c9f5b7970b66db")
        }
        Network::LiquidTestnet => {
            &hex_literal::hex!("54151998bcf5347784eeda549407815d3390742d451221416a65a3ed7d739a34")
        }
        Network::Regtest => {
            &hex_literal::hex!("c96036d788d756a16fdfb427bc70d0b681315224c3d1c12cc9efc6ace2358c13")
        }
    }
}

impl WalletKey {
    pub fn new(master_blinding_key: &[u8], network: Network) -> WalletKey {
        let mut engine = WalletKeyHash::engine();
        engine.input(network_salt(network));
        engine.input(master_blinding_key);
        let secret_key = WalletKeyHash::from_engine(engine).to_byte_array();

        let keypair = elements::secp256k1_zkp::Keypair::from_seckey_slice(SECP256K1, &secret_key)
            .expect("must not fail");

        WalletKey { keypair }
    }

    pub fn public_key(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
    }

    pub fn sign_challenge(&self, challenge: &str) -> secp256k1_zkp::schnorr::Signature {
        let message = get_sign_message_hash(challenge);
        SECP256K1.sign_schnorr(&message, &self.keypair)
    }
}
