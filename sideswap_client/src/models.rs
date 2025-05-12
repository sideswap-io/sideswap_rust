use std::collections::BTreeMap;

use elements::TxOutSecrets;
use serde::{Deserialize, Serialize};
use sideswap_api::{AssetBlindingFactor, AssetId, ValueBlindingFactor};
use sideswap_common::utxo_select::WalletType;
use sideswap_types::timestamp_ms::TimestampMs;

#[derive(PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug, Clone, Copy)]
pub enum AddressType {
    /// Native seg-wit (single-sig)
    #[serde(rename = "p2wpkh")]
    P2wpkh,

    /// Nested seg-wit (single-sig)
    #[serde(rename = "p2sh-p2wpkh")]
    P2shP2wpkh,

    /// AMP (for some reasons GDK returns "p2wsh" for AMP accounts, let's do the same)
    #[serde(rename = "p2wsh")]
    P2wsh,
}

impl From<WalletType> for AddressType {
    fn from(value: WalletType) -> Self {
        match value {
            WalletType::Native => AddressType::P2wpkh,
            WalletType::Nested => AddressType::P2shP2wpkh,
            WalletType::AMP => AddressType::P2wsh,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Address {
    pub address: elements::Address,
    pub pointer: u32,
    pub is_internal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputOutput {
    pub unblinded: TxOutSecrets,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub txid: elements::Txid,
    pub network_fee: u64,
    pub vsize: usize,
    pub created_at: TimestampMs,
    pub block_height: u32,
    /// Only own inputs here (is_relevant = true)
    pub inputs: Vec<InputOutput>,
    /// Only own outputs here (is_relevant = true)
    pub outputs: Vec<InputOutput>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Utxo {
    pub wallet_type: WalletType,
    #[allow(dead_code)]
    pub block_height: u32,
    pub txhash: elements::Txid,
    pub vout: u32,
    pub pointer: u32,

    pub is_internal: bool,
    pub is_blinded: bool,

    /// Examples:
    ///
    /// Single-sig (nested and native):
    /// hex: 76a914e4f0c3354d77e98aa4a4efc6e9f74c9c43dcf10588ac
    /// asm: OP_DUP OP_HASH160 e4f0c3354d77e98aa4a4efc6e9f74c9c43dcf105 OP_EQUALVERIFY OP_CHECKSIG
    ///
    /// AMP:
    /// hex: 522102486b26fc1efc13d1a33583ffc9f12ba848669ccbb2d3970ee675efc632d8ea682102dc3d739c32fd0812c15d929b51560ae457d3242a105132c5e1b7c51cb5dcbea252ae
    /// asm: 2 02486b26fc1efc13d1a33583ffc9f12ba848669ccbb2d3970ee675efc632d8ea68 02dc3d739c32fd0812c15d929b51560ae457d3242a105132c5e1b7c51cb5dcbea2 2 OP_CHECKMULTISIG
    pub prevout_script: elements::Script,

    pub asset_id: elements::AssetId,
    pub satoshi: u64,

    pub asset_commitment: elements::confidential::Asset,
    pub value_commitment: elements::confidential::Value,

    pub assetblinder: AssetBlindingFactor,
    pub amountblinder: ValueBlindingFactor,

    /// Present in multi-sig only.
    /// Example:
    /// hex: a914ee1d154d0409d8b359575bf1a1ef76d562557fc687
    /// asm: OP_HASH160 ee1d154d0409d8b359575bf1a1ef76d562557fc6 OP_EQUAL
    pub script_pub_key: elements::Script,

    pub public_key: Option<elements::bitcoin::PublicKey>, // Present in single-sig only
    pub user_path: Option<Vec<u32>>,                      // Present in single-sig only
}

pub type UtxoList = BTreeMap<AssetId, Vec<Utxo>>;

// NOTE: Do not make incompatible changes, the data can be saved in the settings file!
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddressInfo {
    pub address: elements::Address,
    pub address_type: AddressType,
    pub pointer: u32,
    pub user_path: Vec<u32>,

    // Single-sig only:
    pub is_internal: Option<bool>,
    pub public_key: Option<elements::bitcoin::PublicKey>,

    // Normally AMP only, example: 52210305b9d4acd4c6cd5a5a9eb5e9a4dcd74a7b962eb0109cab264ea7412d6901bfa42102945512944638fe25e24962866d19ec858fdc70dd5a68ae801d54b5c36231f2e652ae
    pub prevout_script: Option<elements::Script>,
    pub service_xpub: Option<String>,
}
