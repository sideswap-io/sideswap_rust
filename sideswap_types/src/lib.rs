use hex_encoded::HexEncoded;

pub mod asset_precision;
pub mod b64;
pub mod bitcoin_amount;
pub mod byte_array;
pub mod chain;
pub mod const_asset_id;
pub mod duration_ms;
pub mod duration_sec;
pub mod enum_utils;
pub mod env;
pub mod error_utils;
pub mod fee_rate;
pub mod hex_encoded;
pub mod network;
pub mod normal_float;
pub mod proxy_address;
pub mod retry_delay;
pub mod signer_api;
pub mod str_encoded;
pub mod timestamp_ms;
pub mod timestamp_us;
pub mod unconfidential_address;
pub mod utxo_ext;

pub type AssetHex = HexEncoded<elements::confidential::Asset>;
pub type ValueHex = HexEncoded<elements::confidential::Value>;

pub type TransactionHex = HexEncoded<elements::Transaction>;
