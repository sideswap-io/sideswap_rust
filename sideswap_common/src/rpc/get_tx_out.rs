use serde::{Deserialize, Serialize};
use sideswap_types::bitcoin_amount::BtcAmount;

use super::{RpcCall, RpcRequest};

#[derive(Debug, Serialize)]
pub struct GetTxOutCall {
    pub txid: elements::Txid,
    pub n: u32,
    pub include_mempool: bool,
}

#[derive(Debug, Deserialize)]
pub struct GetTxOutValue {
    pub bestblock: String,
    pub confirmations: i32,
    pub coinbase: bool,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: super::ScriptPubKey,
    pub valuecommitment: Option<elements::secp256k1_zkp::PedersenCommitment>,
    pub assetcommitment: Option<elements::secp256k1_zkp::Generator>,
    pub value: Option<BtcAmount>,
    pub asset: Option<elements::AssetId>,
}

pub type GetTxOutCallResp = Option<GetTxOutValue>;

impl RpcCall for GetTxOutCall {
    type Response = GetTxOutCallResp;

    fn get_request(self) -> RpcRequest {
        RpcRequest {
            method: "gettxout".to_owned(),
            params: serde_json::to_value(&self).expect("must not fail"),
        }
    }
}
