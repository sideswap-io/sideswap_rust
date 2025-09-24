use serde::{Deserialize, Serialize};

use super::{RpcCall, RpcRequest};

#[derive(Debug, Serialize)]
pub struct WalletProcessPsbtCall {
    pub psbt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign: Option<bool>,
    // pub sighashtype: Option<String>,
    // pub bip32derivs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalize: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct WalletProcessPsbtResp {
    pub psbt: String,
    pub complete: bool,
}

impl RpcCall for WalletProcessPsbtCall {
    type Response = WalletProcessPsbtResp;

    fn get_request(self) -> RpcRequest {
        RpcRequest {
            method: "walletprocesspsbt".to_owned(),
            params: serde_json::to_value(&self).expect("must not fail"),
        }
    }
}
