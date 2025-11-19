use serde::{Deserialize, Serialize};

use super::{RpcCall, RpcRequest};

#[derive(Debug, Serialize)]
pub struct GetTransactionCall {
    pub txid: elements::Txid,
}

#[derive(Debug, Deserialize)]
pub struct GetTransactionResp {
    pub txid: elements::Txid,

    /// The number of confirmations for the transaction.
    /// Negative confirmations means the transaction conflicted that many blocks ago.
    pub confirmations: i32,

    /// The block time expressed in UNIX timestamp
    pub blocktime: Option<i64>,

    /// The transaction time expressed in UNIX epoch time
    pub time: i64,

    /// Raw data for transaction
    pub hex: String,
}

impl RpcCall for GetTransactionCall {
    type Response = GetTransactionResp;

    fn get_request(self) -> RpcRequest {
        RpcRequest {
            method: "gettransaction".to_owned(),
            params: serde_json::to_value(&self).expect("must not fail"),
        }
    }
}
