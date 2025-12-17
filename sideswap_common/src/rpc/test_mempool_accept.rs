use serde::Deserialize;
use sideswap_types::{abort, verify};
use ureq::json;

use crate::rpc::{RpcCall, RpcRequest, RpcServer, make_rpc_call};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("request failed: {0}")]
    Request(anyhow::Error),
    #[error("invalid mempool test result")]
    InvalidResult,
    #[error("transaction rejected, txid: {txid}, reason: {reason}")]
    TxRejected {
        txid: elements::Txid,
        reason: String,
    },
    #[error("transaction rejected with unknown reason, txid: {txid}")]
    UnknownReason { txid: elements::Txid },
}

// Use `test_mempool_accepted` instead (to not forget to check the `allowed` value)
struct TestMempoolAcceptedCall {
    rawtxs: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct TestMempoolAcceptValue {
    pub txid: elements::Txid,
    pub allowed: Option<bool>,
    #[serde(rename = "reject-reason")]
    pub reject_reason: Option<String>,
}

impl RpcCall for TestMempoolAcceptedCall {
    type Response = Vec<TestMempoolAcceptValue>;

    fn get_request(self) -> RpcRequest {
        RpcRequest {
            method: "testmempoolaccept".to_owned(),
            params: vec![json!(self.rawtxs)].into(),
        }
    }
}

pub async fn test_mempool_accepted_list(
    rpc_server: &RpcServer,
    txs: Vec<String>,
) -> Result<Vec<elements::Txid>, Error> {
    let count = txs.len();
    let check_acceptence = make_rpc_call(rpc_server, TestMempoolAcceptedCall { rawtxs: txs })
        .await
        .map_err(Error::Request)?;

    verify!(check_acceptence.len() == count, Error::InvalidResult);

    for resp in check_acceptence.iter() {
        if let Some(reject_reason) = &resp.reject_reason {
            abort!(Error::TxRejected {
                txid: resp.txid,
                reason: reject_reason.clone()
            });
        }
    }

    let mut txids = Vec::new();
    for resp in check_acceptence.into_iter() {
        verify!(
            resp.allowed.unwrap_or_default(),
            Error::UnknownReason { txid: resp.txid }
        );
        txids.push(resp.txid);
    }

    Ok(txids)
}

pub async fn test_mempool_accepted(
    rpc_server: &RpcServer,
    tx: String,
) -> Result<elements::Txid, Error> {
    let resp = test_mempool_accepted_list(rpc_server, vec![tx]).await?;
    Ok(resp[0].clone())
}
