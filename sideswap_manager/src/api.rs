use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sideswap_api::{mkt::QuoteId, OrderId};
use sideswap_common::dealer_ticker::DealerTicker;
use sideswap_types::duration_ms::DurationMs;

#[derive(Debug, Serialize)]
pub enum ErrorCode {
    /// Something wrong with the request arguments
    InvalidRequest,
    /// Server error
    ServerError,
    /// Network error
    NetworkError,
    /// Transaction send failed due to a failed UTXO check.
    /// Since the transaction did not leave the wallet, it is safe to cancel the transaction and try again.
    UtxoCheckFailed,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetails {}

#[derive(Debug, Serialize)]
pub struct Error {
    /// Error message text
    pub text: String,
    /// Error code
    pub code: ErrorCode,
    /// Error details
    pub details: Option<ErrorDetails>,
}

// Common

pub type ReqId = i64;

/// In asset precison
pub type Balances = BTreeMap<DealerTicker, f64>;

#[derive(Serialize)]
pub enum SwapStatus {
    Mempool,
    Confirmed,
    NotFound,
}

#[derive(Serialize)]
pub struct MonitoredTx {
    pub txid: elements::Txid,
    pub status: SwapStatus,
    pub note: String,
}

#[derive(Deserialize)]
pub struct Recipient {
    pub address: elements::Address,
    pub asset: DealerTicker,
    pub amount: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastStatus {
    Success {},
    Error { error_msg: String },
}

// Requests

#[derive(Deserialize)]
pub struct NewAddressReq {}

#[derive(Serialize)]
pub struct NewAddressResp {
    pub address: elements::Address,
}

#[derive(Deserialize)]
pub struct CreateTxReq {
    pub recipients: Vec<Recipient>,
}

#[derive(Serialize)]
pub struct CreateTxResp {
    pub txid: elements::Txid,
    pub network_fee: u64,
}

#[derive(Deserialize)]
pub struct SendTxReq {
    pub txid: elements::Txid,
}

#[derive(Serialize)]
pub struct SendTxResp {
    pub res_wallet: BroadcastStatus,
    pub res_server: BroadcastStatus,
}

#[derive(Deserialize)]
pub struct GetQuoteReq {
    pub send_asset: DealerTicker,
    pub recv_asset: DealerTicker,
    pub send_amount: f64,
    pub receive_address: elements::Address,
}

#[derive(Serialize)]
pub struct GetQuoteResp {
    pub quote_id: QuoteId,
    pub recv_amount: f64,
    pub ttl: DurationMs,
    pub txid: elements::Txid,
}

#[derive(Deserialize)]
pub struct AcceptQuoteReq {
    pub quote_id: QuoteId,
}

#[derive(Serialize)]
pub struct AcceptQuoteResp {
    pub txid: elements::Txid,
}

#[derive(Deserialize)]
pub struct NewPegReq {
    pub recv_addr: String,
    pub peg_in: bool,
    pub blocks: Option<i32>,
}

#[derive(Serialize)]
pub struct NewPegResp {
    pub order_id: OrderId,
    pub peg_addr: String,
}

#[derive(Deserialize)]
pub struct DelPegReq {
    pub order_id: OrderId,
}

#[derive(Serialize)]
pub struct DelPegResp {}

#[derive(Deserialize)]
pub struct GetMonitoredTxsReq {}

#[derive(Serialize)]
pub struct GetMonitoredTxsResp {
    pub txs: Vec<MonitoredTx>,
}

// Notifications

/// Wallet balances
#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct BalancesNotif {
    pub balances: Balances,
}

// Top level WS messages

#[derive(Deserialize)]
pub enum Req {
    NewAddress(NewAddressReq),
    CreateTx(CreateTxReq),
    SendTx(SendTxReq),
    GetQuote(GetQuoteReq),
    AcceptQuote(AcceptQuoteReq),
    GetMonitoredTxs(GetMonitoredTxsReq),
    NewPeg(NewPegReq),
    DelPeg(DelPegReq),
}

#[derive(Serialize)]
pub enum Resp {
    NewAddress(NewAddressResp),
    CreateTx(CreateTxResp),
    SendTx(SendTxResp),
    GetQuote(GetQuoteResp),
    AcceptQuote(AcceptQuoteResp),
    GetMonitoredTxs(GetMonitoredTxsResp),
    NewPeg(NewPegResp),
    DelPeg(DelPegResp),
}

#[derive(Serialize, Clone)]
pub enum Notif {
    Balances(BalancesNotif),
    PegStatus(sideswap_api::PegStatus),
}

#[derive(Deserialize)]
pub enum To {
    Req { id: ReqId, req: Req },
}

#[derive(Serialize)]
pub enum From {
    Resp { id: ReqId, resp: Resp },
    Error { id: ReqId, err: Error },
    Notif { notif: Notif },
}
