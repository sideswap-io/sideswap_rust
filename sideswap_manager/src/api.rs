use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sideswap_api::{mkt::QuoteId, OrderId};
use sideswap_common::dealer_ticker::DealerTicker;
use sideswap_types::{duration_ms::DurationMs, timestamp_ms::TimestampMs};

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
pub enum TxStatus {
    Mempool,
    Confirmed,
    NotFound,
}

#[derive(Serialize)]
pub struct MonitoredTx {
    pub txid: elements::Txid,
    pub status: TxStatus,
    pub description: String,
    pub user_note: Option<String>,
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

#[derive(Serialize)]
pub enum TxType {
    Incoming,
    Outgoing,
    Redeposit,
    Swap,
    Unknown,
}

#[derive(Serialize)]
pub struct WalletTx {
    pub txid: elements::Txid,
    pub height: Option<u32>,
    pub balance: BTreeMap<DealerTicker, f64>,
    pub network_fee: u64,
    pub timestamp: Option<TimestampMs>,
    pub tx_type: TxType,
}

#[derive(Serialize)]
pub struct Address {
    pub index: u32,
    pub address: elements::Address,
    pub user_note: Option<String>,
}

// Requests

#[derive(Deserialize)]
pub struct NewAddressReq {
    pub user_note: Option<String>,
}

#[derive(Serialize)]
pub struct NewAddressResp {
    pub index: u32,
    pub address: elements::Address,
}

#[derive(Deserialize)]
pub struct ListAddressesReq {}

#[derive(Serialize)]
pub struct ListAddressesResp {
    pub addresses: Vec<Address>,
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
    pub user_note: Option<String>,
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
    pub user_note: Option<String>,
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

#[derive(Deserialize)]
pub struct DelMonitoredTxReq {
    pub txid: elements::Txid,
}

#[derive(Serialize)]
pub struct DelMonitoredTxResp {}

#[derive(Deserialize)]
pub struct GetWalletTxsReq {}

#[derive(Serialize)]
pub struct GetWalletTxsResp {
    pub txs: Vec<WalletTx>,
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
    NewPeg(NewPegReq),
    DelPeg(DelPegReq),
    NewAddress(NewAddressReq),
    ListAddresses(ListAddressesReq),
    CreateTx(CreateTxReq),
    SendTx(SendTxReq),
    GetQuote(GetQuoteReq),
    AcceptQuote(AcceptQuoteReq),
    GetMonitoredTxs(GetMonitoredTxsReq),
    DelMonitoredTx(DelMonitoredTxReq),
    GetWalletTxs(GetWalletTxsReq),
}

#[derive(Serialize)]
pub enum Resp {
    NewPeg(NewPegResp),
    DelPeg(DelPegResp),
    NewAddress(NewAddressResp),
    ListAddresses(ListAddressesResp),
    CreateTx(CreateTxResp),
    SendTx(SendTxResp),
    GetQuote(GetQuoteResp),
    AcceptQuote(AcceptQuoteResp),
    GetMonitoredTxs(GetMonitoredTxsResp),
    DelMonitoredTx(DelMonitoredTxResp),
    GetWalletTxs(GetWalletTxsResp),
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
