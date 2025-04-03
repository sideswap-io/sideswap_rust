use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
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

/// Unique integer ID (based on current timestamp in milliseconds since UNIX epoch)
pub type QuoteId = sideswap_api::mkt::QuoteId;

/// Unique string ID (random 32 bytes in hex encoding)
pub type OrderId = sideswap_api::OrderId;

/// Only selected whitelisted assets can be used here:
/// L-BTC, USDt, EURx, MEX, DePix, AMP assets and some token assets.
/// All asset balances are reported/accepted as floating point numbers using the asset precision.
pub type Ticker = sideswap_common::dealer_ticker::DealerTicker;

/// Wallet balance as float point number in the asset precision.
pub type Balances = BTreeMap<Ticker, f64>;

#[derive(Serialize)]
pub enum TxStatus {
    /// Transaction is in the mempool
    Mempool,
    /// Transaction confirmed on the blockchain
    Confirmed,
    /// Transaction not yet propagated or rejected
    NotFound,
}

#[derive(Serialize)]
pub struct MonitoredTx {
    /// Transaction ID (can be from an accepted swap or an asset send)
    pub txid: elements::Txid,
    /// Transaction status as reported by the used Electrs server
    pub status: TxStatus,
    /// Transaction description. Examples:
    /// "send 0.0001 L-BTC to vjU3KGnCKrsZkVPMTzTBo31fPrcXpqNsyoSAEvLP2apepS1JZqvN69oj4deXt3AiBuY1ZjzRCdLkb1aQ"
    /// "swap 10 USDt for 0.0001163 L-BTC to tlq1qqt8je396rxrga980wxrmvgnafld0cvxsk0df0d84pqns4lhndnqdq986krfnkg342jnqzvs7u2j9eqk6kpncyfqyq6l0zrd9m"
    pub description: String,
    /// Optional user note when the transaction was created
    pub user_note: Option<String>,
}

#[derive(Deserialize)]
pub struct Recipient {
    /// Recipient address. Must be confidential Liquid Bitcoin address.
    pub address: elements::Address,
    /// Asset to send
    pub asset: Ticker,
    /// Asset amount as a floating point number (in asset precision)
    pub amount: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastStatus {
    /// Broadcast succeed
    Success {},
    /// Broadcast failed. See `error_msg` for details.
    Error {
        /// Error text as returned by the backend (or network error).
        error_msg: String,
    },
}

#[derive(Serialize)]
pub enum TxType {
    /// Incoming transaction (one or more positive balances received)
    Incoming,
    /// Outgoing transaction (one or more negative balances detected)
    Outgoing,
    /// Internal wallet transaction (net wallet balance change == - network fee)
    Redeposit,
    /// One asset received and one asset sent
    Swap,
    /// All other transactions
    Unknown,
}

/// Wallet transaction from the Liquid Bitcoin network as reported by LWK
#[derive(Serialize)]
pub struct WalletTx {
    /// Transaction id
    pub txid: elements::Txid,
    /// The height of the block in which the transaction is included.
    /// None if the transaction is in the mempool.
    pub height: Option<u32>,
    /// Net change in the wallet balance (only whitelisted assets) in the asset precisions
    pub balance: BTreeMap<Ticker, f64>,
    /// Network fee in sats
    pub network_fee: u64,
    /// Transaction timestamp
    pub timestamp: Option<TimestampMs>,
    /// Transaction type determined from the balance change
    pub tx_type: TxType,
}

#[derive(Serialize)]
pub struct Address {
    /// Index in the address derivation path
    pub index: u32,
    /// Confidential Liquid Bitcoin address
    pub address: elements::Address,
    /// Optional user note when the address was generated
    pub user_note: Option<String>,
}

#[derive(Debug, Copy, Clone, Serialize)]
pub enum PegTxState {
    /// Peg amount is less than the minimum and will not be processed
    InsufficientAmount,
    /// The peg transaction has been detected and the server is waiting for the transaction to be confirmed
    Detected,
    /// The server is processing the transaction
    Processing,
    /// The server has made the payment
    Done,
}

#[derive(Debug, Clone, Serialize)]
pub struct PegTxStatus {
    /// Txid of the user's payment.
    pub tx_hash: sideswap_api::Hash32,
    /// Output index of the user's payment.
    pub vout: u32,
    /// How much the user has paid (in bitcoins)
    pub peg_amount: f64,
    /// How much will be paid or has been paid (in bitcoins).
    /// Will be empty if `tx_state` is InsufficientAmount.
    pub payout_amount: Option<f64>,
    /// Peg state
    pub tx_state: PegTxState,
    /// How many confirmations are required before a payment is initiated.
    /// Set if and only if `tx_state` is `Detected`.
    pub detected_confs: Option<u32>,
    /// Set if and only if `tx_state` is `Detected`.
    pub total_confs: Option<u32>,
    /// Timestamp of when the peg transaction was detected
    pub created_at: TimestampMs,
    /// Payout txid (Liquid Bitcoin for peg-ins and Bitcoin for peg-outs).
    /// Set if and only if `tx_state` is `Done`.
    pub payout_txid: Option<sideswap_api::Hash32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PegStatus {
    /// Peg order id
    pub order_id: OrderId,
    /// true for peg-ins, false for peg-outs
    pub peg_in: bool,
    /// Server address to send funds (bitcoin for peg-ins, liquid bitcoin for peg-outs)
    pub addr_server: String,
    /// User's address to receive funds (liquid bitcoin for peg-ins, bitcoin for peg-outs).
    pub addr_recv: String,
    /// List of detected user transactions (can have more than one transaction).
    /// Will be empty for new peg requests.
    pub list: Vec<PegTxStatus>,
    /// Timestamp of when the order was created
    pub created_at: TimestampMs,
    /// Optional user-submitted return address used for `InsufficientAmount` peg-outs
    pub return_address: Option<String>,
}

// Requests

/// NewAddress request
///
/// The application searches for the first unused index in the blockchain and the first unused index in the DB,
/// and returns the largest value of the two. There is a gap limit of 20 consecutive unused addresses,
/// starting from the last address seen in the blockchain. Once this limit is reached,
/// no new addresses can be generated and an error is returned.
/// If the request succeeds, the new index, address and user note are stored in the DB.
#[derive(Deserialize)]
pub struct NewAddressReq {
    /// Optional user note to store in the DB.
    /// It will not be transmitted to the Liquid Bitcoin network.
    pub user_note: Option<String>,
}

/// NewAddress response
#[derive(Serialize)]
pub struct NewAddressResp {
    /// Index in the address derivation path
    pub index: u32,
    /// Confidential Liquid Bitcoin address derived from the mnemonic.
    /// Addresses can be reused and can receive any assets.
    /// But only whitelisted assets will be reported by the manager.
    pub address: elements::Address,
}

/// ListAddresses request
///
/// Load all addresses from the DB that were previously returned in the NewAddress response.
#[derive(Deserialize)]
pub struct ListAddressesReq {}

/// ListAddresses response
#[derive(Serialize)]
pub struct ListAddressesResp {
    /// The address list from the DB.
    /// If the mnemonic was used previously, there may be gaps and the index may not start at 0.
    pub addresses: Vec<Address>,
}

/// CreateTx request
///
/// Construct a Liquid Bitcoin transaction to send whitelisted assets to the selected list of recipients.
/// Only confidential addresses are allowed.
/// The request will return an error if there is a fractional remainder after converting to sats
/// (e.g. trying to send 0.000000015 L-BTC or 10.5 PPRGB will return an error).
/// The wallet must have enough UTXOs to send the selected asset and pay the network fee in L-BTC.
/// The created transaction is signed and then stored internally.
/// It's not saved to disk or sent to the network.
#[derive(Deserialize)]
pub struct CreateTxReq {
    /// The list of recipients
    pub recipients: Vec<Recipient>,
}

/// CreateTx response
#[derive(Serialize)]
pub struct CreateTxResp {
    /// Transaction ID of the created transaction
    pub txid: elements::Txid,
    /// Network fee (in L-sats) of the created transaction
    pub network_fee: u64,
}

/// SendTx request
/// Try sending a previously created transaction to the Liquid Network.
///
/// Sending a transaction works like this:
/// - The manager checks if the transaction inputs are still available in the wallet's UTXOs.
/// If not, the `UtxoCheckFailed` error is returned.
/// - If `wallet_only` is `false`, the manager sends a request to the SideSwap server to check
///  if the transaction inputs are known/unspent. If the request fails for any reason, the `UtxoCheckFailed` error is returned.
/// - A new DB record is created for the monitored transaction.
/// - If `wallet_only` is false, the manager sends a request to the SideSwap server to broadcast the signed transaction to the network. If the request fails for any reason, the `SendTx` request will succeed but the error will be returned in the `res_server` response field.
/// - The manager sends the request to the used Electrs server to broadcast the signed transaction. If the request fails for any reason, the `SendTx` request will succeed but the error will be returned in the `res_wallet` response field.
/// - All previously created transactions are deleted.
///
/// The client should call the `CreateTx` and `SendTx` requests in the correct order.
/// If a `SendTx` request succeeds, all previously created transactions will be deleted.
/// If the request succeeds, the client should check the `res_wallet` and `res_server` values.
/// If both values indicate success, then the transaction is likely to succeed and be added
/// to the blockchain (but there is a chance that it will be rejected or ignored for some reason).
/// If both values are false, then the transaction will likely fail
/// (but there is a small chance that it will succeed).
/// If one value indicates success and one indicates failure, the transaction may succeed or fail.
/// If the request fails and returns the `UtxoCheckFailed` error code, it's safe to retry
/// or abandon the transaction.
/// If the request fails and returns the `InvalidRequest` error code, it means that
/// the transaction ID is not known. This can happen if another `SendTx` request was sent earlier.
/// If the request fails for any other reason, the transaction may succeed or fail.
/// In all cases (unless the request fails with an `UtxoCheckFailed` or `InvalidRequest` error),
/// the manager will create a DB record before attempting to broadcast the transaction
/// and the transaction status can be retrieved later with the `GetMonitoredTxs` request.
#[derive(Deserialize)]
pub struct SendTxReq {
    /// Transaction ID returned in the CreateTx response
    pub txid: elements::Txid,
    /// Optional user note to be stored in the DB.
    /// It will not be transmitted to the Liquid Bitcoin network.
    pub user_note: Option<String>,
    /// If true, do not use the SideSwap server to check UTXOs and send the raw transaction.
    /// Value is optional (default is false).
    #[serde(default)]
    pub wallet_only: bool,
}

/// SendTx response
#[derive(Serialize)]
pub struct SendTxResp {
    /// The broadcast status returned by the Electrs server
    pub res_wallet: BroadcastStatus,
    /// The broadcast status returned by the SideSwap server (set if `wallet_only` is `false`)
    pub res_server: Option<BroadcastStatus>,
}

/// GetQuote request
///
/// Request a quote from the SideSwap swap market (the market must already exist and have public orders).
/// If no matching orders are found, an error will be returned.
/// Server and fixed fees are included in these amounts.
/// The upstream WebSocket connection to the SideSwap server must already be up.
#[derive(Deserialize)]
pub struct GetQuoteReq {
    /// Which asset to sell
    pub send_asset: Ticker,
    /// Which asset to buy
    pub recv_asset: Ticker,
    /// Exact amount of how much you will spend (in the selected asset precision).
    /// If the quoted amount is less than this an error is returned.
    pub send_amount: f64,
    /// The address that will receive the `recv_asset` asset.
    /// This can be any address, not necessarily the wallet address.
    pub receive_address: elements::Address,
}

/// GetQuote response
#[derive(Serialize)]
pub struct GetQuoteResp {
    /// Quote ID
    pub quote_id: QuoteId,
    /// Exactly how much you will receive
    pub recv_amount: f64,
    /// TTL period of the received quote (about 30 seconds).
    /// The quote can only be accepted within this time period.
    pub ttl: DurationMs,
    /// Transaction ID of the atomic swap transaction
    pub txid: elements::Txid,
}

/// AcceptQuote request
///
/// Accepting a quote works like this:
/// - The manager will verify that the quote exists and that the TTL is valid.
/// - A new DB record is created for the monitored transaction.
/// - The manager will send request to the SideSwap backend.
///
/// If the request fails and returns the `InvalidRequest` error code, it means that
/// the quote ID is not known or it already expired. A new quote should be requested.
/// In all other cases (whether the request succeeds or fails),
/// the client should check the status of the swap transaction using the `GetMonitoredTxs` request.
#[derive(Deserialize)]
pub struct AcceptQuoteReq {
    /// Quote ID
    pub quote_id: QuoteId,
    /// Optional user note to be stored in the DB.
    /// It will not be transmitted to the Liquid Bitcoin network.
    pub user_note: Option<String>,
}

/// AcceptQuote response
#[derive(Serialize)]
pub struct AcceptQuoteResp {
    /// Transaction ID of the swap transaction
    pub txid: elements::Txid,
}

/// NewPeg request
///
/// Register a new peg-in or peg-out on the server.
/// If the request fails due to network errors, it's safe to retry.
/// If successful, the order ID will be stored in the DB.
#[derive(Deserialize)]
pub struct NewPegReq {
    /// The address that will receive converted BTC or L-BTC
    pub addr_recv: String,
    /// Peg-in (true) or peg-out (false).
    /// Peg-ins are used to convert from bitcoin to liquid bitcoin,
    /// peg-outs are from liquid bitcoin to bitcoin.
    pub peg_in: bool,
}

/// NewPeg response
#[derive(Serialize)]
pub struct NewPegResp {
    /// Peg status (the `list` field will be empty)
    pub peg: PegStatus,
}

/// DelPeg request
///
/// Send the `DelPeg` request when receiving a peg status update is no longer needed.
/// The peg order will be removed from the local DB, but not from the server.
/// Peg status updates will not be sent after that.
#[derive(Deserialize)]
pub struct DelPegReq {
    pub order_id: OrderId,
}

/// DelPeg response
#[derive(Serialize)]
pub struct DelPegResp {}

/// GetMonitoredTxs request
///
/// Load all previously registered send and swap transactions and their wallet status.
#[derive(Deserialize)]
pub struct GetMonitoredTxsReq {}

/// GetMonitoredTxs response
#[derive(Serialize)]
pub struct GetMonitoredTxsResp {
    /// The list of registered in the local DB transactions
    pub txs: Vec<MonitoredTx>,
}

/// DelMonitoredTx request
///
/// Use this request to remove the registered transaction from the local DB. The transaction will not be removed from the wallet transactions (if it exists), but it will be removed from the `GetMonitoredTxs` response. It can be used with completed transactions.
#[derive(Deserialize)]
pub struct DelMonitoredTxReq {
    pub txid: elements::Txid,
}

/// DelMonitoredTx response
#[derive(Serialize)]
pub struct DelMonitoredTxResp {}

/// GetWalletTxs
///
/// Load all wallet transactions as reported by the Electrs server.
#[derive(Deserialize)]
pub struct GetWalletTxsReq {}

/// GetWalletTxs response
#[derive(Serialize)]
pub struct GetWalletTxsResp {
    /// Currenlty loaded wallet transactions
    pub txs: Vec<WalletTx>,
}

// Notifications

/// Wallet balances
///
/// The notification is sent to newly connected clients
/// and to all connected clients when the wallet balance changes.
#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct BalancesNotif {
    /// Wallet balances
    pub balances: Balances,
}

/// Peg status
///
/// When the upstream SideSwap server connects, all peg orders stored in the DB are requested
/// and their status is reported to the connected users.
/// When a new client connects, all current peg statuses are sent to that connection.
/// This way all connected clients have the latest status of all pegs.
#[derive(Debug, Serialize, Clone)]
pub struct PegStatusNotif {
    /// Peg status
    pub peg: PegStatus,
}

// Top level WS messages

/// Request messages
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

/// Response messages
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

/// Notification messages
#[derive(Serialize, Clone)]
pub enum Notif {
    Balances(BalancesNotif),
    PegStatus(PegStatusNotif),
}

/// The message sent by clients via WebSocket connection to the manager
#[derive(Deserialize)]
pub enum To {
    Req { id: ReqId, req: Req },
}

/// The message sent to clients via WebSocket connection from the manager
#[derive(Serialize)]
pub enum From {
    Resp { id: ReqId, resp: Resp },
    Error { id: ReqId, err: Error },
    Notif { notif: Notif },
}
