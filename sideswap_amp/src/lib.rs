// TODO: Switch from JSON to msgpack

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    sync::Arc,
    time::{Duration, Instant},
    vec,
};

use bitcoin::{
    bip32::{ChildNumber, Xpub},
    hashes::Hash,
};
use elements::{
    confidential::{AssetBlindingFactor, ValueBlindingFactor},
    pset::PartiallySignedTransaction,
    secp256k1_zkp::global::SECP256K1,
    Address, AssetId, TxOutSecrets, Txid,
};
use elements_miniscript::slip77::MasterBlindingKey;
use futures::{SinkExt, StreamExt};
use secp256k1::ecdsa::Signature;
use serde::Serialize;
use sideswap_common::{
    abort,
    channel_helpers::UncheckedOneshotSender,
    network::Network,
    pset_blind::get_blinding_nonces,
    recipient::Recipient,
    retry_delay::RetryDelay,
    send_tx::pset::{construct_pset, ConstructPsetArgs, ConstructedPset, PsetInput, PsetOutput},
    utxo_select::{self, ChangeWallets, WalletType},
    verify,
};
use sideswap_types::{proxy_address::ProxyAddress, timestamp_us::TimestampUs, utxo_ext::UtxoExt};
use sw_signer::SwSigner;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};
use tokio_tungstenite::tungstenite;
use tx_cache::TxCache;
use wamp::common::{WampArgs, WampString};

use crate::wamp::{
    common::{Arg, WampDict, WampId},
    message::Msg,
};

#[allow(unused)]
mod models;
mod wamp;

pub mod sw_signer;
pub mod tx_cache;

const DEFAULT_AGENT_STR: &str = "sideswap_amp";

const AMP_SUBACCOUNT_DEFAULT_NAME: &str = "AMP";

const AMP_SUBACCOUNT_TYPE: &str = "2of2_no_recovery";

#[derive(Debug)]
pub enum Event {
    Connected {
        gaid: String,
        subaccount: u32,
        block_height: u32,
    },
    Disconnected,
    BalanceUpdated {
        balances: BTreeMap<AssetId, u64>,
    },
    NewBlock {
        block_height: u32,
    },
    NewTx {
        txid: Txid,
    },
}

#[derive(Clone)]
pub struct Wallet {
    command_sender: UnboundedSender<Command>,
    policy_asset: AssetId,
    master_blinding_key: MasterBlindingKey,
    watch_only: bool,
}

pub enum SignAction {
    SignOnly,
    SignAndBroadcast,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("channel was closed sending {0}")]
    SendError(&'static str),
    #[error("channel was closed receiving")]
    RecvError,
    #[error("parsing failed for {0}: {1}")]
    BackendMsgPackError(&'static str, rmp_serde::decode::Error),
    #[error("unexpected arguments count: {0}, expected at least {1} elements")]
    BackendUnexpectedCount(usize, usize),
    #[error("send amount can't be 0")]
    ZeroSendAmount,
    #[error("amount overflow")]
    AmountOverflow,
    #[error(
        "not enough amount for asset {asset_id}, required: {required}, available: {available}"
    )]
    NotEnoughAmount {
        asset_id: AssetId,
        required: u64,
        available: u64,
    },
    #[error("blind error: {0}")]
    BlindError(#[from] sideswap_common::pset_blind::Error),
    #[error("WS error: {0}")]
    WsError(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("protocol error: {0}")]
    ProtocolError(&'static str),
    #[error("wamp error: {context}: {error}")]
    WampError {
        context: &'static str,
        error: String,
    },
    // #[error("script_sig or redeem_script for {0}:{1}")]
    // NoRedeem(Txid, u32),
    #[error("PSET error: {0}")]
    PsetError(#[from] elements::pset::Error),
    #[error("request timeout")]
    RequestTimeout,
    #[error("HTTP connection error: {0}")]
    HttpConnectionError(#[from] tungstenite::http::Error),
    #[error("signer error: {0}")]
    Signer(String),
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("user not found or invalid password")]
    WrongWatchOnlyPassword,
    #[error("proxy error: {0}")]
    ProxyError(#[from] tokio_socks::Error),
}

impl Error {
    /// If the error is fatal and reconnect is not needed
    pub fn is_fatal(&self) -> bool {
        match self {
            Error::Signer(_)
            | Error::WrongWatchOnlyPassword
            | Error::BackendMsgPackError(_, _)
            | Error::BackendUnexpectedCount(_, _) => true,

            Error::SendError(_)
            | Error::RecvError
            | Error::ZeroSendAmount
            | Error::AmountOverflow
            | Error::NotEnoughAmount { .. }
            | Error::BlindError(_)
            | Error::WsError(_)
            | Error::ProtocolError(_)
            | Error::WampError { .. }
            // | Error::NoRedeem(_, _)
            | Error::PsetError(_)
            | Error::RequestTimeout
            | Error::HttpConnectionError(_)
            | Error::InsufficientFunds | Error::ProxyError(_) => false,
        }
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for Error {
    fn from(value: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Error::SendError(std::any::type_name_of_val(&value))
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for Error {
    fn from(_value: tokio::sync::oneshot::error::RecvError) -> Self {
        Error::RecvError
    }
}

type ResSender<T> = UncheckedOneshotSender<Result<T, Error>>;

enum Command {
    ReceiveAddress(ResSender<AddressInfo>),
    PreviousAddresses(ResSender<Vec<AddressInfo>>),
    UnspentOutputs(UncheckedOneshotSender<Vec<Utxo>>),
    SignOrSendTx(
        elements::Transaction,
        Vec<String>,
        SignAction,
        ResSender<elements::Transaction>,
    ),
    LoadTxs(TimestampUs, ResSender<models::Transactions>),
    BlockHeight(ResSender<u32>),
    UploadCaAddresses(u32, ResSender<()>),
    BroadcastTx(String, ResSender<Txid>),
    SetWatchOnly {
        credentials: Credentials,
        res_sender: ResSender<()>,
    },
}

fn to_value<T: serde::Serialize>(value: &T) -> rmpv::Value {
    let value = rmp_serde::encode::to_vec_named(value).expect("must not fail");
    rmp_serde::decode::from_slice(&value).expect("must not fail")
}

fn from_value<T: serde::de::DeserializeOwned>(value: &rmpv::Value) -> Result<T, Error> {
    let value = rmp_serde::encode::to_vec_named(value).expect("must not fail");
    rmp_serde::decode::from_slice::<T>(&value)
        .map_err(|err| Error::BackendMsgPackError(std::any::type_name::<T>(), err))
}

fn parse_args1<T1: serde::de::DeserializeOwned>(args: WampArgs) -> Result<T1, Error> {
    match &*args {
        [value, ..] => {
            let value = from_value::<T1>(value)?;
            Ok(value)
        }
        _ => abort!(Error::BackendUnexpectedCount(args.len(), 1)),
    }
}

fn parse_args2<T1: serde::de::DeserializeOwned, T2: serde::de::DeserializeOwned>(
    args: WampArgs,
) -> Result<(T1, T2), Error> {
    match &*args {
        [value1, value2, ..] => {
            let value1 = from_value::<T1>(value1)?;
            let value2 = from_value::<T2>(value2)?;
            Ok((value1, value2))
        }
        _ => abort!(Error::BackendUnexpectedCount(args.len(), 2)),
    }
}

pub struct Credentials {
    pub username: String,
    pub password: String,
}

pub struct AddressInfo {
    pub address: elements::Address,
    pub pointer: u32,
    pub user_path: Vec<u32>,
    pub prevout_script: elements::Script,
    pub service_xpub: String,
}

pub type EventCallback = Arc<dyn Fn(Event) + Sync + Send>;

pub trait Signer: Send + Sync {
    fn network(&self) -> Network;

    fn get_master_blinding_key(&self) -> Result<MasterBlindingKey, Error>;

    fn get_xpub(&self, path: &[ChildNumber]) -> Result<Xpub, Error>;

    fn sign_message(&self, path: &[ChildNumber], message: String) -> Result<Signature, Error>;
}

pub enum LoginType {
    Full(Arc<dyn Signer>),
    WatchOnly {
        master_blinding_key: MasterBlindingKey,
        credentials: Credentials,
        network: Network,
        amp_user_xpub: Xpub, // TODO: Can this be removed?
    },
}

impl LoginType {
    fn network(&self) -> Network {
        match self {
            LoginType::Full(signer) => signer.network(),
            LoginType::WatchOnly { network, .. } => *network,
        }
    }

    fn get_master_blinding_key(&self) -> Result<MasterBlindingKey, Error> {
        match self {
            LoginType::Full(signer) => signer.get_master_blinding_key(),
            LoginType::WatchOnly {
                master_blinding_key,
                ..
            } => Ok(*master_blinding_key),
        }
    }
}

#[derive(Clone)]
pub struct CreatedTx {
    pub pset: PartiallySignedTransaction,
    pub blinding_nonces: Vec<String>,
    pub used_utxos: Vec<Utxo>,
    pub network_fee: u64,
}

impl Wallet {
    pub async fn connect_once(
        login: &LoginType,
        event_callback: EventCallback,
        proxy: &Option<ProxyAddress>,
    ) -> Result<Wallet, Error> {
        let (command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();

        let data = tokio::time::timeout(
            Duration::from_secs(60),
            connect(login, event_callback, proxy),
        )
        .await
        .map_err(|_err| Error::ProtocolError("connection timeout"))??;

        let wallet = Wallet {
            command_sender,
            policy_asset: data.policy_asset,
            master_blinding_key: data.master_blinding_key,
            watch_only: data.watch_only,
        };

        tokio::task::spawn(run_once(data, command_receiver));

        Ok(wallet)
    }

    pub fn software(
        mnemonic: &bip39::Mnemonic,
        network: Network,
        event_callback: EventCallback,
    ) -> Wallet {
        let (command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();

        let login = LoginType::Full(Arc::new(SwSigner::new(network, &mnemonic)));

        let master_blinding_key = login.get_master_blinding_key().expect("must not fail");

        let wallet = Wallet {
            command_sender,
            policy_asset: network.d().policy_asset,
            master_blinding_key,
            watch_only: false,
        };

        tokio::task::spawn(run_loop(login, command_receiver, event_callback, None));

        wallet
    }

    pub fn watch_only(&self) -> bool {
        self.watch_only
    }

    pub fn master_blinding_key(&self) -> &MasterBlindingKey {
        &self.master_blinding_key
    }

    pub fn policy_asset(&self) -> AssetId {
        self.policy_asset
    }

    pub async fn receive_address(&self) -> Result<AddressInfo, Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::ReceiveAddress(res_sender.into()))?;
        res_receiver.await?
    }

    pub fn receive_address_blocking(&self) -> Result<Address, Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::ReceiveAddress(res_sender.into()))?;
        let address_info = res_receiver.blocking_recv()??;
        Ok(address_info.address)
    }

    pub async fn upload_ca_addresses(&self, count: u32) -> Result<(), Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::UploadCaAddresses(count, res_sender.into()))?;
        res_receiver.await?
    }

    pub async fn unspent_outputs(&self) -> Result<Vec<Utxo>, Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::UnspentOutputs(res_sender.into()))?;
        let utxos = res_receiver.await?;
        Ok(utxos)
    }

    pub async fn previous_addresses(&self) -> Result<Vec<AddressInfo>, Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::PreviousAddresses(res_sender.into()))?;
        let list = res_receiver.await??;
        Ok(list)
    }

    /// Get call Green backend for signatures.
    /// The PSET must be already signed by the user.
    pub async fn green_backend_sign(
        &self,
        mut pset: PartiallySignedTransaction,
        blinding_nonces: Vec<String>,
        sign_action: SignAction,
    ) -> Result<PartiallySignedTransaction, Error> {
        let tx = pset.extract_tx()?;

        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender.send(Command::SignOrSendTx(
            tx,
            blinding_nonces,
            sign_action,
            res_sender.into(),
        ))?;
        let tx = res_receiver.await??;

        sideswap_common::pset::copy_tx_signatures(&tx, &mut pset);

        Ok(pset)
    }

    pub async fn broadcast_tx(&self, tx: String) -> Result<Txid, Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::BroadcastTx(tx, res_sender.into()))?;
        let txid = res_receiver.await??;
        Ok(txid)
    }

    pub async fn set_watch_only(&self, credentials: Credentials) -> Result<(), Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender.send(Command::SetWatchOnly {
            credentials,
            res_sender: res_sender.into(),
        })?;
        res_receiver.await??;
        Ok(())
    }

    fn unblind_ep(
        &self,
        cache: &mut TxCache,
        txid: &Txid,
        ep: models::TransactionEp,
    ) -> Option<TxOutSecrets> {
        if !ep.is_relevant {
            return None;
        }

        if let (Some(asset), Some(value)) = (ep.asset_tag.explicit(), ep.commitment.explicit()) {
            return Some(TxOutSecrets {
                asset,
                asset_bf: AssetBlindingFactor::zero(),
                value,
                value_bf: ValueBlindingFactor::zero(),
            });
        }

        let outpoint = if ep.is_output {
            elements::OutPoint {
                txid: *txid,
                vout: ep.pt_idx,
            }
        } else {
            elements::OutPoint {
                txid: ep.prevtxhash?,
                vout: ep.previdx?,
            }
        };

        if let Some(unblinded) = cache.get_secret(&outpoint) {
            return Some(*unblinded);
        }

        let blinding_key = self.master_blinding_key.blinding_private_key(&ep.script);

        let txout = elements::TxOut {
            asset: ep.asset_tag,
            value: ep.commitment,
            nonce: ep.nonce_commitment,
            script_pubkey: ep.script,
            witness: elements::TxOutWitness {
                surjection_proof: ep.surj_proof,
                rangeproof: ep.range_proof,
            },
        };

        let unblinded_res = txout.unblind(SECP256K1, blinding_key);
        match unblinded_res {
            Ok(unblinded) => {
                cache.add_secret(outpoint, unblinded);
                Some(unblinded)
            }
            Err(err) => {
                log::error!("unblinding failed: {}", err);
                None
            }
        }
    }

    fn convert_tx(&self, cache: &mut TxCache, tx: models::Transaction) -> tx_cache::Transaction {
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut amounts = BTreeMap::new();

        for ep in tx.eps {
            let is_output = ep.is_output;
            let pt_idx = ep.pt_idx;
            let prevtxhash = ep.prevtxhash;
            let previdx: Option<u32> = ep.previdx;

            let unblinded = if ep.is_relevant {
                self.unblind_ep(cache, &tx.txhash, ep)
            } else {
                None
            };

            if let Some(unblinded) = unblinded {
                let sign = if is_output { 1 } else { -1 };
                *amounts.entry(unblinded.asset).or_default() += (unblinded.value as i64) * sign;
            }

            if is_output {
                outputs.push(tx_cache::TransactionOutput { pt_idx, unblinded });
            } else {
                if let (Some(prevtxid), Some(previdx)) = (prevtxhash, previdx) {
                    inputs.push(tx_cache::TransactionInput {
                        prevtxid,
                        previdx,
                        unblinded,
                    });
                }
            }
        }

        amounts.retain(|_, value| *value != 0);

        tx_cache::Transaction {
            txid: tx.txhash,
            created_at: tx.created_at_ts,
            block_height: tx.block_height,
            amounts,
            network_fee: tx.fee,
            inputs,
            outputs,
            vsize: tx.transaction_vsize,
        }
    }

    pub async fn block_height(&self) -> Result<u32, Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::BlockHeight(res_sender.into()))?;
        let resp = res_receiver.await??;
        Ok(resp)
    }

    pub async fn reload_txs(&self, cache: &mut TxCache) -> Result<(), Error> {
        loop {
            let sync_timestamp = cache.start_sync_timestamp();

            let (res_sender, res_receiver) = oneshot::channel();
            self.command_sender
                .send(Command::LoadTxs(sync_timestamp, res_sender.into()))?;
            let resp = res_receiver.await??;

            let new_txs = resp
                .list
                .into_iter()
                .map(|tx| self.convert_tx(cache, tx))
                .collect();
            cache.update_latest_txs(new_txs);

            if !resp.more {
                break;
            }
        }
        Ok(())
    }

    pub fn tx_blinded_values(&self, txid: &Txid, cache: &TxCache) -> Option<String> {
        let tx = cache.txs().iter().find(|tx| tx.txid == *txid)?;

        let mut secrets = Vec::new();

        for input in tx.inputs.iter() {
            let outpoint = elements::OutPoint {
                txid: input.prevtxid,
                vout: input.previdx,
            };
            if let Some(secret) = cache.get_secret(&outpoint) {
                secrets.push(secret);
            }
        }

        for output in tx.outputs.iter() {
            let outpoint = elements::OutPoint {
                txid: tx.txid,
                vout: output.pt_idx,
            };
            if let Some(secret) = cache.get_secret(&outpoint) {
                secrets.push(secret);
            }
        }

        let blinded_values = secrets
            .iter()
            .flat_map(|secret| {
                [
                    secret.value.to_string(),
                    secret.asset.to_string(),
                    secret.value_bf.to_string(),
                    secret.asset_bf.to_string(),
                ]
            })
            .collect::<Vec<_>>();

        Some(blinded_values.join(","))
    }

    pub async fn create_tx(
        &self,
        recipients: Vec<Recipient>,
        deduct_fee: Option<usize>,
    ) -> Result<CreatedTx, Error> {
        let utxos = self.unspent_outputs().await?;

        let utxo_select = utxo_select::select(utxo_select::Args {
            policy_asset: self.policy_asset,
            utxos: utxos
                .iter()
                .map(|utxo| utxo_select::Utxo {
                    wallet: WalletType::AMP,
                    txid: utxo.outpoint.txid,
                    vout: utxo.outpoint.vout,
                    asset_id: utxo.tx_out_sec.asset,
                    value: utxo.tx_out_sec.value,
                })
                .collect(),
            recipients: recipients
                .iter()
                .map(|addr| utxo_select::Recipient {
                    address: utxo_select::RecipientAddress::Known(addr.address.clone()),
                    asset_id: addr.asset_id,
                    amount: addr.amount,
                })
                .collect(),
            deduct_fee,
            force_change_wallets: ChangeWallets::new(),
            use_all_utxos: false,
        })
        .map_err(|err| match err {
            utxo_select::Error::InvalidArgs(err) => Error::ProtocolError(err),
            utxo_select::Error::InsufficientFunds => Error::InsufficientFunds,
        })?;

        let selected_utxos = utxo_select
            .inputs
            .iter()
            .map(|selected| {
                utxos
                    .iter()
                    .find(|utxo| {
                        utxo.outpoint.txid == selected.txid && utxo.outpoint.vout == selected.vout
                    })
                    .expect("UTXO must exist")
                    .clone()
            })
            .collect::<Vec<_>>();

        let inputs = selected_utxos
            .iter()
            .map(|utxo| {
                let asset_commitment = if utxo.tx_out_sec.asset_bf != AssetBlindingFactor::zero() {
                    elements::confidential::Asset::new_confidential(
                        SECP256K1,
                        utxo.tx_out_sec.asset,
                        utxo.tx_out_sec.asset_bf,
                    )
                } else {
                    elements::confidential::Asset::Explicit(utxo.tx_out_sec.asset)
                };

                let value_commitment = if utxo.tx_out_sec.value_bf != ValueBlindingFactor::zero() {
                    elements::confidential::Value::new_confidential_from_assetid(
                        SECP256K1,
                        utxo.tx_out_sec.value,
                        utxo.tx_out_sec.asset,
                        utxo.tx_out_sec.value_bf,
                        utxo.tx_out_sec.asset_bf,
                    )
                } else {
                    elements::confidential::Value::Explicit(utxo.tx_out_sec.value)
                };

                PsetInput {
                    txid: utxo.outpoint.txid,
                    vout: utxo.outpoint.vout,
                    script_pub_key: utxo.script_pub_key.clone(),
                    asset_commitment,
                    value_commitment,
                    tx_out_sec: utxo.tx_out_sec,
                }
            })
            .collect::<Vec<_>>();

        let mut outputs = Vec::<PsetOutput>::new();

        for recipient in utxo_select.updated_recipients.iter() {
            outputs.push(PsetOutput {
                address: recipient.address.known().expect("must be know").clone(),
                asset_id: recipient.asset_id,
                amount: recipient.amount,
            });
        }

        for change in utxo_select.change {
            let change_address = self.receive_address().await?;
            outputs.push(PsetOutput {
                address: change_address.address,
                asset_id: change.asset_id,
                amount: change.value,
            });
        }

        let ConstructedPset {
            blinded_pset: pset,
            blinded_outputs,
        } = construct_pset(ConstructPsetArgs {
            policy_asset: self.policy_asset,
            offlines: Vec::new(),
            inputs,
            outputs,
            network_fee: utxo_select.network_fee,
        })
        .map_err(|_| Error::ProtocolError("unexpected construct_pset error"))?;

        Ok(CreatedTx {
            pset,
            blinding_nonces: get_blinding_nonces(&blinded_outputs),
            used_utxos: selected_utxos,
            network_fee: utxo_select.network_fee,
        })
    }
}

// If the callback returns an error, the wallet connection is restarted
type Callback = Box<dyn FnOnce(&mut Data, Result<WampArgs, Error>) -> Result<(), Error> + Send>;

// If the callback returns an error, the wallet connection is restarted
type SubscribeCallback = fn(&mut Data, WampArgs) -> Result<(), Error>;

type Connection =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct PendingRequest {
    callback: Callback,
    expires_at: Instant,
}

type PendingRequests = BTreeMap<WampId, PendingRequest>;

struct Data {
    policy_asset: AssetId,
    connection: Connection,
    pending_requests: PendingRequests,
    network: Network,
    master_blinding_key: MasterBlindingKey,
    subaccount: u32,
    user_xpub: Xpub,
    service_xpub: Xpub,
    event_callback: EventCallback,
    pending_subscribe: HashMap<WampId, SubscribeCallback>,
    active_subscribe: HashMap<WampId, SubscribeCallback>,
    utxos: Vec<Utxo>,
    reload_utxos: bool,
    ca_addresses: Vec<Address>,
    block_height: u32,
    watch_only: bool,
    gaid: String,
}

#[derive(Debug, Clone)]
pub struct Utxo {
    pub block_height: Option<u32>,
    pub subaccount: u32,
    pub pointer: u32,
    pub txout: elements::TxOut,
    pub outpoint: elements::OutPoint,
    pub tx_out_sec: TxOutSecrets,
    pub prevout_script: elements::Script, // Example: 522103cab1a2a707d13ff3fcc9d08f888724e01c37d54ad8e8d9b274cb33eaebe3461321037888f798b59ff4e1122bdf52ad4c541be32ca755311746b67af2bc5e58df188b52ae
    pub redeem_script: elements::Script, // Example: 0020953851a48d22e33a16eb11e9fb89ce1a410db6f0f681ec5b834b036fb84264c9
    pub script_pub_key: elements::Script,
}

impl UtxoExt for Utxo {
    fn value(&self) -> u64 {
        self.tx_out_sec.value
    }

    fn txid(&self) -> Txid {
        self.outpoint.txid
    }

    fn vout(&self) -> u32 {
        self.outpoint.vout
    }

    fn redeem_script(&self) -> Option<&elements::Script> {
        Some(&self.redeem_script)
    }
}

// Example: 0020953851a48d22e33a16eb11e9fb89ce1a410db6f0f681ec5b834b036fb84264c9
fn redeem_script(prevout_script: &elements::Script) -> elements::Script {
    elements::script::Builder::new()
        .push_int(0)
        .push_slice(&elements::WScriptHash::hash(prevout_script.as_bytes())[..])
        .into_script()
}

fn derive_ga_path(signer: &dyn Signer) -> Result<Vec<u8>, Error> {
    let login_xpub = signer.get_xpub(&[ChildNumber::Hardened { index: 0x4741 }])?;

    let pub_key = login_xpub.public_key.serialize();
    let ga_key = "GreenAddress.it HD wallet path";
    let data = [login_xpub.chain_code.as_bytes(), pub_key.as_slice()].concat();

    use hmac::Mac;
    let mut mac =
        hmac::Hmac::<sha2::Sha512>::new_from_slice(ga_key.as_bytes()).expect("must not fail");
    mac.update(&data);
    let result = mac.finalize();

    Ok(result.into_bytes().to_vec())
}

impl Data {
    fn derive_address(&self, pointer: u32) -> DerivedAddress {
        let prevout_script = derive_prevout_script(&self.user_xpub, &self.service_xpub, pointer);

        let address = get_address(
            &prevout_script,
            Some(&self.master_blinding_key),
            self.network,
        );

        DerivedAddress {
            address,
            prevout_script,
        }
    }

    fn unblind_utxos(&self, utxos: Vec<models::Utxo>) -> Vec<Utxo> {
        utxos
            .into_iter()
            .filter_map(|utxo| {
                let txout = elements::TxOut {
                    asset: utxo.asset_tag,
                    value: utxo.commitment,
                    nonce: utxo.nonce_commitment,
                    script_pubkey: utxo.script,
                    witness: elements::TxOutWitness {
                        surjection_proof: utxo.surj_proof,
                        rangeproof: utxo.range_proof,
                    },
                };
                let blinding_key = self
                    .master_blinding_key
                    .blinding_private_key(&txout.script_pubkey);
                let out_point = elements::OutPoint {
                    txid: utxo.txhash,
                    vout: utxo.pt_idx,
                };

                let tx_out_sec = match (&txout.asset, &txout.value) {
                    (
                        elements::confidential::Asset::Explicit(asset_id),
                        elements::confidential::Value::Explicit(value),
                    ) => TxOutSecrets {
                        asset: *asset_id,
                        asset_bf: AssetBlindingFactor::zero(),
                        value: *value,
                        value_bf: ValueBlindingFactor::zero(),
                    },
                    (
                        elements::confidential::Asset::Confidential(_),
                        elements::confidential::Value::Confidential(_),
                    ) => {
                        let unblinded_res = txout.unblind(SECP256K1, blinding_key);
                        match unblinded_res {
                            Ok(tx_out_sec) => tx_out_sec,
                            Err(err) => {
                                log::error!("unblinding {} failed: {}", out_point, err);
                                return None;
                            }
                        }
                    }
                    _ => {
                        log::error!(
                            "mixed confidential/non-confidential values in {}",
                            out_point
                        );
                        return None;
                    }
                };

                let DerivedAddress {
                    address,
                    prevout_script,
                } = self.derive_address(utxo.pointer);

                let redeem_script = redeem_script(&prevout_script);

                let script_pub_key = address.script_pubkey();

                Some(Utxo {
                    block_height: utxo.block_height,
                    subaccount: utxo.subaccount,
                    txout,
                    tx_out_sec,
                    outpoint: out_point,
                    pointer: utxo.pointer,
                    prevout_script,
                    redeem_script,
                    script_pub_key,
                })
            })
            .collect()
    }
}

pub fn derive_prevout_script(
    user_xpub: &Xpub,
    service_xpub: &Xpub,
    pointer: u32,
) -> elements::Script {
    let pub_key_green = service_xpub
        .derive_pub(SECP256K1, &[ChildNumber::Normal { index: pointer }])
        .expect("should not fail")
        .to_pub();

    let pub_key_user = user_xpub
        .derive_pub(SECP256K1, &[ChildNumber::Normal { index: pointer }])
        .expect("should not fail")
        .to_pub();

    let prevout_script = elements::script::Builder::new()
        .push_opcode(elements::opcodes::all::OP_PUSHNUM_2)
        .push_slice(&pub_key_green.to_bytes())
        .push_slice(&pub_key_user.to_bytes())
        .push_opcode(elements::opcodes::all::OP_PUSHNUM_2)
        .push_opcode(elements::opcodes::all::OP_CHECKMULTISIG)
        .into_script();

    prevout_script
}

struct DerivedAddress {
    address: elements::Address,
    prevout_script: elements::Script,
}

fn get_address(
    prevout_script: &elements::Script,
    master_blinding_key: Option<&MasterBlindingKey>,
    network: Network,
) -> elements::Address {
    let script = elements::script::Builder::new()
        .push_int(0)
        .push_slice(&elements::WScriptHash::hash(prevout_script.as_bytes())[..])
        .into_script();

    let script_hash = elements::ScriptHash::hash(script.as_bytes());

    let unconfidential_address = Address {
        params: network.d().elements_params,
        payload: elements::address::Payload::ScriptHash(script_hash),
        blinding_pubkey: None,
    };

    match master_blinding_key {
        Some(master_blinding_key) => {
            let blinder = master_blinding_key
                .blinding_key(SECP256K1, &unconfidential_address.script_pubkey());
            let confidential_address = unconfidential_address.to_confidential(blinder);
            confidential_address
        }
        None => unconfidential_address,
    }
}

fn parse_gait_path(gait_path: &str) -> Result<Vec<u32>, Error> {
    let bytes =
        hex::decode(gait_path).map_err(|_| Error::ProtocolError("invalid gait_path hex"))?;
    verify!(
        bytes.len() % 2 == 0,
        Error::ProtocolError("invalid gait_path size")
    );
    let value = bytes
        .chunks(2)
        .map(|chunk| u32::from_be_bytes([0, 0, chunk[0], chunk[1]]))
        .collect();
    Ok(value)
}

pub fn address_user_path(subaccount: u32, pointer: u32) -> [ChildNumber; 4] {
    [
        ChildNumber::Hardened { index: 3 },
        ChildNumber::Hardened { index: subaccount },
        ChildNumber::Normal { index: 1 },
        ChildNumber::Normal { index: pointer },
    ]
}

fn derive_user_xpub(signer: &dyn Signer, subaccount: u32) -> Result<Xpub, Error> {
    let user_path = [
        ChildNumber::Hardened { index: 3 },
        ChildNumber::Hardened { index: subaccount },
        ChildNumber::Normal { index: 1 },
    ];
    signer.get_xpub(&user_path)
}

fn derive_service_xpub(network: Network, gait_path: &str, subaccount: u32) -> Result<Xpub, Error> {
    let gait_path = parse_gait_path(gait_path)?;

    let root_xpub = Xpub {
        network: bitcoin::NetworkKind::Test,
        depth: 0,
        parent_fingerprint: Default::default(),
        child_number: 0.into(),
        public_key: network.d().service_pubkey.parse().expect("must be valid"),
        chain_code: network
            .d()
            .service_chain_code
            .parse()
            .expect("must be valid"),
    };

    let path_prefix = 3;
    let mut path = vec![path_prefix];
    path.extend_from_slice(&gait_path);
    path.push(subaccount);

    let path = path
        .into_iter()
        .map(Into::into)
        .collect::<Vec<ChildNumber>>();

    let mut subaccount_xpub = root_xpub
        .derive_pub(SECP256K1, &path)
        .expect("should not fail");
    subaccount_xpub.parent_fingerprint = Default::default();

    Ok(subaccount_xpub)
}

fn get_challenge_address(signer: &dyn Signer) -> Result<Address, Error> {
    let root_xpub = signer.get_xpub(&[])?;
    let pk = root_xpub.public_key;
    Ok(Address::p2pkh(
        &pk.into(),
        None,
        signer.network().d().elements_params,
    ))
}

fn encode_msg(msg: Msg) -> tungstenite::Message {
    let msg = rmp_serde::encode::to_vec(&msg).expect("should not fail");

    if log::log_enabled!(log::Level::Trace) {
        let value = rmpv::decode::read_value(&mut msg.as_slice()).expect("must not fail");
        log::trace!("send: {value:#?}");
    }

    tungstenite::Message::binary(msg)
}

fn decode_msg(msg: tungstenite::Message) -> Result<Option<Msg>, Error> {
    match msg {
        tungstenite::Message::Text(_) => {
            abort!(Error::ProtocolError("unexpected text message received"))
        }
        tungstenite::Message::Binary(msg) => {
            if log::log_enabled!(log::Level::Trace) {
                let value = rmpv::decode::read_value(&mut msg.as_ref()).expect("must not fail");
                log::trace!("recv: {value:#?}");
            }

            let msg = rmp_serde::decode::from_slice::<Msg>(&msg)
                .map_err(|err| Error::BackendMsgPackError(std::any::type_name::<Msg>(), err))?;

            Ok(Some(msg))
        }
        tungstenite::Message::Ping(_) => Ok(None),
        tungstenite::Message::Pong(_) => Ok(None),
        tungstenite::Message::Close(close) => {
            log::debug!("close event received: {close:?}");
            abort!(Error::ProtocolError("close frame message received"))
        }
        tungstenite::Message::Frame(_) => {
            abort!(Error::ProtocolError("unexpected frame message received"))
        }
    }
}

async fn send(connection: &mut Connection, msg: Msg) -> Result<(), Error> {
    connection.send(encode_msg(msg)).await?;
    Ok(())
}

async fn process_msg(data: &mut Data, msg: Msg) -> Result<(), Error> {
    match msg {
        Msg::Result {
            request, arguments, ..
        } => {
            if let Some(req) = data.pending_requests.remove(&request) {
                match arguments {
                    Some(arguments) => {
                        (req.callback)(data, Ok(arguments))?;
                    }
                    None => {
                        (req.callback)(data, Err(Error::ProtocolError("arguments is empty")))?;
                    }
                }
            }
            Ok(())
        }

        Msg::Error {
            typ,
            request,
            error,     // Example: com.greenaddress.error
            arguments, // Example: ["http://greenaddressit.com/error#sessionexpired","Session expired"]
            ..
        } => {
            match typ {
                wamp::message::SUBSCRIBE_ID => {
                    abort!(Error::ProtocolError("subscribe failed: {error}"))
                }
                wamp::message::UNSUBSCRIBE_ID => abort!(Error::WampError {
                    context: "unsubscribe failed",
                    error,
                }),
                wamp::message::CALL_ID => {
                    if let Some(req) = data.pending_requests.remove(&request) {
                        let args = arguments.ok_or(Error::ProtocolError("empty args"))?;
                        let (_error_url, error_text) = parse_args2::<String, String>(args)?;
                        (req.callback)(
                            data,
                            Err(Error::WampError {
                                context: "green backend",
                                error: error_text,
                            }),
                        )?;
                    } else {
                        log::error!("unknown request: {request}");
                    }
                }
                typ => {
                    log::error!("unknown response type: {typ}");
                }
            };

            Ok(())
        }

        Msg::Subscribed {
            request,
            subscription,
        } => {
            log::debug!("subscribed sucesfully, request: {request}, subscription: {subscription}");
            if let Some(callback) = data.pending_subscribe.remove(&request) {
                data.active_subscribe.insert(subscription, callback);
            }
            Ok(())
        }

        Msg::Unsubscribed { .. } => abort!(Error::ProtocolError(
            "unexpected unsubscribed event received"
        )),

        Msg::Event {
            subscription,
            publication: _,
            details: _,
            arguments,
            arguments_kw: _,
        } => {
            if let Some(callback) = data.active_subscribe.get(&subscription) {
                if let Some(arguments) = arguments {
                    callback(data, arguments)?;
                } else {
                    log::error!("arguments is empty in subscription");
                }
            } else {
                log::error!("unknown subscription received");
            }
            Ok(())
        }

        // Unsupported messages
        Msg::Welcome { .. } => abort!(Error::ProtocolError("unexpected welcome message received")),
        Msg::Hello { .. } => abort!(Error::ProtocolError("unexpected hello message received")),
        Msg::Abort { reason, .. } => abort!(Error::WampError {
            context: "abort message received",
            error: reason,
        }),
        Msg::Goodbye { reason, .. } => abort!(Error::WampError {
            context: "goodbye message received",
            error: reason,
        }),
        Msg::Call { .. } => abort!(Error::ProtocolError("unexpected call message received")),
        Msg::Subscribe { .. } => abort!(Error::ProtocolError(
            "unexpected subscribe message received"
        )),
        Msg::Unsubscribe { .. } => abort!(Error::ProtocolError(
            "unexpected unsubscribe message received"
        )),
    }
}

async fn process_ws_msg(data: &mut Data, msg: tungstenite::Message) -> Result<(), Error> {
    let msg = decode_msg(msg)?;
    if let Some(msg) = msg {
        process_msg(data, msg).await
    } else {
        Ok(())
    }
}

async fn get_wamp_msg(connection: &mut Connection) -> Result<Msg, Error> {
    loop {
        let ws_msg = match connection.next().await {
            Some(Ok(ws_msg)) => ws_msg,
            Some(Err(err)) => return Err(err.into()),
            None => abort!(Error::ProtocolError("connection closed unexpectedly")),
        };

        let msg = decode_msg(ws_msg)?;
        if let Some(msg) = msg {
            break Ok(msg);
        }
    }
}

async fn make_request(
    data: &mut Data,
    procedure: &str,
    args: WampArgs,
    callback: Callback,
) -> Result<(), Error> {
    let request = WampId::generate();

    let mut options = WampDict::new();
    options.insert("timeout".to_owned(), Arg::Integer(30000));

    send(
        &mut data.connection,
        Msg::Call {
            request,
            options,
            procedure: procedure.to_owned(),
            arguments: Some(args),
            arguments_kw: None,
        },
    )
    .await?;
    let old_request = data.pending_requests.insert(
        request,
        PendingRequest {
            callback,
            expires_at: Instant::now() + Duration::from_secs(60),
        },
    );
    assert!(old_request.is_none());
    Ok(())
}

async fn recv_addr_request(data: &mut Data, callback: Callback) -> Result<(), Error> {
    let return_pointer = true;
    let addr_type = "p2wsh";
    make_request(
        data,
        "com.greenaddress.vault.fund",
        vec![
            data.subaccount.into(),
            return_pointer.into(),
            addr_type.into(),
        ],
        callback,
    )
    .await
}

async fn process_command(data: &mut Data, command: Command) -> Result<(), Error> {
    match command {
        Command::ReceiveAddress(res_channel) => {
            recv_addr_request(
                data,
                Box::new(move |data, res| {
                    let res = res.and_then(|args| -> Result<AddressInfo, Error> {
                        let resp = parse_args1::<models::ReceiveAddress>(args)?;

                        let derived_address = data.derive_address(resp.pointer);

                        let user_path = address_user_path(data.subaccount, resp.pointer)
                            .into_iter()
                            .map(u32::from)
                            .collect();
                        assert_eq!(derived_address.prevout_script, resp.script);

                        Ok(AddressInfo {
                            address: derived_address.address,
                            pointer: resp.pointer,
                            user_path,
                            prevout_script: derived_address.prevout_script,
                            service_xpub: data.service_xpub.to_string(),
                        })
                    });
                    res_channel.send(res);
                    Ok(())
                }),
            )
            .await
        }

        Command::PreviousAddresses(res_channel) => {
            make_request(
                data,
                "com.greenaddress.addressbook.get_my_addresses",
                vec![data.subaccount.into()],
                Box::new(move |data, res| {
                    let res = res.and_then(|args| -> Result<Vec<AddressInfo>, Error> {
                        let latest_list = parse_args1::<Vec<models::PreviousAddress>>(args)?;

                        let max_pointer = latest_list
                            .iter()
                            .map(|addr| addr.pointer)
                            .max()
                            .unwrap_or_default();

                        let list = (0..=max_pointer)
                            .rev()
                            .map(|pointer| {
                                let derived_address = data.derive_address(pointer);

                                let user_path = address_user_path(data.subaccount, pointer)
                                    .into_iter()
                                    .map(u32::from)
                                    .collect();

                                AddressInfo {
                                    address: derived_address.address,
                                    pointer,
                                    user_path,
                                    prevout_script: derived_address.prevout_script,
                                    service_xpub: data.service_xpub.to_string(),
                                }
                            })
                            .collect::<Vec<_>>();

                        Ok(list)
                    });
                    res_channel.send(res);
                    Ok(())
                }),
            )
            .await
        }

        Command::UnspentOutputs(res_channel) => {
            res_channel.send(data.utxos.clone());
            Ok(())
        }

        Command::SignOrSendTx(transaction, blinding_nonces, sign_action, res_channel) => {
            let transaction = elements::encode::serialize_hex(&transaction);

            #[derive(serde::Serialize)]
            struct TwofacData {}
            let twofac_data = TwofacData {};
            let twofac_data = to_value(&twofac_data);

            #[derive(serde::Serialize)]
            struct PrivData {
                blinding_nonces: Vec<String>,
            }
            let priv_data = PrivData { blinding_nonces };
            let priv_data = to_value(&priv_data);

            #[derive(serde::Deserialize)]
            struct Output {
                // txhash: elements::Txid,
                tx: String,
            }

            let procedure = match sign_action {
                SignAction::SignOnly => "com.greenaddress.vault.sign_raw_tx",
                SignAction::SignAndBroadcast => "com.greenaddress.vault.send_raw_tx",
            };
            make_request(
                data,
                procedure,
                vec![transaction.into(), twofac_data, priv_data],
                Box::new(move |_data, res| {
                    let res = res.and_then(|args| -> Result<elements::Transaction, Error> {
                        let output = parse_args1::<Output>(args)?;
                        let transaction = hex::decode(&output.tx)
                            .map_err(|_| Error::ProtocolError("invalid hex in tx"))?;
                        let transaction = elements::encode::deserialize(&transaction)
                            .map_err(|_| Error::ProtocolError("can't deserialize tx"))?;
                        Ok(transaction)
                    });
                    res_channel.send(res);
                    Ok(())
                }),
            )
            .await
        }

        Command::LoadTxs(timestamp, res_channel) => {
            make_request(
                data,
                "com.greenaddress.txs.get_list_v3",
                vec![data.subaccount.into(), timestamp.micros().into()],
                Box::new(move |_data, res| {
                    let res = res.and_then(|args| -> Result<models::Transactions, Error> {
                        let transactions = parse_args1::<models::Transactions>(args)?;
                        Ok(transactions)
                    });
                    res_channel.send(res);
                    Ok(())
                }),
            )
            .await
        }

        Command::BlockHeight(res_channel) => {
            res_channel.send(Ok(data.block_height));
            Ok(())
        }

        Command::UploadCaAddresses(count, res_channel) => {
            let res = upload_ca_addresses(data, count).await;
            res_channel.send(res);
            Ok(())
        }

        Command::BroadcastTx(tx, res_channel) => {
            make_request(
                data,
                "com.greenaddress.vault.broadcast_raw_tx",
                vec![tx.into()],
                Box::new(move |_data, res| {
                    let res = res.and_then(|args| -> Result<Txid, Error> {
                        let txid = parse_args1::<models::BroadcastResult>(args)?.0;
                        Ok(txid)
                    });
                    res_channel.send(res);
                    Ok(())
                }),
            )
            .await
        }

        Command::SetWatchOnly {
            credentials,
            res_sender,
        } => {
            make_request(
                data,
                "com.greenaddress.addressbook.sync_custom",
                vec![credentials.username.into(), credentials.password.into()],
                Box::new(move |_data, res| {
                    let res = res.and_then(|args| -> Result<(), Error> {
                        let resp = parse_args1::<bool>(args)?;
                        verify!(resp, Error::ProtocolError("unexpected error"));
                        Ok(())
                    });
                    res_sender.send(res);
                    Ok(())
                }),
            )
            .await
        }
    }
}

async fn connect_ws(network: Network, proxy: &Option<ProxyAddress>) -> Result<Connection, Error> {
    let url = match network {
        Network::Liquid => "wss://green-liquid-mainnet.blockstream.com/v2/ws",
        Network::LiquidTestnet => "wss://green-liquid-testnet.blockstream.com/v2/ws",
        Network::Regtest => std::future::pending().await, // Do nothing on regtest
    };
    let url: url::Url = url.parse().expect("must be valid");
    let host = url.host().expect("must be set").to_string();
    let port = url.port_or_known_default().expect("must be set");

    let server_address = format!("{}:{}", host, port);

    let request = tungstenite::http::Request::builder()
        .uri(url.as_ref())
        .header("Host", host)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("User-Agent", DEFAULT_AGENT_STR)
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Protocol", "wamp.2.msgpack")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        );

    let request = request.body(())?;

    let stream = if let Some(ProxyAddress::Socks5 { address }) = proxy {
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .map_err(|err| Error::WsError(err.into()))?;
        let stream =
            tokio_socks::tcp::Socks5Stream::connect_with_socket(stream, server_address).await?;
        stream.into_inner()
    } else {
        tokio::net::TcpStream::connect(server_address)
            .await
            .map_err(|err| Error::WsError(err.into()))?
    };

    let (connection, _resp) = tokio_tungstenite::client_async_tls(request, stream).await?;

    Ok(connection)
}

async fn login(connection: &mut Connection) -> Result<(), Error> {
    let mut details = WampDict::new();
    let mut client_roles = WampDict::new();
    for role in [
        wamp::common::ClientRole::Subscriber,
        wamp::common::ClientRole::Publisher,
    ] {
        client_roles.insert(String::from(role.to_str()), Arg::Dict(WampDict::new()));
    }
    for role in [
        wamp::common::ClientRole::Caller,
        wamp::common::ClientRole::Callee,
    ] {
        let mut features = WampDict::new();
        features.insert("call_timeout".to_owned(), Arg::Bool(true));
        let mut options = WampDict::new();
        options.insert("features".to_owned(), Arg::Dict(features));
        client_roles.insert(String::from(role.to_str()), Arg::Dict(options));
    }
    details.insert("roles".to_owned(), Arg::Dict(client_roles));

    send(
        connection,
        Msg::Hello {
            realm: "realm1".to_owned(),
            details,
        },
    )
    .await?;

    let resp = get_wamp_msg(connection).await?;
    if let Msg::Welcome { session, .. } = resp {
        log::debug!("welcome message received, session: {session}");
    } else {
        abort!(Error::WampError {
            context: "unexpected response received",
            error: serde_json::to_string(&resp).expect("must not fail"),
        });
    }

    Ok(())
}

async fn get_challenge(connection: &mut Connection, signer: &dyn Signer) -> Result<String, Error> {
    let challenge_address = get_challenge_address(signer)?.to_string();
    let args = vec![challenge_address.into(), true.into()];

    let request_id = WampId::generate();

    send(
        connection,
        Msg::Call {
            request: request_id,
            options: WampDict::new(),
            procedure: "com.greenaddress.login.get_trezor_challenge".to_owned(),
            arguments: Some(args),
            arguments_kw: None,
        },
    )
    .await?;

    let resp = get_wamp_msg(connection).await?;
    let resp = match resp {
        Msg::Result {
            request, arguments, ..
        } => {
            verify!(
                request == request_id,
                Error::ProtocolError("unexpected request_id")
            );
            let args = arguments.ok_or(Error::ProtocolError("empty args"))?;
            parse_args1::<String>(args)?
        }
        Msg::Error { request, error, .. } => {
            verify!(
                request == request_id,
                Error::ProtocolError("unexpected request_id")
            );
            abort!(Error::WampError {
                context: "get_trezor_challenge call failed",
                error
            });
        }
        _ => abort!(Error::ProtocolError("unexpected response")),
    };

    Ok(resp)
}

struct AuthenticateResp {
    gait_path: String,
    wallet_id: String,
    amp_subaccount: Option<models::Subaccount>,
    block_height: u32,
    next_subaccount: u32,
}

const USER_AGENT_CAPS: &str = "[v2,sw,csv,csv_opt] sideswap_amp";

async fn authenticate(
    connection: &mut Connection,
    signer: &dyn Signer,
    challenge: &str,
) -> Result<Option<AuthenticateResp>, Error> {
    let login_path = [ChildNumber::Normal { index: 0x4741b11e }];
    let message = format!("greenaddress.it      login {}", challenge);

    let signature = signer.sign_message(&login_path, message)?.to_string();

    let args = vec![
        signature.into(),
        true.into(),
        "GA".into(),
        "".into(),
        USER_AGENT_CAPS.into(),
    ];

    let request_id = WampId::generate();

    send(
        connection,
        Msg::Call {
            request: request_id,
            options: WampDict::new(),
            procedure: "com.greenaddress.login.authenticate".to_owned(),
            arguments: Some(args),
            arguments_kw: None,
        },
    )
    .await?;

    let resp = get_wamp_msg(connection).await?;

    match resp {
        Msg::Result {
            request, arguments, ..
        } => {
            verify!(
                request == request_id,
                Error::ProtocolError("unexpected request_id")
            );
            let args = arguments.ok_or(Error::ProtocolError("empty response"))?;

            if args.first().and_then(|resp| resp.as_bool()) == Some(false) {
                log::debug!("login failed, not account found");
                return Ok(None);
            }

            let auth_res = parse_args1::<models::AuthenticateResult>(args)?;

            let next_subaccount = auth_res
                .subaccounts
                .iter()
                .map(|subaccount| subaccount.pointer)
                .max()
                .unwrap_or(0)
                + 1;

            let amp_subaccount = auth_res
                .subaccounts
                .into_iter()
                .find(|subaccount| subaccount.type_ == AMP_SUBACCOUNT_TYPE);

            log::info!("authenticaton succeed");
            Ok(Some(AuthenticateResp {
                gait_path: auth_res.gait_path,
                wallet_id: auth_res.receiving_id,
                amp_subaccount,
                block_height: auth_res.block_height,
                next_subaccount,
            }))
        }
        Msg::Error { request, error, .. } => {
            verify!(
                request == request_id,
                Error::ProtocolError("unexpected request_id")
            );
            abort!(Error::WampError {
                context: "login.authenticate call failed",
                error
            })
        }
        _ => abort!(Error::ProtocolError("unexpected response")),
    }
}

async fn wo_login(
    connection: &mut Connection,
    Credentials { username, password }: &Credentials,
) -> Result<Option<AuthenticateResp>, Error> {
    #[derive(Serialize)]
    pub struct Credentials {
        username: String,
        password: String,
        minimal: String,
    }

    let credentials = Credentials {
        username: username.to_owned(),
        password: password.to_owned(),
        minimal: "true".to_owned(), // Must be string!
    };

    // let with_blob = false;

    let args = vec![
        "custom".into(),
        to_value(&credentials),
        USER_AGENT_CAPS.into(),
        // with_blob.into(),
    ];

    let request_id = WampId::generate();

    send(
        connection,
        Msg::Call {
            request: request_id,
            options: WampDict::new(),
            procedure: "com.greenaddress.login.watch_only_v2".to_owned(),
            arguments: Some(args),
            arguments_kw: None,
        },
    )
    .await?;

    let resp = get_wamp_msg(connection).await?;

    match resp {
        Msg::Result {
            request, arguments, ..
        } => {
            verify!(
                request == request_id,
                Error::ProtocolError("unexpected request_id")
            );
            let args = arguments.ok_or(Error::ProtocolError("empty response"))?;

            if args.first().and_then(|resp| resp.as_bool()) == Some(false) {
                log::debug!("login failed, no account found");
                return Ok(None);
            }

            let auth_res = parse_args1::<models::AuthenticateResult>(args)?;

            let next_subaccount = auth_res
                .subaccounts
                .iter()
                .map(|subaccount| subaccount.pointer)
                .max()
                .unwrap_or(0)
                + 1;

            let amp_subaccount = auth_res
                .subaccounts
                .into_iter()
                .find(|subaccount| subaccount.type_ == AMP_SUBACCOUNT_TYPE);

            log::info!("watch-only login succeed");
            Ok(Some(AuthenticateResp {
                gait_path: auth_res.gait_path,
                wallet_id: auth_res.receiving_id,
                amp_subaccount,
                block_height: auth_res.block_height,
                next_subaccount,
            }))
        }
        Msg::Error {
            request,
            error,
            arguments,
            ..
        } => {
            verify!(
                request == request_id,
                Error::ProtocolError("unexpected request_id")
            );
            let args = arguments.ok_or(Error::ProtocolError("empty error response"))?;
            if args.first().and_then(|resp| resp.as_str())
                == Some("http://greenaddressit.com/error#usernotfound")
            {
                abort!(Error::WrongWatchOnlyPassword)
            }
            abort!(Error::WampError {
                context: "login.watch_only_v2 call failed",
                error
            })
        }
        _ => abort!(Error::ProtocolError("unexpected response")),
    }
}

async fn create_subaccount(
    connection: &mut Connection,
    signer: &dyn Signer,
    pointer: u32,
) -> Result<String, Error> {
    let user_path = [
        ChildNumber::Hardened { index: 3 },
        ChildNumber::Hardened { index: pointer },
    ];

    let subaccount_xpub = signer.get_xpub(&user_path)?.to_string();

    let xpubs: WampArgs = vec![subaccount_xpub.into()];
    let sigs: WampArgs = vec!["".into()];

    let args = vec![
        pointer.into(),
        AMP_SUBACCOUNT_DEFAULT_NAME.into(),
        AMP_SUBACCOUNT_TYPE.into(),
        xpubs.into(),
        sigs.into(),
    ];

    let request_id = WampId::generate();

    send(
        connection,
        Msg::Call {
            request: request_id,
            options: WampDict::new(),
            procedure: "com.greenaddress.txs.create_subaccount_v2".to_owned(),
            arguments: Some(args),
            arguments_kw: None,
        },
    )
    .await?;

    let resp = get_wamp_msg(connection).await?;

    match resp {
        Msg::Result {
            request, arguments, ..
        } => {
            verify!(
                request == request_id,
                Error::ProtocolError("unexpected request_id")
            );
            let args = arguments.ok_or(Error::ProtocolError("empty response"))?;
            let gaid = parse_args1::<String>(args)?;
            log::info!("AMP subaccount created");
            Ok(gaid)
        }
        Msg::Error { request, error, .. } => {
            verify!(
                request == request_id,
                Error::ProtocolError("unexpected request_id")
            );
            abort!(Error::WampError {
                context: "txs.create_subaccount_v2 call failed",
                error
            })
        }
        _ => abort!(Error::ProtocolError("unexpected response")),
    }
}

async fn register(connection: &mut Connection, signer: &dyn Signer) -> Result<(), Error> {
    let root_xpub = signer.get_xpub(&[])?;

    let pubkey = hex::encode(root_xpub.public_key.serialize());
    let chaincode = hex::encode(root_xpub.chain_code.as_bytes());
    let ga_path = hex::encode(derive_ga_path(signer)?);

    let args = vec![
        pubkey.into(),
        chaincode.into(),
        USER_AGENT_CAPS.into(),
        ga_path.into(),
    ];

    let request_id = WampId::generate();

    send(
        connection,
        Msg::Call {
            request: request_id,
            options: WampDict::new(),
            procedure: "com.greenaddress.login.register".to_owned(),
            arguments: Some(args),
            arguments_kw: None,
        },
    )
    .await?;

    let resp = get_wamp_msg(connection).await?;

    match resp {
        Msg::Result {
            request, arguments, ..
        } => {
            verify!(
                request == request_id,
                Error::ProtocolError("unexpected request_id")
            );
            let args = arguments.ok_or(Error::ProtocolError("empty response"))?;

            let register_res = parse_args1::<bool>(args)?;
            verify!(register_res, Error::ProtocolError("registration failed"));
            log::info!("registration succeed");
            Ok(())
        }
        Msg::Error { request, error, .. } => {
            verify!(
                request == request_id,
                Error::ProtocolError("unexpected request_id")
            );
            abort!(Error::WampError {
                context: "login.register call failed",
                error
            });
        }
        _ => abort!(Error::ProtocolError("unexpected response")),
    }
}

async fn subscribe(
    data: &mut Data,
    topic: WampString,
    callback: SubscribeCallback,
) -> Result<(), Error> {
    let request = WampId::generate();
    log::debug!("send subscribe request, request: {request}, topic: {topic}");

    let mut options = WampDict::new();
    options.insert("match".to_owned(), Arg::String("exact".to_owned()));

    send(
        &mut data.connection,
        Msg::Subscribe {
            request,
            options,
            topic,
        },
    )
    .await?;

    data.pending_subscribe.insert(request, callback);

    Ok(())
}

fn block_callback(data: &mut Data, args: WampArgs) -> Result<(), Error> {
    let block = parse_args1::<models::BlockEvent>(args)?;
    log::debug!("block callback: {block:?}");
    data.block_height = block.count;
    (data.event_callback)(Event::NewBlock {
        block_height: block.count,
    });
    Ok(())
}

fn tx_callback(data: &mut Data, args: WampArgs) -> Result<(), Error> {
    let tx = parse_args1::<models::TransactionEvent>(args)?;
    log::debug!("tx callback: {tx:?}");
    data.reload_utxos = true;
    (data.event_callback)(Event::NewTx { txid: tx.txhash });
    Ok(())
}

fn send_event(data: &Data, event: Event) {
    (data.event_callback)(event);
}

async fn reload_wallet_utxos(data: &mut Data) -> Result<(), Error> {
    let confs = 0u32;
    make_request(
        data,
        "com.greenaddress.txs.get_all_unspent_outputs",
        vec![confs.into(), data.subaccount.into()],
        Box::new(move |data, res| {
            let args = res?;
            let utxos = parse_args1::<Vec<models::Utxo>>(args)?;
            let utxos = data.unblind_utxos(utxos);

            let mut balances = BTreeMap::<AssetId, u64>::new();
            for utxo in utxos.iter() {
                *balances.entry(utxo.tx_out_sec.asset).or_default() += utxo.tx_out_sec.value;
            }
            send_event(data, Event::BalanceUpdated { balances });
            data.utxos = utxos;
            Ok(())
        }),
    )
    .await?;
    Ok(())
}

async fn request_timeout(reqs: &mut PendingRequests) -> PendingRequest {
    let (&wamp_id, req) = reqs
        .iter()
        .min_by_key(|req| req.1.expires_at)
        .expect("reqs can't be empty");
    let timeout = req.expires_at.saturating_duration_since(Instant::now());
    tokio::time::sleep(timeout).await;
    log::error!("request {wamp_id} timeout");
    reqs.remove(&wamp_id).expect("must be known")
}

async fn connection_check(data: &mut Data) -> Result<(), Error> {
    make_request(
        data,
        "com.greenaddress.addressbook.get_my_addresses",
        vec![data.subaccount.into()],
        Box::new(move |_data, res| {
            let _args = res?;
            log::debug!("connection check succeed");
            Ok(())
        }),
    )
    .await?;
    Ok(())
}

async fn upload_ca_addresses(data: &mut Data, num: u32) -> Result<(), Error> {
    verify!(
        !data.watch_only,
        Error::ProtocolError("can't upload CA addresses from watch-only session")
    );

    log::debug!("upload {num} ca addresses");
    for _ in 0..num {
        recv_addr_request(
            data,
            Box::new(move |data, res| {
                let address = parse_args1::<models::ReceiveAddress>(res?)?;
                let address = data.derive_address(address.pointer);
                data.ca_addresses.push(address.address);
                Ok(())
            }),
        )
        .await?;
    }
    Ok(())
}

async fn send_ca_addresses(data: &mut Data) -> Result<(), Error> {
    let addresses = std::mem::take(&mut data.ca_addresses);
    let addresses = addresses
        .into_iter()
        .map(|a| rmpv::Value::String(a.to_string().into()))
        .collect::<Vec<_>>();
    if !addresses.is_empty() {
        let count = addresses.len();
        log::debug!("send {count} ca addresses...");
        make_request(
            data,
            "com.greenaddress.txs.upload_authorized_assets_confidential_address",
            vec![data.subaccount.into(), addresses.into()],
            Box::new(move |_data, res| {
                let success = parse_args1::<bool>(res?)?;
                verify!(
                    success,
                    Error::ProtocolError("uploading ca addresses failed")
                );
                log::debug!("uploading {count} ca addresses succeed");
                Ok(())
            }),
        )
        .await?;
    }
    Ok(())
}

async fn processing_loop(
    data: &mut Data,
    command_receiver: &mut UnboundedReceiver<Command>,
) -> Result<(), Error> {
    // Prevent "Session expired"
    let mut connection_check_interval = tokio::time::interval(Duration::from_secs(3000));

    loop {
        if data.reload_utxos {
            reload_wallet_utxos(data).await?;
            data.reload_utxos = false;
        }

        if !data.ca_addresses.is_empty() && data.pending_requests.is_empty() {
            send_ca_addresses(data).await?;
        }

        tokio::select! {
            msg = data.connection.next() => {
                let msg = match msg {
                    Some(Ok(msg)) => msg,
                    Some(Err(err)) => return Err(err.into()),
                    None => return Ok(()),
                };
                process_ws_msg(data, msg).await?;
            }

            command = command_receiver.recv() => {
                let command = match command {
                    Some(command) => command,
                    None => return Ok(()),
                };
                process_command(data, command).await?;
            }

            req = request_timeout(&mut data.pending_requests), if !data.pending_requests.is_empty() => {
                (req.callback)(data, Err(Error::RequestTimeout))?;
                // Restart processing just in case
                abort!(Error::ProtocolError("disconnect because of request timeout"));
            }

            _ = connection_check_interval.tick() => {
                connection_check(data).await?;
            }
        }
    }
}

async fn connect(
    login_details: &LoginType,
    event_callback: EventCallback,
    proxy: &Option<ProxyAddress>,
) -> Result<Data, Error> {
    let mut connection = connect_ws(login_details.network(), proxy).await?;

    let master_blinding_key = login_details.get_master_blinding_key()?;

    login(&mut connection).await?;

    let auth_res = match login_details {
        LoginType::Full(signer) => {
            let challenge = get_challenge(&mut connection, signer.as_ref()).await?;
            log::debug!("got challenge: {challenge}");
            authenticate(&mut connection, signer.as_ref(), &challenge).await?
        }
        LoginType::WatchOnly { credentials, .. } => wo_login(&mut connection, credentials).await?,
    };

    let watch_only = match login_details {
        LoginType::Full(_) => false,
        LoginType::WatchOnly { .. } => true,
    };

    let AuthenticateResp {
        gait_path,
        wallet_id,
        amp_subaccount,
        block_height,
        next_subaccount,
    } = match auth_res {
        Some(auth) => {
            log::debug!("authentication succeed");
            auth
        }
        None => {
            log::debug!("authentication failed, try register...");
            let signer = match login_details {
                LoginType::Full(signer) => signer,
                LoginType::WatchOnly { .. } => {
                    return Err(Error::ProtocolError("no wo account found"))
                }
            };

            register(&mut connection, signer.as_ref()).await?;

            let challenge = get_challenge(&mut connection, signer.as_ref()).await?;
            log::debug!("got challenge: {challenge}");
            let auth_res = authenticate(&mut connection, signer.as_ref(), &challenge).await?;

            auth_res.ok_or(Error::ProtocolError(
                "login after registration failed unexpectedly",
            ))?
        }
    };

    let (subaccount, gaid, required_ca) = match amp_subaccount {
        Some(subaccount) => (
            subaccount.pointer,
            subaccount.receiving_id,
            subaccount.required_ca.unwrap_or_default(),
        ),
        None => {
            let signer = match login_details {
                LoginType::Full(signer) => signer,
                LoginType::WatchOnly { .. } => {
                    return Err(Error::ProtocolError("no wo subaccount found"))
                }
            };

            let new_gaid =
                create_subaccount(&mut connection, signer.as_ref(), next_subaccount).await?;
            (next_subaccount, new_gaid, 20)
        }
    };

    let user_xpub = match login_details {
        LoginType::Full(signer) => derive_user_xpub(signer.as_ref(), subaccount)?,

        LoginType::WatchOnly { amp_user_xpub, .. } => *amp_user_xpub,
    };

    let service_xpub = derive_service_xpub(login_details.network(), &gait_path, subaccount)?;

    let network = login_details.network();

    let policy_asset = network.d().policy_asset;

    let mut data = Data {
        policy_asset,
        connection,
        pending_requests: BTreeMap::new(),
        network,
        master_blinding_key,
        subaccount,
        user_xpub,
        service_xpub,
        event_callback,
        pending_subscribe: HashMap::new(),
        active_subscribe: HashMap::new(),
        utxos: Vec::new(),
        reload_utxos: true,
        ca_addresses: Vec::new(),
        block_height,
        watch_only,
        gaid,
    };

    subscribe(
        &mut data,
        "com.greenaddress.blocks".to_owned(),
        block_callback,
    )
    .await?;

    subscribe(
        &mut data,
        format!("com.greenaddress.txs.wallet_{wallet_id}"),
        tx_callback,
    )
    .await?;

    if !data.watch_only {
        upload_ca_addresses(&mut data, required_ca).await?;
    }

    send_event(
        &data,
        Event::Connected {
            gaid: data.gaid.clone(),
            subaccount: data.subaccount,
            block_height: data.block_height,
        },
    );

    Ok(data)
}

async fn run_once(
    mut data: Data,
    mut command_receiver: UnboundedReceiver<Command>,
) -> Result<(), Error> {
    let res = processing_loop(&mut data, &mut command_receiver).await;

    while let Some(req) = data.pending_requests.pop_first() {
        let _ = (req.1.callback)(&mut data, Err(Error::ProtocolError("connection closed")));
    }

    res
}

async fn run_loop(
    login: LoginType,
    mut command_receiver: UnboundedReceiver<Command>,
    event_callback: EventCallback,
    proxy: Option<ProxyAddress>,
) -> Result<(), Error> {
    let mut retry_delay = RetryDelay::default();

    loop {
        let res = tokio::time::timeout(
            Duration::from_secs(60),
            connect(&login, event_callback.clone(), &proxy),
        )
        .await
        .unwrap_or_else(|_err| Err(Error::ProtocolError("connection timeout")));

        match res {
            Ok(mut data) => {
                retry_delay = RetryDelay::default();

                let res = processing_loop(&mut data, &mut command_receiver).await;

                while let Some(req) = data.pending_requests.pop_first() {
                    let _ =
                        (req.1.callback)(&mut data, Err(Error::ProtocolError("connection closed")));
                }

                match res {
                    Ok(()) => {
                        log::debug!("connection closed normally");
                    }
                    Err(err) => {
                        log::error!("connection closed unexpectedly: {err}");
                    }
                }
            }

            Err(err) => {
                log::error!("connection failed: {err}");
                tokio::time::sleep(retry_delay.next_delay()).await;
            }
        }
    }
}

#[cfg(test)]
mod tests;
