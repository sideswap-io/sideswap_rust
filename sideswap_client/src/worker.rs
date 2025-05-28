use std::net::SocketAddr;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use crate::ffi::proto::Account;
use crate::ffi::{self, proto, GIT_COMMIT_HASH};
use crate::gdk_ses::{
    self, ElectrumServer, GdkSes, JadeData, NotifCallback, TransactionList, WalletInfo, WalletNotif,
};
use crate::gdk_ses_amp::{derive_amp_wo_login, GdkSesAmp};
use crate::gdk_ses_rust::{self};
use crate::models::AddressType;
use crate::settings::WatchOnly;
use crate::utils::{
    self, convert_tx, derive_amp_address, derive_native_address, derive_nested_address,
    get_jade_network, get_peg_item, get_tx_size, redact_from_msg, redact_to_msg, TxSize,
};
use crate::{gdk_ses_amp, models, settings};

use anyhow::{anyhow, bail, ensure};
use bitcoin::bip32;
use bitcoin::secp256k1::global::SECP256K1;
use elements::bitcoin::bip32::ChildNumber;
use elements::pset::PartiallySignedTransaction;
use elements::{AssetId, TxOutSecrets};
use elements_miniscript::slip77::MasterBlindingKey;
use log::{debug, error, info, warn};
use market_worker::{get_wallet_account, REGISTER_PATH};
use serde::{Deserialize, Serialize};
use sideswap_amp::sw_signer::SwSigner;
use sideswap_api::mkt::AssetPair;
use sideswap_common::env::Env;
use sideswap_common::event_proofs::EventProofs;
use sideswap_common::network::Network;
use sideswap_common::pset_blind::get_blinding_nonces;
use sideswap_common::recipient::Recipient;
use sideswap_common::send_tx::pset::{
    construct_pset, ConstructPsetArgs, ConstructedPset, PsetInput, PsetOutput,
};
use sideswap_common::types::{self, peg_out_amount, Amount};
use sideswap_common::utxo_select::{self, WalletType};
use sideswap_common::ws::next_request_id;
use sideswap_common::{abort, b64, pin, verify};
use sideswap_jade::jade_mng::{self, JadeStatus, JadeStatusCallback, ManagedJade};
use sideswap_types::fee_rate::FeeRateSats;
use sideswap_types::proxy_address::ProxyAddress;
use tokio::sync::mpsc::UnboundedSender;

use sideswap_api::{self as api, fcm_models, MarketType, OrderId};
use sideswap_common::ws::manual as ws;

pub struct StartParams {
    pub work_dir: String,
    pub version: String,
}

#[derive(thiserror::Error, Debug)]
pub enum CallError {
    #[error("Server error: {0}")]
    Backend(String),
    #[error("{0}")]
    UnregisteredGaid(String),
    #[error("Unknown UTXO, wait for wallet sync")]
    UnknownUtxo,
    #[error("Request timeout")]
    Timeout,
    #[error("Unexpected response")]
    UnexpectedResponse,
    #[error("Disconnected")]
    Disconnected,
}

impl From<sideswap_api::Error> for CallError {
    fn from(value: sideswap_api::Error) -> Self {
        match value.code {
            sideswap_api::ErrorCode::UnregisteredGaid => CallError::UnregisteredGaid(value.message),

            sideswap_api::ErrorCode::UnknownUtxo => CallError::UnknownUtxo,

            sideswap_api::ErrorCode::ParseError
            | sideswap_api::ErrorCode::InvalidRequest
            | sideswap_api::ErrorCode::MethodNotFound
            | sideswap_api::ErrorCode::InvalidParams
            | sideswap_api::ErrorCode::InternalError
            | sideswap_api::ErrorCode::ServerError
            | sideswap_api::ErrorCode::UnknownToken
            | sideswap_api::ErrorCode::Unknown => CallError::Backend(value.message),
        }
    }
}

macro_rules! send_request {
    ($sender:expr, $t:ident, $value:expr, $timeout:expr) => {
        match $sender.send_request(sideswap_api::Request::$t($value), $timeout) {
            Ok(sideswap_api::Response::$t(value)) => Ok(value),
            Ok(_) => Err(CallError::UnexpectedResponse),
            Err(error) => Err(error),
        }
    };
}

macro_rules! send_market_request {
    ($sender:expr, $t:ident, $value:expr, $timeout:expr) => {
        match $sender.send_request(
            sideswap_api::Request::Market(sideswap_api::mkt::Request::$t($value)),
            $timeout,
        ) {
            Ok(sideswap_api::Response::Market(sideswap_api::mkt::Response::$t(value))) => Ok(value),
            Ok(_) => Err(CallError::UnexpectedResponse),
            Err(error) => Err(error),
        }
    };
}

mod assets_registry;
mod market_worker;
mod wallet;

const CLIENT_API_KEY: &str = "f8b7a12ee96aa68ee2b12ebfc51d804a4a404c9732652c298d24099a3d922a84";

pub const USER_AGENT: &str = "SideSwapApp";

const SERVER_REQUEST_TIMEOUT_SHORT: std::time::Duration = std::time::Duration::from_secs(5);
const SERVER_REQUEST_TIMEOUT_LONG: std::time::Duration = std::time::Duration::from_secs(40);
const SERVER_REQUEST_POLL_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

pub const TX_CONF_COUNT_LIQUID: u32 = 2;

const DEFAULT_ICON: &[u8] = include_bytes!("../images/icon_blank.png");

struct ActivePeg {
    order_id: api::OrderId,
}

struct ServerResp(String, Result<api::Response, api::Error>);

type FromCallback = Arc<dyn Fn(proto::from::Msg) -> bool + Send + Sync>;

enum LoginData {
    Mnemonic { mnemonic: bip39::Mnemonic },
    Jade { jade: Arc<ManagedJade> },
}

#[derive(Clone)]
struct UiData {
    from_callback: FromCallback,
    ui_stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Default)]
struct UsedAddresses {
    nested: [u32; 2],
    native: [u32; 2],
    amp: u32,
}

#[derive(Clone)]
struct XPubInfo {
    master_blinding_key: MasterBlindingKey,
    nested_account: bip32::Xpub,
    native_account: bip32::Xpub,
    amp_service_xpub: bip32::Xpub,
    amp_user_xpub: bip32::Xpub,
}

type AsyncRequests =
    BTreeMap<api::RequestId, Box<dyn FnOnce(&mut Data, Result<api::Response, api::Error>)>>;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum TimerEvent {
    SyncUtxos,
    SendAck,
    CleanQuotes,
}

struct CreatedTx {
    pset: PartiallySignedTransaction,
    selected_utxos: Vec<models::Utxo>,
    change_addresses: Vec<models::AddressInfo>,
    blinding_nonces: Vec<String>,
    assets: BTreeSet<AssetId>,
}

pub struct WalletData {
    xpubs: XPubInfo,
    wallet_reg: Arc<dyn GdkSes>,
    wallet_amp: Arc<GdkSesAmp>,
    address_registration_active: bool,
    /// An updated UTXO list (updates whenever the wallet balance changes)
    wallet_utxos: BTreeMap<Account, models::UtxoList>,
    created_txs: BTreeMap<String, CreatedTx>,
    sent_txhash: Option<elements::Txid>,
    used_addresses: UsedAddresses,
    pending_txs: BTreeMap<Account, TransactionList>,
    gaid: Option<String>,
    amp_subaccount: Option<u32>,

    reg_sync_complete: bool,
    wallet_loaded_sent: bool,
    active_extern_peg: Option<ActivePeg>,
    peg_out_server_amounts: Option<LastPegOutAmount>,
    last_recv_address: Option<models::AddressInfo>,
}

#[derive(Clone)]
struct LastPegOutAmount {
    req_amount: i64,
    send_amount: i64,
    recv_amount: i64,
    is_send_entered: bool,
    fee_rate: FeeRateSats,
}

#[derive(PartialEq, Eq)]
struct WalletAddress {
    address_type: AddressType,
    address: elements::Address,
    pointer: u32,
    is_internal: bool,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct AddressPointer {
    address_type: AddressType,
    is_internal: bool,
    pointer: u32,
}

impl From<&WalletAddress> for AddressPointer {
    fn from(value: &WalletAddress) -> Self {
        AddressPointer {
            address_type: value.address_type,
            is_internal: value.is_internal,
            pointer: value.pointer,
        }
    }
}

pub struct Data {
    policy_asset: AssetId,
    active_page: proto::ActivePage,
    app_active: bool,
    amp_connected: bool,
    ws_connected: bool,
    server_status: Option<api::ServerStatus>,
    env: Env,
    ui: UiData,
    market: market_worker::Data,
    assets: BTreeMap<AssetId, api::Asset>,
    amp_assets: BTreeSet<AssetId>,
    msg_sender: mpsc::Sender<Message>,
    ws_sender: UnboundedSender<ws::WrappedRequest>,
    ws_hint: UnboundedSender<()>,
    resp_receiver: mpsc::Receiver<ServerResp>,
    async_requests: AsyncRequests,
    params: StartParams,
    timers: BTreeMap<Instant, TimerEvent>,

    wallet_data: Option<WalletData>,

    settings: settings::Settings,
    push_token: Option<String>,

    jade_mng: jade_mng::JadeMng,

    network_settings: proto::to::NetworkSettings,
    proxy_address: Option<ProxyAddress>,
    wallet_event_callback: wallet::EventCallback,
}

pub enum Message {
    Ui(ffi::ToMsg),
    Ws(ws::WrappedResponse),
    WalletEvent(Account, wallet::Event),
    WalletNotif(Account, WalletNotif),
    BackgroundMessage(String, mpsc::Sender<()>),
    Quit,
}

impl UiData {
    fn send(&self, msg: proto::from::Msg) {
        debug!(
            "to ui: {}",
            serde_json::to_string(&redact_from_msg(msg.clone())).unwrap()
        );
        let result = (self.from_callback)(msg);
        if !result {
            warn!("posting dart message failed");
            self.ui_stopped
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct AssetsCache {
    git_commit_hash: String,
    assets: Vec<api::Asset>,
}

impl Data {
    fn logged_in(&self) -> bool {
        self.wallet_data.is_some()
    }

    fn master_xpub(&mut self) -> bip32::Xpub {
        if self.settings.master_pub_key.is_none() {
            let seed = rand::Rng::gen::<[u8; 32]>(&mut rand::thread_rng());
            let master_priv_key =
                bip32::Xpriv::new_master(bitcoin::Network::Bitcoin, &seed).unwrap();
            let master_pub_key = bitcoin::bip32::Xpub::from_priv(SECP256K1, &master_priv_key);
            self.settings.master_pub_key = Some(master_pub_key);
            self.save_settings();
        }
        self.settings.master_pub_key.unwrap()
    }

    /// Elements of `asset_ids` must be unique
    fn load_gdk_assets<'a>(
        &mut self,
        asset_ids: impl Iterator<Item = &'a AssetId>,
    ) -> Result<Vec<api::Asset>, anyhow::Error> {
        let asset_ids = asset_ids.copied().collect::<Vec<_>>();
        assets_registry::get_assets(self.env, self.master_xpub(), asset_ids, self.proxy())
    }

    fn merge_txs(txs: BTreeMap<Account, TransactionList>) -> TransactionList {
        let mut merged_txs = BTreeMap::<elements::Txid, models::Transaction>::new();

        let tip_height = txs
            .values()
            .map(|resp| resp.tip_height)
            .max()
            .unwrap_or_default();

        for txs_list in txs.values() {
            for tx in txs_list.list.iter() {
                let merged_tx = merged_txs
                    .entry(tx.txid)
                    .or_insert_with(|| models::Transaction {
                        txid: tx.txid,
                        network_fee: tx.network_fee,
                        vsize: tx.vsize,
                        created_at: tx.created_at,
                        block_height: tx.block_height,
                        inputs: Vec::new(),
                        outputs: Vec::new(),
                    });

                merged_tx.inputs.extend_from_slice(&tx.inputs);
                merged_tx.outputs.extend_from_slice(&tx.outputs);
            }
        }

        let mut list = merged_txs.into_values().collect::<Vec<_>>();

        list.sort_by_key(|tx| {
            if tx.block_height == 0 {
                0
            } else {
                u32::MAX - tx.block_height
            }
        });

        TransactionList { tip_height, list }
    }

    fn send_pending_txs(&mut self) {
        let wallet_data = self.wallet_data.as_mut().expect("must be set");

        let merged_txs = Self::merge_txs(wallet_data.pending_txs.clone());

        let sent_tx = wallet_data
            .sent_txhash
            .as_ref()
            .and_then(|sent_txhash| merged_txs.list.iter().find(|tx| tx.txid == *sent_txhash));

        if let Some(sent_tx) = sent_tx {
            let sent_tx = convert_tx(&self.settings.tx_memos, merged_txs.tip_height, sent_tx);
            let result = proto::from::send_result::Result::TxItem(sent_tx);
            self.ui
                .send(proto::from::Msg::SendResult(proto::from::SendResult {
                    result: Some(result),
                }));
            self.wallet_data.as_mut().expect("must be set").sent_txhash = None;
        }

        let items = merged_txs
            .list
            .into_iter()
            .map(|tx| convert_tx(&self.settings.tx_memos, merged_txs.tip_height, &tx))
            .collect::<Vec<_>>();

        self.ui
            .send(proto::from::Msg::UpdatedTxs(proto::from::UpdatedTxs {
                items,
            }));
    }

    fn sync_wallet(&mut self, account: Account) {
        log::debug!("sync wallet {account:?}");

        wallet::callback(
            account,
            self,
            |ses| ses.get_utxos(),
            move |data, res| match res {
                Ok(utxos) => {
                    let wallet_data = match data.wallet_data.as_mut() {
                        Some(wallet_data) => wallet_data,
                        None => return,
                    };

                    for list in utxos.values() {
                        for utxo in list {
                            let last_used = match utxo.wallet_type {
                                WalletType::Native => {
                                    &mut wallet_data.used_addresses.native
                                        [usize::from(utxo.is_internal)]
                                }
                                WalletType::Nested => {
                                    &mut wallet_data.used_addresses.nested
                                        [usize::from(utxo.is_internal)]
                                }
                                WalletType::AMP => &mut wallet_data.used_addresses.amp,
                            };
                            if utxo.pointer > *last_used {
                                *last_used = utxo.pointer;
                            }
                        }
                    }

                    let balances = utxos
                        .iter()
                        .map(|(asset_id, list)| proto::Balance {
                            asset_id: asset_id.to_string(),
                            amount: list.iter().map(|utxo| utxo.satoshi).sum::<u64>() as i64,
                        })
                        .collect();

                    // Refresh wallet UTXOs in the market API.
                    // Do it before sending balances, some tests may fail otherwise.
                    market_worker::wallet_utxos(data, account, utxos);

                    data.ui.send(proto::from::Msg::BalanceUpdate(
                        proto::from::BalanceUpdate {
                            account: account.into(),
                            balances,
                        },
                    ));

                    data.update_address_registrations();
                }
                Err(err) => {
                    log::error!("loading utxos failed: {err}");
                }
            },
        );

        wallet::callback(
            account,
            self,
            |ses| ses.get_transactions(gdk_ses::GetTransactionsOpt::PendingOnly),
            move |data, res| match res {
                Ok(resp) => {
                    if let Some(wallet_data) = data.wallet_data.as_mut() {
                        wallet_data.pending_txs.insert(account, resp);
                        data.send_pending_txs();
                    }
                }
                Err(err) => {
                    log::error!("loading pending txs failed: {err}");
                }
            },
        );
    }

    fn send_wallet_loaded(&mut self) {
        let wallet_data = self.wallet_data.as_mut().expect("must be set");
        if !wallet_data.wallet_loaded_sent {
            wallet_data.wallet_loaded_sent = true;
            self.ui
                .send(proto::from::Msg::WalletLoaded(proto::Empty {}));
        }
    }

    fn resume_peg_monitoring(&mut self) {
        if self.assets.is_empty() || !self.ws_connected {
            return;
        }
        for peg in self.settings.pegs.iter().flatten() {
            self.start_peg_monitoring(peg);
        }
    }

    fn data_path(env: Env, path: &str) -> std::path::PathBuf {
        let env_data = env.d();
        let path = std::path::Path::new(&path).join(env_data.name);
        std::fs::create_dir_all(&path).expect("can't create data path");
        path
    }

    fn get_data_path(&self) -> std::path::PathBuf {
        Data::data_path(self.env, &self.params.work_dir)
    }

    fn cookie_path(&self) -> std::path::PathBuf {
        self.get_data_path().join("sideswap.cookie")
    }
    fn assets_cache_path(&self) -> std::path::PathBuf {
        self.get_data_path().join("assets_cache.json")
    }
    fn assets_cache_path_tmp(&self) -> std::path::PathBuf {
        self.get_data_path().join("assets_cache.json.tmp")
    }
    fn cache_path(&self) -> std::path::PathBuf {
        self.get_data_path().join("cache")
    }
    fn registry_path(&self) -> std::path::PathBuf {
        self.get_data_path().join("registry")
    }

    fn subscribe_price_update(&mut self, asset_id: &AssetId) {
        self.send_request_msg(api::Request::PriceUpdateSubscribe(
            api::PriceUpdateSubscribe { asset: *asset_id },
        ));
    }

    fn register_new_device(&mut self) {
        // register device key if does not exist
        self.make_async_request(
            api::Request::RegisterDevice(api::RegisterDeviceRequest {
                os_type: api::get_os_type(),
            }),
            move |data, res| {
                match res {
                    Ok(api::Response::RegisterDevice(resp)) => {
                        info!("new device_key is registered: {}", resp.device_key);
                        data.settings.device_key = Some(resp.device_key);
                        data.settings.nested_registered = Default::default();
                        data.settings.native_registered = Default::default();
                        data.settings.amp_registered = Default::default();
                        data.save_settings();

                        data.finish_ws_connection();
                    }
                    Ok(_) => {
                        log::error!("unexpected RegisterDevice response");
                    }
                    Err(err) => {
                        log::debug!("RegisterDevice failed: {err}");
                    }
                };
            },
        );
    }

    fn finish_ws_connection(&mut self) {
        self.resume_peg_monitoring();
        self.update_push_token();
        // self.send_subscribe_request();
        self.update_address_registrations();
    }

    fn process_ws_connected(&mut self) {
        info!("connected to server, version: {}", &self.params.version);
        // ws_connected must be set to true before any WS requests are sent
        self.ws_connected = true;

        self.subscribe_active_page(true);

        let cookie = std::fs::read_to_string(self.cookie_path()).ok();
        self.make_async_request(
            api::Request::LoginClient(api::LoginClientRequest {
                api_key: Some(CLIENT_API_KEY.to_owned()),
                cookie,
                user_agent: USER_AGENT.to_owned(),
                version: self.params.version.clone(),
            }),
            move |data, res| {
                match res {
                    Ok(api::Response::LoginClient(resp)) => {
                        let res = std::fs::write(data.cookie_path(), &resp.cookie);
                        if let Err(err) = res {
                            error!("can't write cookie: {}", &err);
                        };
                    }
                    Ok(_) => {
                        log::error!("unexpected LoginClient response");
                    }
                    Err(err) => {
                        log::debug!("LoginClient failed: {err}");
                    }
                };
            },
        );

        self.make_async_request(
            api::Request::Assets(Some(api::AssetsRequestParam {
                embedded_icons: Some(false),
                all_assets: Some(true),
                amp_asset_restrictions: Some(true),
            })),
            move |data, res| {
                match res {
                    Ok(api::Response::Assets(resp)) => {
                        let res = data.save_assets_cache(&resp.assets);
                        if let Err(err) = res {
                            log::error!("saving assets cache failed: {err}");
                        }

                        for asset in resp
                            .assets
                            .iter()
                            .filter(|asset| asset.market_type == Some(MarketType::Stablecoin))
                        {
                            data.subscribe_price_update(&asset.asset_id);
                        }

                        data.amp_assets = resp
                            .assets
                            .iter()
                            .filter_map(|v| {
                                if v.market_type == Some(MarketType::Amp) {
                                    Some(v.asset_id)
                                } else {
                                    None
                                }
                            })
                            .collect();

                        data.ui
                            .send(proto::from::Msg::AmpAssets(proto::from::AmpAssets {
                                assets: data
                                    .amp_assets
                                    .iter()
                                    .map(|asset_id| asset_id.to_string())
                                    .collect(),
                            }));

                        data.register_assets_with_gdk_icons(resp.assets);
                    }
                    Ok(_) => {
                        log::error!("unexpected Assets response");
                    }
                    Err(err) => {
                        log::debug!("Assets failed: {err}");
                    }
                };
            },
        );

        self.make_async_request(api::Request::ServerStatus(None), move |data, res| {
            match res {
                Ok(api::Response::ServerStatus(resp)) => {
                    data.process_server_status(resp);
                }
                Ok(_) => {
                    log::error!("unexpected ServerStatus response");
                }
                Err(err) => {
                    log::debug!("ServerStatus failed: {err}");
                }
            };
        });

        self.make_async_request(
            api::Request::Login(api::LoginRequest {
                session_id: self.settings.session_id,
            }),
            move |data, res| {
                match res {
                    Ok(api::Response::Login(resp)) => {
                        for order in resp.orders {
                            // Cancel old orders
                            data.send_request_msg(api::Request::Cancel(api::CancelRequest {
                                order_id: order.order_id,
                            }));
                        }
                        if Some(&resp.session_id) != data.settings.session_id.as_ref() {
                            data.settings.session_id = Some(resp.session_id);
                            data.save_settings();
                        }
                    }
                    Ok(_) => {
                        log::error!("unexpected Login response");
                    }
                    Err(err) => {
                        log::debug!("Login failed: {err}");
                    }
                };
            },
        );

        // verify device key if exists
        if let Some(device_key) = &self.settings.device_key {
            self.make_async_request(
                api::Request::VerifyDevice(api::VerifyDeviceRequest {
                    device_key: device_key.clone(),
                }),
                |data, res| {
                    match res {
                        Ok(api::Response::VerifyDevice(resp)) => {
                            match resp.device_state {
                                api::DeviceState::Unregistered => {
                                    warn!("device_key is not registered");
                                    data.settings.device_key = None;
                                    data.save_settings();

                                    data.register_new_device();
                                }
                                api::DeviceState::Registered => {
                                    info!("device_key is registered");

                                    data.finish_ws_connection();
                                }
                            };
                        }
                        Ok(_) => {
                            log::error!("unexpected VerifyDevice response");
                        }
                        Err(err) => {
                            log::debug!("VerifyDevice failed: {err}");
                        }
                    };
                },
            );
        } else {
            self.register_new_device();
        }

        // self.process_pending_requests();
        market_worker::ws_connected(self);

        self.ui
            .send(proto::from::Msg::ServerConnected(proto::Empty {}));
    }

    fn process_ws_disconnected(&mut self) {
        warn!("disconnected from server");
        self.ws_connected = false;

        self.ui
            .send(proto::from::Msg::ServerDisconnected(proto::Empty {}));

        let async_requests = std::mem::take(&mut self.async_requests);
        for request in async_requests.into_values() {
            request(
                self,
                Err(api::Error {
                    code: api::ErrorCode::ServerError,
                    message: "Server disconnected".to_owned(),
                }),
            );
        }

        market_worker::ws_disconnected(self);

        if self.logged_in() {
            self.send_ws_connect();
        }

        remove_timers(self, TimerEvent::SendAck);
    }

    fn process_server_status(&mut self, resp: api::ServerStatus) {
        let bitcoin_fee_rates = resp
            .bitcoin_fee_rates
            .iter()
            .map(|item| proto::FeeRate {
                blocks: item.blocks,
                value: item.value.raw(),
            })
            .collect();
        let status_copy = proto::ServerStatus {
            min_peg_in_amount: resp.min_peg_in_amount,
            min_peg_out_amount: resp.min_peg_out_amount,
            server_fee_percent_peg_in: resp.server_fee_percent_peg_in,
            server_fee_percent_peg_out: resp.server_fee_percent_peg_out,
            bitcoin_fee_rates,
        };
        self.ui.send(proto::from::Msg::ServerStatus(status_copy));
        self.server_status = Some(resp);
    }

    fn process_price_update(&mut self, msg: api::PriceUpdateNotification) {
        let asset = match self.assets.get(&msg.asset) {
            Some(v) => v,
            None => return,
        };
        let price_update = proto::from::PriceUpdate {
            asset: asset.asset_id.to_string(),
            bid: msg.price.bid,
            ask: msg.price.ask,
        };
        self.ui.send(proto::from::Msg::PriceUpdate(price_update));
    }

    fn process_wallet_event(&mut self, account_id: Account, event: wallet::Event) {
        let _wallet = match self.get_wallet(account_id) {
            Ok(wallet) => wallet,
            Err(err) => {
                log::debug!("ignore wallet event: {err}");
                return;
            }
        };

        match event {
            wallet::Event::Run(callback) => {
                callback(self);
            }
        }
    }

    fn process_wallet_notif(&mut self, account: Account, notification: WalletNotif) {
        if self.get_wallet(account).is_err() {
            debug!("ignore notification from a deleted wallet, account_id: {account:?}");
            return;
        }

        let wallet_data = self.wallet_data.as_mut().expect("must be set");

        match notification {
            WalletNotif::Transaction(_txid) => {
                self.sync_wallet(account);

                self.ui.send(proto::from::Msg::NewTx(proto::Empty {}));
            }

            WalletNotif::Block => {
                let pending = wallet_data
                    .pending_txs
                    .values()
                    .any(|pending_txs| !pending_txs.list.is_empty());

                // GDK rust sends the Block notification when it loads data from the cache.
                // Send the wallet balance to the UI in this case.
                let unconfirmed_txs_or_wait_sync = !wallet_data.reg_sync_complete || pending;
                if unconfirmed_txs_or_wait_sync {
                    self.sync_wallet(account)
                }

                self.ui.send(proto::from::Msg::NewBlock(proto::Empty {}));
            }

            WalletNotif::AccountSynced => {
                // GDK rust takes about 10 seconds to sync even if it's cached
                debug!("sync_complete, account_id: {account:?}");
                if !wallet_data.reg_sync_complete {
                    wallet_data.reg_sync_complete = true;
                    self.send_wallet_loaded();
                    // self.process_pending_requests();
                    self.ui
                        .send(proto::from::Msg::SyncComplete(proto::Empty {}));
                }

                self.sync_wallet(account);
            }

            WalletNotif::AmpConnected { subaccount, gaid } => {
                wallet_data.amp_subaccount = Some(subaccount);
                wallet_data.gaid = Some(gaid.clone());

                self.ui
                    .send(proto::from::Msg::RegisterAmp(proto::from::RegisterAmp {
                        result: Some(proto::from::register_amp::Result::AmpId(gaid.clone())),
                    }));

                log::debug!("AMP connected");
                self.amp_connected = true;
                self.update_address_registrations();

                self.sync_wallet(account);
            }

            WalletNotif::AmpDisconnected => {
                log::debug!("AMP disconnected");
                self.amp_connected = false;
            }

            WalletNotif::AmpFailed { error_msg } => {
                log::warn!("AMP failed: {error_msg}");
                self.show_message(&format!("AMP connection failed: {error_msg}"));
                self.amp_connected = false;
            }

            WalletNotif::AmpBalanceUpdated => {
                self.sync_wallet(account);
            }
        }
    }

    fn try_process_pegout_amount(
        &mut self,
        req: proto::to::PegOutAmount,
    ) -> Result<proto::from::peg_out_amount::Amounts, anyhow::Error> {
        ensure!(self.ws_connected, "not connected");

        let wallet_data = self
            .wallet_data
            .as_mut()
            .ok_or_else(|| anyhow!("no wallet_data"))?;

        let utxos = wallet_data
            .wallet_utxos
            .values()
            .flat_map(|account| account.get(&self.policy_asset))
            .flatten()
            .collect::<Vec<_>>();

        let server_status = self
            .server_status
            .as_ref()
            .ok_or(anyhow!("server_status is not known"))?;

        let amount = if req.is_send_entered {
            ensure!(
                req.amount >= server_status.min_peg_out_amount,
                "Min {}",
                Amount::from_sat(server_status.min_peg_out_amount).to_bitcoin()
            );

            let utxo_select_res = utxo_select::select(utxo_select::Args {
                policy_asset: self.policy_asset,
                utxos: utxos
                    .iter()
                    .map(|utxo| utxo_select::Utxo {
                        wallet: utxo.wallet_type,
                        txid: utxo.txhash,
                        vout: utxo.vout,
                        asset_id: utxo.asset_id,
                        value: utxo.satoshi,
                    })
                    .collect(),
                recipients: vec![utxo_select::Recipient {
                    address: utxo_select::RecipientAddress::Unknown(WalletType::Native),
                    asset_id: self.policy_asset,
                    amount: req.amount as u64,
                }],
                deduct_fee: Some(0),
                force_change_wallets: BTreeMap::from([(self.policy_asset, WalletType::Native)]),
                use_all_utxos: false,
            })?;

            req.amount as u64 - utxo_select_res.network_fee
        } else {
            req.amount as u64
        };

        let fee_rate = FeeRateSats::from_raw(req.fee_rate);

        let amounts = peg_out_amount(types::PegOutAmountReq {
            amount: amount as i64,
            is_send_entered: req.is_send_entered,
            fee_rate,
            min_peg_out_amount: server_status.min_peg_out_amount,
            server_fee_percent_peg_out: server_status.server_fee_percent_peg_out,
            peg_out_bitcoin_tx_vsize: server_status.peg_out_bitcoin_tx_vsize,
        })?;

        wallet_data.peg_out_server_amounts = Some(LastPegOutAmount {
            req_amount: req.amount,
            send_amount: amounts.send_amount,
            recv_amount: amounts.recv_amount,
            is_send_entered: req.is_send_entered,
            fee_rate,
        });

        Ok(proto::from::peg_out_amount::Amounts {
            send_amount: amounts.send_amount,
            recv_amount: amounts.recv_amount,
            fee_rate: req.fee_rate,
            is_send_entered: req.is_send_entered,
        })
    }

    fn process_pegout_amount(&mut self, req: proto::to::PegOutAmount) {
        let res = match self.try_process_pegout_amount(req) {
            Ok(amounts) => proto::from::peg_out_amount::Result::Amounts(amounts),
            Err(err) => {
                error!("peg-out amount failed: {}", err);
                proto::from::peg_out_amount::Result::ErrorMsg(err.to_string())
            }
        };
        let amounts_result = proto::from::PegOutAmount { result: Some(res) };
        self.ui.send(proto::from::Msg::PegOutAmount(amounts_result));
    }

    fn try_process_pegout_request(
        &mut self,
        req: proto::to::PegOutRequest,
    ) -> Result<OrderId, anyhow::Error> {
        ensure!(self.ws_connected, "not connected");

        let server_status = self
            .server_status
            .as_ref()
            .ok_or(anyhow!("server_status is not known"))?;
        ensure!(
            req.send_amount >= server_status.min_peg_out_amount,
            "Min {}",
            Amount::from_sat(server_status.min_peg_out_amount)
                .to_bitcoin()
                .to_string()
        );

        let wallet_data = self
            .wallet_data
            .as_ref()
            .ok_or_else(|| anyhow!("no wallet_data"))?;

        let peg_out_server_amounts = wallet_data
            .peg_out_server_amounts
            .clone()
            .ok_or_else(|| anyhow!("peg_out_server_amounts is None"))?;

        let device_key = self
            .settings
            .device_key
            .as_ref()
            .ok_or_else(|| anyhow!("device_key is None"))?
            .clone();

        let resp = send_request!(
            self,
            Peg,
            api::PegRequest {
                recv_addr: req.recv_addr.clone(),
                send_amount: None,
                peg_in: false,
                device_key: Some(device_key),
                blocks: Some(req.blocks),
                peg_out_amounts: Some(api::PegOutAmounts {
                    send_amount: peg_out_server_amounts.send_amount,
                    recv_amount: peg_out_server_amounts.recv_amount,
                    is_send_entered: peg_out_server_amounts.is_send_entered,
                    fee_rate: peg_out_server_amounts.fee_rate
                }),
                fee_rate: None,
            },
            SERVER_REQUEST_TIMEOUT_LONG
        )?;

        self.add_peg_monitoring(resp.order_id, settings::PegDir::Out);

        let (send_amount, deduct_fee_output) = if peg_out_server_amounts.is_send_entered {
            (peg_out_server_amounts.req_amount, Some(0))
        } else {
            (peg_out_server_amounts.send_amount, None)
        };

        let created_tx = self.try_create_tx(proto::CreateTx {
            addressees: vec![proto::AddressAmount {
                address: resp.peg_addr,
                amount: send_amount,
                asset_id: self.policy_asset.to_string(),
            }],
            utxos: Vec::new(),
            fee_asset_id: None,
            deduct_fee_output,
        })?;

        // TODO: Verify that the network fee did not change

        self.try_send_tx(proto::to::SendTx { id: created_tx.id })?;

        Ok(resp.order_id)
    }

    fn process_pegout_request(&mut self, req: proto::to::PegOutRequest) {
        let result = self.try_process_pegout_request(req);
        match result {
            Ok(order_id) => {
                let wallet_data = self.wallet_data.as_mut().expect("must bet set");
                wallet_data.active_extern_peg = Some(ActivePeg { order_id });
            }
            Err(e) => {
                error!("starting peg-out failed: {}", e);
                self.ui.send(proto::from::Msg::SwapFailed(e.to_string()));
            }
        }
    }

    fn try_process_pegin_request(&mut self) -> Result<proto::from::PeginWaitTx, anyhow::Error> {
        ensure!(self.ws_connected, "not connected");

        let device_key = self
            .settings
            .device_key
            .as_ref()
            .ok_or_else(|| anyhow!("device_key is None"))?
            .clone();

        let account = Account::Reg;

        let recv_addr = wallet::call(account, self, |ses| ses.get_receive_address())?.address;

        let resp = send_request!(
            self,
            Peg,
            api::PegRequest {
                recv_addr: recv_addr.to_string(),
                send_amount: None,
                peg_in: true,
                device_key: Some(device_key),
                blocks: None,
                peg_out_amounts: None,
                fee_rate: None,
            },
            SERVER_REQUEST_TIMEOUT_LONG
        )?;

        self.add_peg_monitoring(resp.order_id, settings::PegDir::In);

        let msg = proto::from::PeginWaitTx {
            order_id: resp.order_id.to_string(),
            peg_addr: resp.peg_addr,
            recv_addr: recv_addr.to_string(),
        };

        let wallet_data = self.wallet_data.as_mut().expect("must bet set");
        wallet_data.active_extern_peg = Some(ActivePeg {
            order_id: resp.order_id,
        });
        Ok(msg)
    }

    fn process_pegin_request(&mut self) {
        let result = self.try_process_pegin_request();
        match result {
            Ok(v) => {
                self.ui.send(proto::from::Msg::PeginWaitTx(v));
            }
            Err(e) => {
                error!("starting peg-in failed: {}", e);
                self.ui.send(proto::from::Msg::SwapFailed(e.to_string()));
            }
        }
    }

    fn process_get_recv_address(&mut self, account: proto::Account) {
        wallet::callback(
            account,
            self,
            |ses| ses.get_receive_address(),
            move |data, res| match res {
                Ok(addr_info) => {
                    let wallet_data = data.wallet_data.as_mut().expect("must be set");
                    data.ui
                        .send(proto::from::Msg::RecvAddress(proto::from::RecvAddress {
                            addr: proto::Address {
                                addr: addr_info.address.to_string(),
                            },
                            account: account.into(),
                        }));
                    wallet_data.last_recv_address = Some(addr_info);
                }
                Err(err) => data.show_message(&err.to_string()),
            },
        );
    }

    fn get_selected_utxos<'a>(
        utxos: impl Iterator<Item = &'a models::Utxo>,
        selected: &[ffi::proto::OutPoint],
    ) -> Result<Vec<models::Utxo>, anyhow::Error> {
        let selected_outpoints = selected
            .iter()
            .map(|outpoint| -> Result<elements::OutPoint, anyhow::Error> {
                Ok(elements::OutPoint {
                    txid: outpoint.txid.parse()?,
                    vout: outpoint.vout,
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        ensure!(selected_outpoints.len() == selected.len());

        let mut inputs = Vec::new();
        for utxo in utxos {
            if selected_outpoints.contains(&elements::OutPoint {
                txid: utxo.txhash,
                vout: utxo.vout,
            }) {
                inputs.push(utxo.clone());
            }
        }
        ensure!(
            selected.len() == inputs.len(),
            "Not all UTXOs found, please try again"
        );

        Ok(inputs)
    }

    fn get_change_address(&self) -> Result<models::AddressInfo, anyhow::Error> {
        wallet::call(Account::Reg, self, |ses| ses.get_change_address())
    }

    fn try_create_tx(&mut self, req: proto::CreateTx) -> Result<proto::CreatedTx, anyhow::Error> {
        let wallet_data = self
            .wallet_data
            .as_ref()
            .ok_or_else(|| anyhow!("no wallet_data"))?;

        let use_all_utxos = !req.utxos.is_empty();
        let all_utxos = wallet_data
            .wallet_utxos
            .values()
            .flat_map(|utxos| utxos.values())
            .flatten();
        let utxos = if !use_all_utxos {
            all_utxos.cloned().collect::<Vec<_>>()
        } else {
            Self::get_selected_utxos(all_utxos, &req.utxos)?
        };

        let recipients = req
            .addressees
            .iter()
            .map(|addr| -> Result<Recipient, anyhow::Error> {
                Ok(Recipient {
                    asset_id: AssetId::from_str(&addr.asset_id)?,
                    amount: addr.amount.try_into()?,
                    address: elements::Address::from_str(&addr.address)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(!recipients.is_empty());

        let fee_asset = req
            .fee_asset_id
            .as_ref()
            .map(|asset_id| AssetId::from_str(asset_id))
            .transpose()?;

        let assets = recipients
            .iter()
            .map(|recipient| recipient.asset_id)
            .chain(fee_asset.iter().copied())
            .collect::<BTreeSet<_>>();

        if let Some(fee_asset) = fee_asset {
            let deduct_fee = req.deduct_fee_output.map(|index| index as usize);
            if let Some(index) = deduct_fee {
                let recipient = recipients
                    .get(index)
                    .ok_or_else(|| anyhow!("no output with index {index}"))?;
                ensure!(
                    recipient.asset_id == fee_asset,
                    "can't deduct fee from the specified output"
                );
            }

            let payjoin_utxos = utxos
                .iter()
                .map(|utxo| sideswap_payjoin::Utxo {
                    wallet_type: utxo.wallet_type,
                    txid: utxo.txhash,
                    vout: utxo.vout,
                    script_pub_key: utxo.script_pub_key.clone(),
                    asset_id: utxo.asset_id,
                    value: utxo.satoshi,
                    asset_bf: utxo.assetblinder,
                    value_bf: utxo.amountblinder,
                })
                .collect::<Vec<_>>();

            let network = self.env.d().network;
            let base_url = self.env.base_server_http_url();

            let mut change_addresses = Vec::<models::AddressInfo>::new();

            let mut change_cb = || {
                let address_info = self.get_change_address()?;
                let address = address_info.address.clone();
                change_addresses.push(address_info);
                Ok(address)
            };

            let resp = sideswap_payjoin::create_payjoin(
                &mut change_cb,
                sideswap_payjoin::CreatePayjoin {
                    network,
                    base_url,
                    user_agent: USER_AGENT.to_owned(),
                    utxos: payjoin_utxos,
                    use_all_utxos,
                    recipients,
                    deduct_fee,
                    fee_asset,
                },
            )?;

            let tx = resp.pset.extract_tx()?;

            let id = tx.txid().to_string();

            let TxSize {
                input_count,
                output_count,
                size,
                vsize,
                discount_vsize,
                network_fee,
                fee_per_byte,
            } = get_tx_size(tx, &self.policy_asset, &utxos);

            let outpoints = resp
                .pset
                .inputs()
                .iter()
                .map(|input| elements::OutPoint {
                    txid: input.previous_txid,
                    vout: input.previous_output_index,
                })
                .collect::<BTreeSet<_>>();

            let selected_utxos = utxos
                .into_iter()
                .filter(|utxo| {
                    outpoints.contains(&elements::OutPoint {
                        txid: utxo.txhash,
                        vout: utxo.vout,
                    })
                })
                .collect::<Vec<_>>();

            let wallet_data = self.wallet_data.as_mut().expect("must bet set");
            wallet_data.created_txs.insert(
                id.clone(),
                CreatedTx {
                    pset: resp.pset,
                    selected_utxos,
                    change_addresses,
                    blinding_nonces: resp.blinding_nonces,
                    assets,
                },
            );

            let mut addressees = req.addressees.clone();
            if let Some(index) = req.deduct_fee_output {
                addressees[index as usize].amount -= resp.asset_fee as i64;
            }

            Ok(ffi::proto::CreatedTx {
                id,
                req,
                input_count,
                output_count,
                size,
                vsize,
                discount_vsize,
                network_fee,
                server_fee: Some(resp.asset_fee as i64),
                fee_per_byte,
                addressees,
            })
        } else {
            // Prefer to receive stablecoin and L-BTC change to the native segwit account
            let force_change_wallets = self
                .assets
                .values()
                .filter_map(|asset| {
                    (asset.market_type == Some(MarketType::Stablecoin)
                        || asset.asset_id == self.policy_asset)
                        .then_some((asset.asset_id, WalletType::Native))
                })
                .collect::<BTreeMap<_, _>>();

            let utxo_select_res = utxo_select::select(utxo_select::Args {
                policy_asset: self.policy_asset,
                utxos: utxos
                    .iter()
                    .map(|utxo| utxo_select::Utxo {
                        wallet: utxo.wallet_type,
                        txid: utxo.txhash,
                        vout: utxo.vout,
                        asset_id: utxo.asset_id,
                        value: utxo.satoshi,
                    })
                    .collect(),
                recipients: recipients
                    .into_iter()
                    .map(|addr| utxo_select::Recipient {
                        address: utxo_select::RecipientAddress::Known(addr.address),
                        asset_id: addr.asset_id,
                        amount: addr.amount,
                    })
                    .collect(),
                deduct_fee: req.deduct_fee_output.map(|index| index as usize),
                force_change_wallets,
                use_all_utxos,
            })?;

            let utxo_select::Res {
                inputs,
                updated_recipients,
                change,
                network_fee,
            } = utxo_select_res;

            let selected_utxos = inputs
                .iter()
                .map(|selected| {
                    utxos
                        .iter()
                        .find(|utxo| utxo.txhash == selected.txid && utxo.vout == selected.vout)
                        .expect("UTXO must exist")
                })
                .collect::<Vec<_>>();

            let inputs = selected_utxos
                .iter()
                .map(|utxo| PsetInput {
                    txid: utxo.txhash,
                    vout: utxo.vout,
                    script_pub_key: utxo.script_pub_key.clone(),
                    asset_commitment: utxo.asset_commitment,
                    value_commitment: utxo.value_commitment,
                    tx_out_sec: TxOutSecrets {
                        asset: utxo.asset_id,
                        asset_bf: utxo.assetblinder,
                        value: utxo.satoshi,
                        value_bf: utxo.amountblinder,
                    },
                })
                .collect::<Vec<_>>();

            let mut outputs = Vec::<PsetOutput>::new();
            for recipient in updated_recipients.iter() {
                outputs.push(PsetOutput {
                    address: recipient.address.known().expect("must be know").clone(),
                    asset_id: recipient.asset_id,
                    amount: recipient.amount,
                });
            }

            let mut change_addresses = Vec::new();
            for output in change {
                let account = get_wallet_account(output.wallet);
                let change_address = market_worker::get_address(
                    self,
                    account,
                    market_worker::AddressType::Change,
                    market_worker::CachePolicy::Skip,
                )?;
                outputs.push(PsetOutput {
                    address: change_address.address.clone(),
                    asset_id: output.asset_id,
                    amount: output.value,
                });
                change_addresses.push(change_address);
            }

            let ConstructedPset {
                blinded_pset: pset,
                blinded_outputs,
            } = construct_pset(ConstructPsetArgs {
                policy_asset: self.policy_asset,
                offlines: Vec::new(),
                inputs,
                outputs,
                network_fee,
            })?;

            let tx = pset.extract_tx()?;
            let id = tx.txid().to_string();

            let wallet_data = self
                .wallet_data
                .as_mut()
                .ok_or_else(|| anyhow!("wallet not found"))?;

            let TxSize {
                input_count,
                output_count,
                size,
                vsize,
                discount_vsize,
                network_fee,
                fee_per_byte,
            } = get_tx_size(tx, &self.policy_asset, &utxos);

            let outpoints = pset
                .inputs()
                .iter()
                .map(|input| elements::OutPoint {
                    txid: input.previous_txid,
                    vout: input.previous_output_index,
                })
                .collect::<BTreeSet<_>>();

            let selected_utxos = utxos
                .into_iter()
                .filter(|utxo| {
                    outpoints.contains(&elements::OutPoint {
                        txid: utxo.txhash,
                        vout: utxo.vout,
                    })
                })
                .collect::<Vec<_>>();

            wallet_data.created_txs.insert(
                id.clone(),
                CreatedTx {
                    pset,
                    selected_utxos,
                    change_addresses,
                    blinding_nonces: get_blinding_nonces(&blinded_outputs),
                    assets,
                },
            );

            let mut addressees = req.addressees.clone();
            assert!(addressees.len() == updated_recipients.len());
            if let Some(index) = req.deduct_fee_output {
                addressees[index as usize].amount =
                    updated_recipients[index as usize].amount as i64;
            }

            Ok(proto::CreatedTx {
                id,
                req,
                input_count,
                output_count,
                size,
                vsize,
                discount_vsize,
                network_fee,
                server_fee: None,
                fee_per_byte,
                addressees,
            })
        }
    }

    fn process_create_tx(&mut self, req: proto::CreateTx) {
        let res = self.try_create_tx(req);

        let res = match res {
            Ok(created_tx) => proto::from::create_tx_result::Result::CreatedTx(created_tx),
            Err(err) => proto::from::create_tx_result::Result::ErrorMsg(err.to_string()),
        };
        self.ui.send(proto::from::Msg::CreateTxResult(
            proto::from::CreateTxResult { result: Some(res) },
        ));
    }

    fn try_send_tx(&mut self, req: proto::to::SendTx) -> Result<elements::Txid, anyhow::Error> {
        let wallet_data = self
            .wallet_data
            .as_mut()
            .ok_or_else(|| anyhow!("wallet not found"))?;

        let created_tx = wallet_data
            .created_txs
            .remove(&req.id)
            .ok_or_else(|| anyhow!("can't find created tx"))?;

        let selected_utxos = created_tx.selected_utxos.iter().collect::<Vec<_>>();
        let change_addresses = created_tx.change_addresses.iter().collect::<Vec<_>>();

        // FIXME: We should not show L-BTC output to the server for review on Jade with payjoins
        let pset = if market_worker::is_jade(self) {
            market_worker::try_sign_pset_jade(
                self,
                &selected_utxos,
                &[],
                &change_addresses,
                None,
                created_tx.pset,
                created_tx.assets,
                Some(&created_tx.blinding_nonces),
                jade_mng::TxType::Normal,
            )?
        } else {
            market_worker::try_sign_pset_software(self, created_tx.pset)?
        };

        let need_green_signature = selected_utxos.iter().any(|utxo| match utxo.wallet_type {
            WalletType::Native | WalletType::Nested => false,
            WalletType::AMP => true,
        });

        let pset = if need_green_signature {
            let wallet_data = self
                .wallet_data
                .as_mut()
                .ok_or_else(|| anyhow!("wallet not found"))?;

            wallet_data
                .wallet_amp
                .green_backend_sign(pset, created_tx.blinding_nonces)?
        } else {
            pset
        };

        let tx = pset.extract_tx()?;
        let txid = tx.txid();
        let tx = elements::encode::serialize_hex(&tx);

        wallet::call(Account::Reg, self, move |ses| {
            ses.broadcast_tx(&tx)?;
            Ok(())
        })?;

        Ok(txid)
    }

    fn process_send_tx(&mut self, req: proto::to::SendTx) {
        let res = self.try_send_tx(req);

        match res {
            Ok(txid) => {
                self.wallet_data.as_mut().expect("must be set").sent_txhash = Some(txid);
            }
            Err(err) => self
                .ui
                .send(proto::from::Msg::SendResult(proto::from::SendResult {
                    result: Some(proto::from::send_result::Result::ErrorMsg(err.to_string())),
                })),
        }
    }

    fn process_blinded_values(
        &mut self,
        proto::to::BlindedValues { txid }: proto::to::BlindedValues,
    ) {
        let txid = elements::Txid::from_str(&txid).expect("must be valid txid");

        let mut res_receivers = Vec::new();
        if let Some(wallet_data) = self.wallet_data.as_mut() {
            let wallets: [Arc<dyn GdkSes>; 2] = [
                wallet_data.wallet_reg.clone(),
                wallet_data.wallet_amp.clone(),
            ];
            for wallet in wallets {
                let res_receiver = wallet::send_wallet(&wallet, move |ses| {
                    ses.get_transactions(gdk_ses::GetTransactionsOpt::All)
                });
                res_receivers.push(res_receiver);
            }
        }

        let blinded_values = res_receivers
            .iter()
            .filter_map(|res_receiver| res_receiver.recv().expect("channel must be open").ok())
            .filter_map(|tx_list| tx_list.list.into_iter().find(|tx| tx.txid == txid))
            .flat_map(|tx| tx.inputs.into_iter().chain(tx.outputs))
            .flat_map(|in_out| {
                [
                    in_out.unblinded.value.to_string(),
                    in_out.unblinded.asset.to_string(),
                    in_out.unblinded.value_bf.to_string(),
                    in_out.unblinded.asset_bf.to_string(),
                ]
            })
            .collect::<Vec<_>>();

        let result = proto::from::blinded_values::Result::BlindedValues(blinded_values.join(","));
        let blinded_values = proto::from::BlindedValues {
            txid: txid.to_string(),
            result: Some(result),
        };
        self.ui
            .send(proto::from::Msg::BlindedValues(blinded_values));
    }

    // logins

    fn get_notif_callback(&self) -> NotifCallback {
        let msg_sender = self.msg_sender.clone();

        Box::new(move |account_id, details| {
            let result = msg_sender.send(Message::WalletNotif(account_id, details));
            if let Err(e) = result {
                error!("sending notification message failed: {}", e);
            }
        })
    }

    fn electrum_server(&self) -> ElectrumServer {
        match self.network_settings.selected.as_ref() {
            Some(proto::to::network_settings::Selected::Sideswap(_)) | None => {
                ElectrumServer::SideSwap
            }
            Some(proto::to::network_settings::Selected::SideswapCn(_)) => {
                ElectrumServer::SideSwapCn
            }
            Some(proto::to::network_settings::Selected::Blockstream(_)) => {
                ElectrumServer::Blockstream
            }
            Some(proto::to::network_settings::Selected::Custom(
                proto::to::network_settings::Custom {
                    host,
                    port,
                    use_tls,
                },
            )) => ElectrumServer::Custom {
                host: host.clone(),
                port: *port as u16,
                use_tls: *use_tls,
            },
        }
    }

    fn proxy(&self) -> &Option<ProxyAddress> {
        &self.proxy_address
    }

    fn try_register(&mut self, login: &LoginData) -> Result<settings::RegInfo, anyhow::Error> {
        log::debug!("try register...");
        if self.env == Env::LocalRegtest {
            return Ok(settings::RegInfo {
                watch_only: None,
                amp_service_xpub: "tpubECMbgHMZm4QymM7WtpQonF5cU5x54M54QvLFsGjEY3HWx8YPxqZ7nq3PiaQSEjeDwCwpYr4heLC8N7kP74HYGKjoycutoZ4VACJmco16btA".parse().expect("must not fail"),
                amp_user_path: vec![2147483651, 2147483649, 1],
            });
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("must not fail");

        let event_callback = Arc::new(|_event| {});

        let _enter_guard = runtime.enter();

        let amp_wallet = match &login {
            LoginData::Mnemonic { mnemonic } => {
                runtime.block_on(sideswap_amp::Wallet::connect_once(
                    &sideswap_amp::LoginType::Full(Arc::new(SwSigner::new(
                        self.env.d().network,
                        mnemonic,
                    ))),
                    event_callback,
                    self.proxy(),
                ))?
            }

            LoginData::Jade { jade } => {
                utils::unlock_hw(self.env, jade)?;

                let jade_data = JadeData {
                    env: self.env,
                    jade: jade.clone(),
                };

                runtime.block_on(sideswap_amp::Wallet::connect_once(
                    &sideswap_amp::LoginType::Full(Arc::new(jade_data)),
                    event_callback,
                    self.proxy(),
                ))?
            }
        };

        let new_address = runtime.block_on(amp_wallet.receive_address())?;
        let amp_service_xpub = new_address.service_xpub;
        let amp_user_path = new_address.user_path[0..3].to_vec();

        let watch_only = match login {
            LoginData::Mnemonic { mnemonic: _ } => None,
            LoginData::Jade { jade } => {
                let credentials = derive_amp_wo_login(amp_wallet.master_blinding_key());

                runtime.block_on(amp_wallet.set_watch_only(credentials))?;

                let jade_data = JadeData {
                    env: self.env,
                    jade: jade.clone(),
                };

                let nested_path = self.env.nd().account_path_sh_wpkh;
                let native_path = self.env.nd().account_path_wpkh;

                let network = utils::get_jade_network(self.env);

                let root_xpub = jade_data.resolve_xpub(network, &[])?;
                // let password_xpub = jade_data.resolve_xpub(network, &XPUB_PATH_PASS)?;
                let nested_xpub = jade_data.resolve_xpub(network, &nested_path)?;
                let native_xpub = jade_data.resolve_xpub(network, &native_path)?;

                let amp_user_xpub = jade_data.resolve_xpub(network, &amp_user_path)?;

                let master_blinding_key = (*amp_wallet.master_blinding_key()).into();

                let master_xpub_fingerprint = root_xpub.fingerprint();

                Some(WatchOnly {
                    master_xpub_fingerprint,
                    master_blinding_key,
                    native_xpub,
                    nested_xpub,
                    amp_user_xpub,
                })
            }
        };

        Ok(settings::RegInfo {
            watch_only,
            amp_service_xpub,
            amp_user_path,
        })
    }

    fn try_process_login_request(&mut self, req: proto::to::Login) -> Result<(), anyhow::Error> {
        debug!("process login request...");

        let cache_dir = self.cache_path();

        let wallet = req.wallet.ok_or_else(|| anyhow!("empty login request"))?;

        let login_data = match wallet {
            proto::to::login::Wallet::Mnemonic(mnemonic) => {
                let mnemonic = bip39::Mnemonic::from_str(&mnemonic)?;
                LoginData::Mnemonic { mnemonic }
            }

            proto::to::login::Wallet::JadeId(jade_id) => {
                let proxy = self.proxy().clone();
                let jade = self.jade_mng.open(&jade_id, &proxy)?;
                LoginData::Jade {
                    jade: Arc::new(jade),
                }
            }
        };

        let reg_info = match self.settings.reg_info.clone() {
            Some(reg_info) => reg_info,
            None => {
                let reg_info = self.try_register(&login_data)?;
                self.settings.reg_info = Some(reg_info.clone());
                self.save_settings();
                reg_info
            }
        };

        let wallet_info = match login_data {
            LoginData::Mnemonic { mnemonic } => WalletInfo::Mnemonic(mnemonic.clone()),

            LoginData::Jade { jade } => {
                let watch_only = reg_info
                    .watch_only
                    .as_ref()
                    .ok_or_else(|| anyhow!("watch_only is not set"))?
                    .clone();

                WalletInfo::Jade(
                    gdk_ses::JadeData {
                        env: self.env,
                        jade,
                    },
                    watch_only,
                )
            }
        };

        let wallet_reg = {
            let info_reg = gdk_ses::LoginInfo {
                account: Account::Reg,
                env: self.env,
                cache_dir: cache_dir.clone(),
                wallet_info: wallet_info.clone(),
                electrum_server: self.electrum_server(),
                proxy: self.proxy().clone(),
            };

            gdk_ses_rust::start_processing(info_reg, self.get_notif_callback())
        };

        let wallet_amp = {
            let info_amp = gdk_ses::LoginInfo {
                account: Account::Amp,
                env: self.env,
                cache_dir: cache_dir.clone(),
                wallet_info: wallet_info.clone(),
                electrum_server: self.electrum_server(),
                proxy: self.proxy().clone(),
            };

            gdk_ses_amp::start_processing(info_amp, self.get_notif_callback())
        };

        let nested_account_path = self.env.nd().account_path_sh_wpkh;
        let native_account_path = self.env.nd().account_path_wpkh;
        let amp_service_xpub = reg_info.amp_service_xpub;
        let amp_user_path = reg_info.amp_user_path.clone();

        let (nested_account, native_account, amp_user_xpub, master_blinding_key) =
            if let Some(watch_only) = reg_info.watch_only.as_ref() {
                (
                    watch_only.nested_xpub,
                    watch_only.native_xpub,
                    watch_only.amp_user_xpub,
                    watch_only.master_blinding_key.into_inner(),
                )
            } else {
                let mnemonic = wallet_info.mnemonic().expect("mnemonic must be set");
                let seed = mnemonic.to_seed("");
                let bitcoin_network = self.env.d().network.d().bitcoin_network;
                let master_key = bip32::Xpriv::new_master(bitcoin_network, &seed).unwrap();
                let master_blinding_key = MasterBlindingKey::from_seed(&seed);

                let register_priv = master_key
                    .derive_priv(
                        SECP256K1,
                        &REGISTER_PATH
                            .iter()
                            .map(|num| ChildNumber::from(*num))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap()
                    .private_key;
                let nested_xpriv = master_key
                    .derive_priv(
                        SECP256K1,
                        &nested_account_path
                            .iter()
                            .map(|num| ChildNumber::from(*num))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap();
                let native_xpriv = master_key
                    .derive_priv(
                        SECP256K1,
                        &native_account_path
                            .iter()
                            .map(|num| ChildNumber::from(*num))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap();
                let amp_xpriv = master_key
                    .derive_priv(
                        SECP256K1,
                        &amp_user_path
                            .iter()
                            .map(|num| ChildNumber::from(*num))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap();

                let event_proofs = self
                    .settings
                    .event_proofs
                    .as_ref()
                    .map(|event_proofs| {
                        serde_json::from_value::<EventProofs>(event_proofs.clone())
                            .expect("must not fail")
                    })
                    .unwrap_or_else(|| {
                        EventProofs::new(self.env, register_priv.public_key(SECP256K1))
                    });

                market_worker::set_xprivs(
                    self,
                    market_worker::Xprivs {
                        register_priv,
                        nested_xpriv,
                        native_xpriv,
                        amp_xpriv,
                        event_proofs,
                        ack_succeed: false,
                        expected_nonce: None,
                    },
                );

                (
                    bip32::Xpub::from_priv(SECP256K1, &nested_xpriv),
                    bip32::Xpub::from_priv(SECP256K1, &native_xpriv),
                    bip32::Xpub::from_priv(SECP256K1, &amp_xpriv),
                    master_blinding_key,
                )
            };

        let xpubs = XPubInfo {
            nested_account,
            native_account,
            amp_service_xpub,
            amp_user_xpub,
            master_blinding_key,
        };

        self.wallet_data = Some(WalletData {
            xpubs,
            wallet_reg,
            wallet_amp,
            address_registration_active: false,
            wallet_utxos: BTreeMap::new(),
            created_txs: BTreeMap::new(),
            sent_txhash: None,
            used_addresses: Default::default(),
            pending_txs: BTreeMap::new(),
            gaid: None,
            amp_subaccount: None,
            reg_sync_complete: false,
            wallet_loaded_sent: false,
            active_extern_peg: None,
            peg_out_server_amounts: None,
            last_recv_address: None,
        });

        if self.skip_wallet_sync() {
            info!("skip wallet sync delay");
            self.send_wallet_loaded();
        }

        self.send_ws_connect();

        Ok(())
    }

    fn process_login_request(&mut self, req: proto::to::Login) {
        let res = self.try_process_login_request(req);
        let res = match res {
            Ok(()) => proto::from::login::Result::Success(proto::Empty {}),
            Err(err) => proto::from::login::Result::ErrorMsg(err.to_string()),
        };
        self.ui.send(proto::from::Msg::Login(proto::from::Login {
            result: Some(res),
        }));
    }

    fn restart_websocket(&mut self) {
        self.ws_connected = false;
        debug!("restart WS connection");
        self.ws_sender.send(ws::WrappedRequest::Disconnect).unwrap();
    }

    fn process_logout_request(&mut self) {
        debug!("process logout request...");

        self.wallet_data = None;
        self.market = market_worker::new();

        self.settings = settings::Settings::default();
        self.save_settings();

        self.ui.send(proto::from::Msg::Logout(proto::Empty {}));

        // Required because new device_key is needed
        // TODO: Do something better when multi-wallets are added
        self.restart_websocket();
    }

    fn recreate_wallets(&mut self) {
        let wallet_data = match self.wallet_data.take() {
            Some(wallet_data) => wallet_data,
            None => return,
        };

        let WalletData {
            xpubs,
            wallet_reg,
            wallet_amp,
            address_registration_active,
            wallet_utxos,
            created_txs,
            sent_txhash,
            used_addresses,
            pending_txs,
            gaid,
            amp_subaccount,
            reg_sync_complete,
            wallet_loaded_sent,
            active_extern_peg,
            peg_out_server_amounts,
            last_recv_address,
        } = wallet_data;

        let mut login_info_reg = wallet_reg.login_info().clone();
        let mut login_info_amp = wallet_amp.login_info().clone();

        login_info_reg.electrum_server = self.electrum_server();
        login_info_reg.proxy = self.proxy().clone();

        login_info_amp.electrum_server = self.electrum_server();
        login_info_amp.proxy = self.proxy().clone();

        drop(wallet_reg);
        drop(wallet_amp);

        let wallet_reg = gdk_ses_rust::start_processing(login_info_reg, self.get_notif_callback());
        let wallet_amp = gdk_ses_amp::start_processing(login_info_amp, self.get_notif_callback());

        self.wallet_data = Some(WalletData {
            xpubs,
            wallet_reg,
            wallet_amp,
            address_registration_active,
            wallet_utxos,
            created_txs,
            sent_txhash,
            used_addresses,
            pending_txs,
            gaid,
            amp_subaccount,
            reg_sync_complete,
            wallet_loaded_sent,
            active_extern_peg,
            peg_out_server_amounts,
            last_recv_address,
        });
    }

    fn process_network_settings(&mut self, req: proto::to::NetworkSettings) {
        let electrum_server_old = self.electrum_server();
        self.network_settings = req;
        let electrum_server_new = self.electrum_server();
        if electrum_server_new != electrum_server_old {
            debug!("new electrum server: {electrum_server_new:?}");
            self.recreate_wallets();
        }

        let master_xpub = self.master_xpub();
        assets_registry::refresh(self.env, master_xpub, self.proxy().clone());
    }

    fn process_proxy_settings(&mut self, req: proto::to::ProxySettings) {
        let res = match req.proxy {
            Some(proxy_user) => {
                ProxyAddress::from_str(&format!("{}:{}", proxy_user.host, proxy_user.port))
                    .or_else(|err| {
                        // Try IPv6 as a fallback
                        ProxyAddress::from_str(&format!(
                            "[{}]:{}",
                            proxy_user.host, proxy_user.port
                        ))
                        .map_err(|_err| {
                            format!(
                                "invalid proxy address: {}:{}: {}",
                                proxy_user.host, proxy_user.port, err
                            )
                        })
                    })
                    .map(Some)
            }

            None => match std::env::var("SOCKS_SERVER").ok() {
                Some(proxy_env) => match ProxyAddress::from_str(&proxy_env) {
                    Ok(proxy_env) => Ok(Some(proxy_env)),
                    Err(err) => Err(format!(
                        "invalid SOCKS_SERVER env value: {}: {}",
                        proxy_env, err
                    )),
                },
                None => Ok(None),
            },
        };

        match res {
            Ok(Some(ProxyAddress::Socks5 {
                address: SocketAddr::V6(socket),
            })) => {
                // ureq 2.x can't handle IPv6 proxy addresses
                // TODO: Check that this works correctly in ureq 3: ureq::Proxy::new(&proxy.to_string())
                self.show_message(&format!(
                    "invalid proxy address: {socket}: IPv6 proxy addresses are not supported"
                ));
            }

            Ok(proxy_new) => {
                if proxy_new != *self.proxy() {
                    debug!("new proxy: {proxy_new:?}");
                    self.proxy_address = proxy_new.clone();
                    self.recreate_wallets();
                    self.restart_websocket();
                    assets_registry::refresh(self.env, self.master_xpub(), proxy_new);
                }
            }
            Err(err) => {
                self.show_message(&err);
            }
        }
    }

    fn process_encrypt_pin(&self, req: proto::to::EncryptPin) {
        let result = match pin::encrypt_pin(&req.mnemonic, &req.pin, self.proxy()) {
            Ok(v) => {
                let data = serde_json::from_str::<pin::PinData>(&v).expect("must not fail");
                proto::from::encrypt_pin::Result::Data(proto::from::encrypt_pin::Data {
                    salt: data.salt,
                    encrypted_data: data.encrypted_data,
                    pin_identifier: data.pin_identifier,
                    hmac: data.hmac,
                })
            }
            Err(e) => proto::from::encrypt_pin::Result::Error(e.to_string()),
        };
        self.ui
            .send(proto::from::Msg::EncryptPin(proto::from::EncryptPin {
                result: Some(result),
            }));
    }

    fn process_decrypt_pin(&self, req: proto::to::DecryptPin) {
        // Workaround when UI sends an empty string
        let hmac = req.hmac.unwrap_or_default();
        let hmac = (!hmac.is_empty()).then_some(hmac);

        let details = pin::PinData {
            salt: req.salt,
            encrypted_data: req.encrypted_data,
            pin_identifier: req.pin_identifier,
            hmac,
        };
        let data = serde_json::to_string(&details).expect("must not fail");
        let result = match pin::decrypt_pin(&data, &req.pin, self.proxy()) {
            Ok(v) => proto::from::decrypt_pin::Result::Mnemonic(v),
            Err(e) => {
                let error_code = match &e {
                    pin::Error::WrongPin => proto::from::decrypt_pin::ErrorCode::WrongPin,
                    pin::Error::NetworkError(_) => {
                        proto::from::decrypt_pin::ErrorCode::NetworkError
                    }
                    pin::Error::InvalidData(_) => proto::from::decrypt_pin::ErrorCode::InvalidData,
                };
                proto::from::decrypt_pin::Result::Error(proto::from::decrypt_pin::Error {
                    error_msg: e.to_string(),
                    error_code: error_code.into(),
                })
            }
        };
        self.ui
            .send(proto::from::Msg::DecryptPin(proto::from::DecryptPin {
                result: Some(result),
            }));
    }

    fn process_app_state(&mut self, req: proto::to::AppState) {
        self.app_active = req.active;
        if req.active {
            self.check_ws_connection();
            self.check_amp_connection();
        }
    }

    fn subscribe_active_page(&mut self, subscribe: bool) {
        if !self.ws_connected {
            return;
        }

        let values = match self.active_page {
            proto::ActivePage::Other => [].as_slice(),
            proto::ActivePage::PegIn => [
                api::SubscribedValueType::PegInMinAmount,
                api::SubscribedValueType::PegInWalletBalance,
            ]
            .as_slice(),
            proto::ActivePage::PegOut => [
                api::SubscribedValueType::PegOutMinAmount,
                api::SubscribedValueType::PegOutWalletBalance,
            ]
            .as_slice(),
        };

        if subscribe {
            for &value in values {
                self.send_request_msg(api::Request::SubscribeValue(api::SubscribeValueRequest {
                    value,
                }));
            }
        } else {
            for &value in values {
                self.send_request_msg(api::Request::UnsubscribeValue(
                    api::UnsubscribeValueRequest { value },
                ));
            }
        }
    }

    fn process_subscribed_value(&mut self, notif: api::SubscribedValueNotification) {
        let msg = match notif.value {
            api::SubscribedValue::PegInMinAmount { min_amount } => {
                proto::from::subscribed_value::Result::PegInMinAmount(min_amount)
            }
            api::SubscribedValue::PegInWalletBalance { available } => {
                proto::from::subscribed_value::Result::PegInWalletBalance(available)
            }
            api::SubscribedValue::PegOutMinAmount { min_amount } => {
                proto::from::subscribed_value::Result::PegOutMinAmount(min_amount)
            }
            api::SubscribedValue::PegOutWalletBalance { available } => {
                proto::from::subscribed_value::Result::PegOutWalletBalance(available)
            }
        };

        self.ui.send(proto::from::Msg::SubscribedValue(
            proto::from::SubscribedValue { result: Some(msg) },
        ));
    }

    fn process_active_page(&mut self, active_page: i32) {
        let active_page = proto::ActivePage::try_from(active_page).expect("must be valid");
        if active_page != self.active_page {
            self.subscribe_active_page(false);
            self.active_page = active_page;
            self.subscribe_active_page(true);
        }
    }

    fn process_peg_status(&mut self, status: api::PegStatus) {
        let pegs = status
            .list
            .iter()
            .map(|tx| get_peg_item(&status, tx))
            .collect::<Vec<_>>();

        let mut queue_msgs = Vec::new();

        let wallet_data = match self.wallet_data.as_mut() {
            Some(wallet_data) => wallet_data,
            None => return,
        };

        if let Some(peg) = wallet_data.active_extern_peg.as_ref() {
            if peg.order_id == status.order_id {
                if let Some(first_peg) = status.list.first() {
                    let peg_item = get_peg_item(&status, first_peg);
                    queue_msgs.push(proto::from::Msg::SwapSucceed(peg_item));
                    wallet_data.active_extern_peg = None;
                }
            }
        }

        self.ui
            .send(proto::from::Msg::UpdatedPegs(proto::from::UpdatedPegs {
                order_id: status.order_id.to_string(),
                items: pegs,
            }));

        for msg in queue_msgs.into_iter() {
            self.ui.send(msg);
        }
    }

    fn process_asset_details_response(&mut self, msg: api::AssetDetailsResponse) {
        let stats = msg.chain_stats.map(|v| proto::from::asset_details::Stats {
            burned_amount: v.burned_amount,
            issued_amount: v.issued_amount,
            offline_amount: v.offline_amount.unwrap_or_default(),
            has_blinded_issuances: v.has_blinded_issuances,
        });
        let from = proto::from::AssetDetails {
            asset_id: msg.asset_id.to_string(),
            stats,
            chart_url: msg.chart_url,
        };
        self.ui.send(proto::from::Msg::AssetDetails(from));
    }

    fn process_set_memo(&mut self, req: proto::to::SetMemo) {
        let txid = elements::Txid::from_str(&req.txid).expect("must be valid txid");
        self.settings.tx_memos.insert(txid, req.memo);
        self.save_settings();
    }

    fn try_load_all_addresses(
        &mut self,
        account: proto::Account,
    ) -> Result<Vec<WalletAddress>, anyhow::Error> {
        let wallet = self.get_wallet(account)?;
        let resp = wallet::call_wallet(&wallet, move |ses| ses.get_previous_addresses())?;

        let list = resp
            .list
            .into_iter()
            .map(|addr| WalletAddress {
                address_type: addr.address_type,
                address: addr.address,
                pointer: addr.pointer,
                is_internal: addr.is_internal.unwrap_or(false),
            })
            .collect();

        Ok(list)
    }

    fn try_process_load_utxos(
        &mut self,
        account: proto::Account,
    ) -> Result<Vec<proto::from::load_utxos::Utxo>, anyhow::Error> {
        // Load utxos before loading address (to prevent a race)
        let inputs = wallet::call(account, self, |ses| ses.get_utxos())?
            .into_values()
            .flat_map(|utxos| utxos.into_iter())
            .collect::<Vec<_>>();

        let addresses = self.try_load_all_addresses(account)?;

        let addresses = addresses
            .into_iter()
            .map(|address| (AddressPointer::from(&address), address))
            .collect::<BTreeMap<_, _>>();

        let mut utxos = Vec::new();
        for input in inputs {
            let address = addresses
                .get(&AddressPointer {
                    address_type: input.wallet_type.into(),
                    is_internal: input.is_internal,
                    pointer: input.pointer,
                })
                .ok_or_else(|| {
                    anyhow!("address {}/{} not found", input.pointer, input.is_internal)
                })?;

            utxos.push(proto::from::load_utxos::Utxo {
                txid: input.txhash.to_string(),
                vout: input.vout,
                asset_id: input.asset_id.to_string(),
                amount: input.satoshi,
                address: address.address.to_string(),
                is_internal: input.is_internal,
                is_confidential: input.is_blinded,
            });
        }

        Ok(utxos)
    }

    fn process_load_utxos(&mut self, account: proto::Account) {
        let result = self.try_process_load_utxos(account);
        let (utxos, error_msg) = match result {
            Ok(utxos) => (utxos, None),
            Err(e) => {
                error!("loading utxos failed: {}", e);
                (Vec::new(), Some(e.to_string()))
            }
        };
        self.ui
            .send(proto::from::Msg::LoadUtxos(proto::from::LoadUtxos {
                account: account.into(),
                utxos,
                error_msg,
            }));
    }

    fn try_process_load_addresses(
        &mut self,
        account: proto::Account,
    ) -> Result<Vec<proto::from::load_addresses::Address>, anyhow::Error> {
        let addresses = self.try_load_all_addresses(account)?;

        let addresses = addresses
            .into_iter()
            .map(|addr| {
                let script_type = match addr.address_type {
                    AddressType::P2wpkh => proto::ScriptType::P2wpkh,
                    AddressType::P2shP2wpkh | AddressType::P2wsh => proto::ScriptType::P2sh,
                };
                proto::from::load_addresses::Address {
                    address: addr.address.to_string(),
                    unconfidential_address: addr.address.to_unconfidential().to_string(),
                    index: addr.pointer,
                    is_internal: addr.is_internal,
                    script_type: script_type.into(),
                }
            })
            .collect();

        Ok(addresses)
    }

    fn process_load_addresses(&mut self, account: proto::Account) {
        let result = self.try_process_load_addresses(account);
        let (addresses, error_msg) = match result {
            Ok(utxos) => (utxos, None),
            Err(e) => {
                error!("loading addresses failed: {}", e);
                (Vec::new(), Some(e.to_string()))
            }
        };
        self.ui.send(proto::from::Msg::LoadAddresses(
            proto::from::LoadAddresses {
                account: account.into(),
                addresses,
                error_msg,
            },
        ));
    }

    fn try_process_load_transactions(&mut self) -> Result<Vec<proto::TransItem>, anyhow::Error> {
        let mut res_receivers = Vec::new();
        if let Some(wallet_data) = self.wallet_data.as_mut() {
            let wallets: [Arc<dyn GdkSes>; 2] = [
                wallet_data.wallet_reg.clone(),
                wallet_data.wallet_amp.clone(),
            ];
            for wallet in wallets {
                let res_receiver = wallet::send_wallet(&wallet, move |ses| {
                    ses.get_transactions(gdk_ses::GetTransactionsOpt::All)
                });
                res_receivers.push((wallet.login_info().account, res_receiver));
            }
        }

        let mut txs = BTreeMap::new();
        for (account, res_receiver) in res_receivers {
            let list = res_receiver.recv()??;
            txs.insert(account, list);
        }

        let merged_txs = Self::merge_txs(txs);

        let merged_list = merged_txs
            .list
            .into_iter()
            .map(|tx| convert_tx(&self.settings.tx_memos, merged_txs.tip_height, &tx))
            .collect::<Vec<_>>();

        Ok(merged_list)
    }

    fn process_load_transactions(&mut self) {
        let result = self.try_process_load_transactions();
        let (txs, error_msg) = match result {
            Ok(txs) => (txs, None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };
        self.ui.send(proto::from::Msg::LoadTransactions(
            proto::from::LoadTransactions { txs, error_msg },
        ));
    }

    fn process_update_push_token(&mut self, req: proto::to::UpdatePushToken) {
        self.push_token = Some(req.token);
        self.update_push_token();
    }

    fn find_own_amp_address_info(
        &mut self,
        addr: &elements::Address,
    ) -> Result<models::AddressInfo, anyhow::Error> {
        let wallet_data = self
            .wallet_data
            .as_ref()
            .ok_or_else(|| anyhow!("no wallet_data"))?;

        let registered = u32::max(self.settings.amp_registered, wallet_data.used_addresses.amp);
        let max_pointer = registered + 10000; // Some big value just in case

        // The address is probably somewhere in the range [registered - 100, registered).
        // This will iterate all addresses in the range [0..max_pointer), but starting at the most likely position.
        let amp_address = (0..registered)
            .rev()
            .chain(registered..max_pointer)
            .find_map(|pointer| {
                let amp_address = derive_amp_address(
                    &wallet_data.xpubs.amp_service_xpub,
                    &wallet_data.xpubs.amp_user_xpub,
                    self.env.d().network,
                    pointer,
                    Some(&wallet_data.xpubs.master_blinding_key),
                );
                (amp_address.address == *addr).then_some(amp_address)
            })
            .ok_or_else(|| {
                anyhow!("can't find own AMP address {addr}, max_pointer: {max_pointer}")
            })?;

        let subaccount = wallet_data
            .amp_subaccount
            .ok_or_else(|| anyhow!("no amp_subaccount"))?;

        let user_path = sideswap_amp::address_user_path(subaccount, amp_address.pointer)
            .into_iter()
            .map(u32::from)
            .collect();

        Ok(models::AddressInfo {
            address: amp_address.address,
            address_type: AddressType::P2wsh,
            pointer: amp_address.pointer,
            user_path,
            is_internal: None,
            public_key: None,
            prevout_script: Some(amp_address.prevout_script),
            service_xpub: Some(wallet_data.xpubs.amp_service_xpub),
            branch: None,
        })
    }

    fn process_asset_details(&mut self, req: proto::AssetId) {
        self.send_request_msg(api::Request::AssetDetails(api::AssetDetailsRequest {
            asset_id: AssetId::from_str(&req.asset_id).unwrap(),
        }));
    }

    fn process_portfolio_prices(&mut self) {
        self.make_async_request(api::Request::PortfolioPrices(None), move |data, res| {
            if let Ok(api::Response::PortfolioPrices(resp)) = res {
                let prices_usd = resp
                    .prices_usd
                    .into_iter()
                    .map(|(asset_id, price)| (asset_id.to_string(), price))
                    .collect();
                data.ui.send(proto::from::Msg::PortfolioPrices(
                    proto::from::PortfolioPrices { prices_usd },
                ));
            }
        });
    }

    fn process_conversion_rates(&mut self) {
        self.make_async_request(api::Request::ConversionRates(None), move |data, res| {
            if let Ok(api::Response::ConversionRates(resp)) = res {
                let usd_conversion_rates = resp.usd_conversion_rates.into_iter().collect();
                data.ui.send(proto::from::Msg::ConversionRates(
                    proto::from::ConversionRates {
                        usd_conversion_rates,
                    },
                ));
            }
        });
    }

    fn process_local_message(&mut self, msg: api::LocalMessageNotification) {
        self.ui
            .send(proto::from::Msg::LocalMessage(proto::from::LocalMessage {
                title: msg.title,
                body: msg.body,
            }));
    }

    // message processing

    fn send_request_msg(&self, request: api::Request) -> api::RequestId {
        let request_id = next_request_id();
        self.ws_sender
            .send(ws::WrappedRequest::Request(api::RequestMessage::Request(
                request_id.clone(),
                request,
            )))
            .unwrap();
        request_id
    }

    fn send_request(
        &self,
        request: api::Request,
        timeout: Duration,
    ) -> Result<api::Response, CallError> {
        verify!(self.ws_connected, CallError::Disconnected);

        // Blocking requests use string ids
        let active_id = sideswap_common::ws::next_id().to_string();
        self.ws_sender
            .send(ws::WrappedRequest::Request(api::RequestMessage::Request(
                api::RequestId::String(active_id.clone()),
                request,
            )))
            .unwrap();

        let started = std::time::Instant::now();
        loop {
            let resp = self.resp_receiver.recv_timeout(SERVER_REQUEST_POLL_PERIOD);
            match resp {
                Ok(ServerResp(req_id, result)) => {
                    if req_id != active_id {
                        warn!("discard old response: {:?}", result);
                        continue;
                    }
                    return result.map_err(Into::into);
                }
                Err(_) => {
                    let spent_time = std::time::Instant::now().duration_since(started);
                    if spent_time > timeout {
                        error!("request timeout");
                        abort!(CallError::Timeout);
                    }
                }
            };
        }
    }

    fn make_async_request(
        &mut self,
        req: api::Request,
        resp: impl FnOnce(&mut Data, Result<api::Response, api::Error>) + 'static,
    ) {
        if !self.ws_connected {
            resp(
                self,
                Err(api::Error {
                    code: api::ErrorCode::ServerError,
                    message: "Not connected".to_owned(),
                }),
            );
            return;
        }
        let request_id = next_request_id();
        self.ws_sender
            .send(ws::WrappedRequest::Request(api::RequestMessage::Request(
                request_id.clone(),
                req,
            )))
            .unwrap();
        self.async_requests.insert(request_id, Box::new(resp));
    }

    fn show_message(&self, text: &str) {
        info!("show message: {}", text);
        let msg = proto::from::ShowMessage {
            text: text.to_owned(),
        };
        self.ui.send(proto::from::Msg::ShowMessage(msg));
    }

    fn check_ws_connection(&mut self) {
        debug!("check ws connection");
        if !self.ws_connected {
            debug!("ws is not connected, send reconnect hint");
            let _ = self.ws_hint.send(());
            return;
        }
        let ping_response = send_request!(self, Ping, None, SERVER_REQUEST_TIMEOUT_SHORT);
        if ping_response.is_err() {
            debug!("WS connection check failed, reconnecting...");
            self.restart_websocket();
        }
    }

    fn send_ws_connect(&self) {
        // TODO: Add a new env type
        let (host, port, use_tls) = if self.network_settings.selected.as_ref()
            == Some(&proto::to::network_settings::Selected::SideswapCn(
                proto::Empty {},
            )) {
            ("cn.sideswap.io".to_owned(), 443, true)
        } else {
            let env_data = self.env.d();
            (env_data.host.to_owned(), env_data.port, env_data.use_tls)
        };

        self.ws_sender
            .send(ws::WrappedRequest::Connect {
                host,
                port,
                use_tls,
                proxy: self.proxy().clone(),
            })
            .unwrap();
    }

    fn check_amp_connection(&mut self) {
        if let Some(wallet_data) = &self.wallet_data {
            let wallet = Arc::clone(&wallet_data.wallet_amp);

            std::thread::spawn(move || {
                let res = wallet.check_connection();
                match res {
                    Ok(()) => log::debug!("AMP connection check succeed"),
                    Err(err) => log::warn!("AMP connection check failed: {err}"),
                }
            });
        }
    }

    fn process_push_message(&mut self, req: String, _pending_sign: Option<mpsc::Sender<()>>) {
        let _msg = match serde_json::from_str::<fcm_models::FcmMessage>(&req) {
            Ok(v) => v,
            Err(e) => {
                error!("parsing FCM message failed: {}", e);
                return;
            }
        };
    }

    fn skip_wallet_sync(&self) -> bool {
        true
    }

    fn process_ui(&mut self, msg: ffi::ToMsg) {
        debug!(
            "from ui: {}",
            serde_json::to_string(&redact_to_msg(msg.clone())).unwrap()
        );
        match msg {
            proto::to::Msg::Login(req) => self.process_login_request(req),
            proto::to::Msg::Logout(_) => self.process_logout_request(),
            proto::to::Msg::NetworkSettings(req) => self.process_network_settings(req),
            proto::to::Msg::ProxySettings(req) => self.process_proxy_settings(req),
            proto::to::Msg::EncryptPin(req) => self.process_encrypt_pin(req),
            proto::to::Msg::DecryptPin(req) => self.process_decrypt_pin(req),
            proto::to::Msg::AppState(req) => self.process_app_state(req),
            proto::to::Msg::ActivePage(req) => self.process_active_page(req),
            proto::to::Msg::PushMessage(req) => self.process_push_message(req, None),
            proto::to::Msg::PegInRequest(_) => self.process_pegin_request(),
            proto::to::Msg::PegOutAmount(req) => self.process_pegout_amount(req),
            proto::to::Msg::PegOutRequest(req) => self.process_pegout_request(req),
            proto::to::Msg::GetRecvAddress(req) => {
                self.process_get_recv_address(Account::try_from(req).expect("must be valid"))
            }
            proto::to::Msg::CreateTx(req) => self.process_create_tx(req),
            proto::to::Msg::SendTx(req) => self.process_send_tx(req),
            proto::to::Msg::BlindedValues(req) => self.process_blinded_values(req),
            proto::to::Msg::SetMemo(req) => self.process_set_memo(req),
            proto::to::Msg::LoadUtxos(req) => {
                self.process_load_utxos(Account::try_from(req).expect("must be valid"))
            }
            proto::to::Msg::LoadAddresses(req) => {
                self.process_load_addresses(Account::try_from(req).expect("must be valid"))
            }
            proto::to::Msg::LoadTransactions(_req) => self.process_load_transactions(),
            proto::to::Msg::UpdatePushToken(req) => self.process_update_push_token(req),
            proto::to::Msg::AssetDetails(req) => self.process_asset_details(req),
            proto::to::Msg::PortfolioPrices(_) => self.process_portfolio_prices(),
            proto::to::Msg::ConversionRates(_) => self.process_conversion_rates(),
            proto::to::Msg::JadeRescan(_) => self.process_jade_rescan_request(),
            proto::to::Msg::JadeUnlock(_) => self.process_jade_unlock(),
            proto::to::Msg::JadeVerifyAddress(msg) => self.process_jade_verify_address(msg),
            proto::to::Msg::GaidStatus(msg) => self.process_gaid_status_req(msg),
            proto::to::Msg::MarketSubscribe(msg) => market_worker::market_subscribe(self, msg),
            proto::to::Msg::MarketUnsubscribe(msg) => market_worker::market_unsubscribe(self, msg),
            proto::to::Msg::OrderSubmit(msg) => market_worker::order_submit(self, msg),
            proto::to::Msg::OrderEdit(msg) => market_worker::order_edit(self, msg),
            proto::to::Msg::OrderCancel(msg) => market_worker::order_cancel(self, msg),
            proto::to::Msg::StartQuotes(msg) => market_worker::start_quotes(self, msg, None, None),
            proto::to::Msg::StartOrder(msg) => market_worker::start_order(self, msg),
            proto::to::Msg::StopQuotes(msg) => market_worker::stop_quotes(self, msg),
            proto::to::Msg::AcceptQuote(msg) => market_worker::accept_quote(self, msg),
            proto::to::Msg::ChartsSubscribe(msg) => market_worker::charts_subscribe(self, msg),
            proto::to::Msg::ChartsUnsubscribe(msg) => market_worker::charts_unsubscribe(self, msg),
            proto::to::Msg::LoadHistory(msg) => market_worker::load_history(self, msg),
        }
    }

    fn process_ws_resp(&mut self, resp: api::Response) {
        match resp {
            api::Response::Ping(_) => {}
            api::Response::ServerStatus(_) => {}
            api::Response::Assets(_) => {}
            api::Response::AmpAssets(_) => {}
            api::Response::PegFee(_) => {}
            api::Response::Peg(_) => {}
            api::Response::PegStatus(msg) => self.process_peg_status(msg),
            api::Response::PegReturnAddress(_) => {}
            api::Response::PriceUpdateBroadcast(_) => {}
            api::Response::PriceUpdateSubscribe(_) => {}
            api::Response::LoginClient(_) => {}
            api::Response::LoginDealer(_) => {}
            api::Response::VerifyDevice(_) => {}
            api::Response::RegisterDevice(_) => {}
            api::Response::RegisterAddresses(_) => {}
            api::Response::UpdatePushToken(_) => {}
            api::Response::LoadPrices(_) => {}
            api::Response::CancelPrices(_) => {}
            api::Response::PortfolioPrices(_) => {}
            api::Response::ConversionRates(_) => {}
            api::Response::Submit(_) => {}
            api::Response::Edit(_) => {}
            api::Response::Cancel(_) => {}
            api::Response::Login(_) => {}
            api::Response::Subscribe(_) => {}
            api::Response::Unsubscribe(_) => {}
            api::Response::Link(_) => {}
            api::Response::PsetMaker(_) => {}
            api::Response::PsetTaker(_) => {}
            api::Response::Sign(_) => {}
            api::Response::GetSign(_) => {}
            api::Response::ResolveGaid(_) => {}
            api::Response::GaidStatus(_) => {}
            api::Response::AssetDetails(msg) => self.process_asset_details_response(msg),
            api::Response::BroadcastPriceStream(_) => {}
            api::Response::SubscribePriceStream(_) => {}
            api::Response::UnsubscribePriceStream(_) => {}
            api::Response::StartSwapWeb(_) => {}
            api::Response::StartSwapClient(_) => {}
            api::Response::StartSwapDealer(_) => {}
            api::Response::SignedSwapClient(_) => {}
            api::Response::SignedSwapDealer(_) => {}
            api::Response::MarketDataSubscribe(_) => {}
            api::Response::MarketDataUnsubscribe(_) => {}
            api::Response::SwapPrices(_) => {}
            api::Response::Market(resp) => market_worker::process_resp(self, resp),
            api::Response::SubscribeValue(_) => {}
            api::Response::UnsubscribeValue(_) => {}
        }
    }

    fn process_ws_msg(&mut self, msg: api::ResponseMessage) {
        match msg {
            api::ResponseMessage::Response(Some(req_id), res) => {
                if let Some(callback) = self.async_requests.remove(&req_id) {
                    callback(self, res);
                } else {
                    match res {
                        Ok(resp) => {
                            self.process_ws_resp(resp);
                        }
                        Err(err) => {
                            log::error!("ws request failed: {err}, id: {req_id:?}");
                        }
                    }
                }
            }
            api::ResponseMessage::Response(None, res) => {
                log::error!("ws request id is not set: {res:?}");
            }
            api::ResponseMessage::Notification(msg) => self.process_ws_notification(msg),
        }
    }

    fn process_ws(&mut self, resp: ws::WrappedResponse) {
        match resp {
            ws::WrappedResponse::Connected => self.process_ws_connected(),
            ws::WrappedResponse::Disconnected => self.process_ws_disconnected(),
            ws::WrappedResponse::Response(msg) => self.process_ws_msg(msg),
        }
    }

    fn process_ws_notification(&mut self, notification: api::Notification) {
        match notification {
            api::Notification::Market(notif) => market_worker::process_notif(self, notif),
            api::Notification::PegStatus(status) => self.process_peg_status(status),
            api::Notification::ServerStatus(resp) => self.process_server_status(resp),
            api::Notification::PriceUpdate(msg) => self.process_price_update(msg),
            api::Notification::Sign(_) => {}
            api::Notification::Complete(_) => {}
            api::Notification::OrderCreated(_) => {}
            api::Notification::OrderRemoved(_) => {}
            api::Notification::UpdatePrices(_) => {}
            api::Notification::UpdatePriceStream(_) => {}
            api::Notification::BlindedSwapClient(_) => {}
            api::Notification::SwapDone(_) => {}
            api::Notification::LocalMessage(msg) => self.process_local_message(msg),
            api::Notification::NewAsset(_) => {}
            api::Notification::MarketDataUpdate(_) => {}
            api::Notification::StartSwapDealer(_) => {}
            api::Notification::BlindedSwapDealer(_) => {}
            api::Notification::NewSwapPrice(_) => {}
            api::Notification::SubscribedValue(notif) => self.process_subscribed_value(notif),
        }
    }

    fn add_missing_gdk_assets<'a>(&mut self, asset_ids: impl Iterator<Item = &'a AssetId>) {
        // Do not replace existing asset information (like market_type)
        let new_asset_ids = asset_ids
            .filter(|asset_id| !self.assets.contains_key(asset_id))
            .collect::<BTreeSet<_>>();
        if !new_asset_ids.is_empty() {
            let new_assets = self
                .load_gdk_assets(new_asset_ids.into_iter())
                .ok()
                .unwrap_or_default();
            for asset in new_assets {
                self.register_asset(asset);
            }
        }
    }

    fn add_gdk_assets_for_asset_pair<'a>(
        &mut self,
        asset_pairs: impl Iterator<Item = &'a AssetPair>,
    ) {
        let assets = asset_pairs
            .into_iter()
            .flat_map(|asset_pair| [&asset_pair.base, &asset_pair.quote]);
        self.add_missing_gdk_assets(assets);
    }

    pub fn register_asset(&mut self, asset: api::Asset) {
        let asset_id = asset.asset_id;
        let unregistered = asset.asset_id != self.policy_asset && asset.domain.is_none();
        let amp_asset_restrictions =
            asset
                .amp_asset_restrictions
                .clone()
                .map(|info| proto::AmpAssetRestrictions {
                    allowed_countries: info.allowed_countries.unwrap_or_default(),
                });
        let asset_copy = proto::Asset {
            asset_id: asset.asset_id.to_string(),
            name: asset.name.clone(),
            ticker: asset.ticker.0.clone(),
            icon: asset
                .icon
                .clone()
                .unwrap_or_else(|| b64::encode(DEFAULT_ICON)),
            precision: u32::from(asset.precision.value()),
            swap_market: asset.market_type == Some(MarketType::Stablecoin),
            amp_market: asset.market_type == Some(MarketType::Amp),
            domain: asset.domain.clone(),
            domain_agent: asset.domain_agent.clone(),
            domain_agent_link: asset.domain_agent_link.clone(),
            unregistered,
            instant_swaps: asset.instant_swaps.unwrap_or(false),
            always_show: asset.always_show,
            amp_asset_restrictions,
            payjoin: asset.payjoin,
        };

        self.assets.insert(asset_id, asset);

        self.ui.send(proto::from::Msg::NewAsset(asset_copy));
    }

    pub fn register_assets_with_gdk_icons(&mut self, mut assets: api::Assets) {
        let asset_ids = assets.iter().map(|asset| &asset.asset_id);
        let gdk_assets = self.load_gdk_assets(asset_ids).ok().unwrap_or_default();
        let gdk_icons = gdk_assets
            .into_iter()
            .map(|asset| (asset.asset_id, asset.icon))
            .collect::<BTreeMap<_, _>>();

        for asset in assets.iter_mut() {
            asset.icon = gdk_icons.get(&asset.asset_id).cloned().flatten();
        }

        for asset in assets {
            self.register_asset(asset);
        }
    }

    pub fn save_assets_cache(&self, assets: &[api::Asset]) -> Result<(), anyhow::Error> {
        // Save asset cache so that deleting default assets work without releasing new app version
        let cache = AssetsCache {
            git_commit_hash: GIT_COMMIT_HASH.to_owned(),
            assets: assets
                .iter()
                .filter(|asset| asset.always_show.unwrap_or_default())
                .cloned()
                .collect(),
        };
        let data = serde_json::to_string(&cache).expect("must not fail");
        std::fs::write(self.assets_cache_path_tmp(), data)?;
        std::fs::rename(self.assets_cache_path_tmp(), self.assets_cache_path())?;
        log::debug!("saved {} to assets cache", cache.assets.len());
        Ok(())
    }

    pub fn load_assets_cache(&self) -> Result<Vec<api::Asset>, anyhow::Error> {
        let data = std::fs::read(self.assets_cache_path())?;
        let cache = serde_json::from_slice::<AssetsCache>(&data)?;
        // Ignore asset cache from older builds, it can contain outdated data
        ensure!(cache.git_commit_hash == GIT_COMMIT_HASH);
        log::debug!("loaded {} from assets cache", cache.assets.len());
        Ok(cache.assets)
    }

    pub fn load_default_assets(&mut self) {
        let assets = self.load_assets_cache().unwrap_or_else(|err| {
            log::debug!("loading assets cache failed: {err}, use default cache instead");
            let data = match self.env.d().network {
                Network::Liquid => include_str!("../data/assets.json"),
                Network::LiquidTestnet => include_str!("../data/assets-testnet.json"),
                Network::Regtest => "[]",
            };
            serde_json::from_str::<api::Assets>(data).expect("must not fail")
        });
        self.register_assets_with_gdk_icons(assets);
    }

    // pegs monitoring

    fn start_peg_monitoring(&self, peg: &settings::Peg) {
        let request = match peg.dir {
            settings::PegDir::In => api::Request::PegStatus(api::PegStatusRequest {
                order_id: peg.order_id,
                peg_in: None,
            }),
            settings::PegDir::Out => api::Request::PegStatus(api::PegStatusRequest {
                order_id: peg.order_id,
                peg_in: None,
            }),
        };
        self.send_request_msg(request);
    }

    fn add_peg_monitoring(&mut self, order_id: OrderId, dir: settings::PegDir) {
        let peg = settings::Peg { order_id, dir };
        if self.ws_connected {
            self.start_peg_monitoring(&peg);
        }
        self.settings.pegs.get_or_insert_with(Vec::new).push(peg);
        self.save_settings();
    }

    fn update_push_token(&mut self) {
        if let (Some(push_token), true, Some(device_key)) = (
            &self.push_token,
            self.ws_connected,
            &self.settings.device_key,
        ) {
            self.make_async_request(
                api::Request::UpdatePushToken(api::UpdatePushTokenRequest {
                    device_key: device_key.clone(),
                    push_token: push_token.clone(),
                }),
                move |_data, res| {
                    if let Err(e) = res {
                        error!("updating push token failed: {}", e);
                    }
                },
            );
        };
    }

    fn update_address_registrations(&mut self) {
        let wallet_data = match self.wallet_data.as_mut() {
            Some(wallet_data) => wallet_data,
            None => return,
        };

        if wallet_data.address_registration_active || !self.ws_connected {
            return;
        }

        let device_key = match self.settings.device_key.as_ref() {
            Some(device_key) => device_key.clone(),
            None => return,
        };

        let count_in_advance = 100;
        let limit_one_request = 100;

        // Nested account
        for is_internal in [false, true] {
            let first = self.settings.nested_registered[usize::from(is_internal)];
            let last_max =
                wallet_data.used_addresses.nested[usize::from(is_internal)] + count_in_advance;
            let last = u32::min(first + limit_one_request, last_max);

            let addresses = (first..last)
                .map(|pointer| {
                    derive_nested_address(
                        &wallet_data.xpubs.nested_account,
                        self.env.d().network,
                        is_internal,
                        pointer,
                        None,
                    )
                    .to_string()
                })
                .collect::<Vec<_>>();

            if !addresses.is_empty() {
                log::debug!(
                    "register nested addresses, is_internal: {}, first: {}, last: {}, count: {}...",
                    is_internal,
                    first,
                    last,
                    addresses.len(),
                );

                wallet_data.address_registration_active = true;
                self.make_async_request(
                    api::Request::RegisterAddresses(api::RegisterAddressesRequest {
                        device_key,
                        addresses,
                    }),
                    move |data, res| {
                        if let Some(wallet_data) = data.wallet_data.as_mut() {
                            wallet_data.address_registration_active = false;
                            match res {
                                Ok(_) => {
                                    log::debug!("address registration succeed");
                                    data.settings.nested_registered.as_mut()
                                        [is_internal as usize] = last;
                                    data.save_settings();
                                    data.update_address_registrations();
                                }

                                Err(err) => {
                                    error!("addresses registration failed: {}", err.message);
                                }
                            }
                        }
                    },
                );
                return;
            }
        }

        // Native account
        for is_internal in [false, true] {
            let first = self.settings.native_registered[is_internal as usize];
            let last_max =
                wallet_data.used_addresses.native[usize::from(is_internal)] + count_in_advance;
            let last = u32::min(first + limit_one_request, last_max);

            let addresses = (first..last)
                .map(|pointer| {
                    derive_native_address(
                        &wallet_data.xpubs.native_account,
                        self.env.d().network,
                        is_internal,
                        pointer,
                        None,
                    )
                    .to_string()
                })
                .collect::<Vec<_>>();

            if !addresses.is_empty() {
                log::debug!(
                    "register native addresses, is_internal: {}, first: {}, last: {}, count: {}...",
                    is_internal,
                    first,
                    last,
                    addresses.len(),
                );

                wallet_data.address_registration_active = true;
                self.make_async_request(
                    api::Request::RegisterAddresses(api::RegisterAddressesRequest {
                        device_key,
                        addresses,
                    }),
                    move |data, res| {
                        if let Some(wallet_data) = data.wallet_data.as_mut() {
                            wallet_data.address_registration_active = false;
                            match res {
                                Ok(_) => {
                                    log::debug!("address registration succeed");
                                    data.settings.native_registered.as_mut()
                                        [is_internal as usize] = last;
                                    data.save_settings();
                                    data.update_address_registrations();
                                }

                                Err(err) => {
                                    error!("addresses registration failed: {}", err.message);
                                }
                            }
                        }
                    },
                );
                return;
            }
        }

        // AMP account
        if self.amp_connected {
            let first = self.settings.amp_registered;
            let last_max = wallet_data.used_addresses.amp + count_in_advance;
            let last = u32::min(first + limit_one_request, last_max);

            let addresses = (first..last)
                .map(|pointer| {
                    derive_amp_address(
                        &wallet_data.xpubs.amp_service_xpub,
                        &wallet_data.xpubs.amp_user_xpub,
                        self.env.d().network,
                        pointer,
                        None,
                    )
                    .address
                    .to_string()
                })
                .collect::<Vec<_>>();

            if !addresses.is_empty() {
                log::debug!(
                    "register multi-sig addresses, first: {}, last: {}, count: {}...",
                    first,
                    last,
                    addresses.len(),
                );

                wallet_data.address_registration_active = true;
                self.make_async_request(
                    api::Request::RegisterAddresses(api::RegisterAddressesRequest {
                        device_key,
                        addresses,
                    }),
                    move |data, res| {
                        if let Some(wallet_data) = data.wallet_data.as_mut() {
                            wallet_data.address_registration_active = false;
                            match res {
                                Ok(_) => {
                                    log::debug!("address registration succeed");
                                    data.settings.amp_registered = last;
                                    data.save_settings();
                                    data.update_address_registrations();
                                }

                                Err(err) => {
                                    error!("addresses registration failed: {}", err.message);
                                }
                            }
                        }
                    },
                );
                return;
            }
        }

        log::debug!("no need to register new addresses");
    }

    fn save_settings(&self) {
        let result = settings::save_settings(&self.settings, &self.get_data_path());
        if let Err(e) = result {
            error!("saving settings failed: {}", e);
        }
    }

    fn process_background_message(&mut self, data: String, pending_sign: mpsc::Sender<()>) {
        self.process_push_message(data, Some(pending_sign));
    }

    fn get_wallet(&self, account: Account) -> Result<Arc<dyn GdkSes>, anyhow::Error> {
        let wallet_data = self
            .wallet_data
            .as_ref()
            .ok_or_else(|| anyhow!("wallet not found"))?;
        let wallet: Arc<dyn GdkSes> = match account {
            Account::Reg => wallet_data.wallet_reg.clone(),
            Account::Amp => wallet_data.wallet_amp.clone(),
        };
        Ok(wallet)
    }

    fn process_jade_rescan_request(&mut self) {
        let ports_result = self.jade_mng.ports();
        match ports_result {
            Ok(ports) => {
                let ports = ports
                    .iter()
                    .map(|data| proto::from::jade_ports::Port {
                        jade_id: data.jade_id.clone(),
                        port: data.port_name.clone(),
                    })
                    .collect();
                self.ui
                    .send(proto::from::Msg::JadePorts(proto::from::JadePorts {
                        ports,
                    }))
            }
            Err(e) => error!("jade port scan failed: {e}"),
        }
    }

    fn try_jade_unlock(&mut self) -> Result<(), anyhow::Error> {
        let wallet_data = self
            .wallet_data
            .as_mut()
            .ok_or_else(|| anyhow!("no wallet_data"))?;

        match &wallet_data.wallet_reg.login_info().wallet_info {
            WalletInfo::Mnemonic(_mnemonic) => Ok(()),
            WalletInfo::Jade(jade_data, _watch_only) => utils::unlock_hw(self.env, &jade_data.jade),
        }
    }

    fn process_jade_unlock(&mut self) {
        let res = self.try_jade_unlock();
        let result = proto::GenericResponse {
            success: res.is_ok(),
            error_msg: res.err().map(|err| err.to_string()),
        };
        self.ui.send(proto::from::Msg::JadeUnlock(result));
    }

    fn try_jade_verify_address(&mut self, msg: proto::Address) -> Result<(), anyhow::Error> {
        let wallet_data = self
            .wallet_data
            .as_ref()
            .ok_or_else(|| anyhow!("no wallet_data"))?;

        let latest_address = wallet_data
            .last_recv_address
            .as_ref()
            .ok_or_else(|| anyhow!("no last_recv_address"))?;

        ensure!(latest_address.address.to_string() == msg.addr);

        match &wallet_data.wallet_reg.login_info().wallet_info {
            WalletInfo::Mnemonic(_mnemonic) => bail!("jade only request"),
            WalletInfo::Jade(jade_data, _watch_only) => {
                utils::unlock_hw(self.env, &jade_data.jade)?;

                // TODO: Verify jade wallet fingerprint

                let network = get_jade_network(self.env);

                let req = match latest_address.address_type {
                    models::AddressType::P2wpkh | models::AddressType::P2shP2wpkh => {
                        let variant = match latest_address.address_type {
                            AddressType::P2wpkh => sideswap_jade::models::OutputVariant::P2wpkh,
                            AddressType::P2shP2wpkh => {
                                sideswap_jade::models::OutputVariant::P2wpkhP2sh
                            }
                            AddressType::P2wsh => unreachable!(),
                        };

                        sideswap_jade::models::GetReceiveAddressReq {
                            network,
                            variant: Some(variant),
                            path: Some(latest_address.user_path.clone()),
                            subaccount: None,
                            pointer: None,
                            branch: None,
                        }
                    }

                    models::AddressType::P2wsh => {
                        let subaccount = wallet_data
                            .amp_subaccount
                            .ok_or_else(|| anyhow!("amp_subaccount is None"))?;
                        let branch = latest_address
                            .branch
                            .ok_or_else(|| anyhow!("branch is None"))?;
                        sideswap_jade::models::GetReceiveAddressReq {
                            network,
                            variant: None,
                            path: None,
                            subaccount: Some(subaccount),
                            pointer: Some(latest_address.pointer),
                            branch: Some(branch),
                        }
                    }
                };

                let resp = jade_data.jade.get_receive_address(req)?;
                ensure!(msg.addr == resp, "unexpected jade address");

                Ok(())
            }
        }
    }

    fn process_jade_verify_address(&mut self, msg: proto::Address) {
        let res = self.try_jade_verify_address(msg);
        let result = proto::GenericResponse {
            success: res.is_ok(),
            error_msg: res.err().map(|err| err.to_string()),
        };
        self.ui.send(proto::from::Msg::JadeVerifyAddress(result));
    }

    fn process_gaid_status_req(&mut self, msg: proto::to::GaidStatus) {
        self.make_async_request(
            api::Request::GaidStatus(api::GaidStatusRequest {
                gaid: msg.gaid.clone(),
                asset_id: AssetId::from_str(&msg.asset_id).unwrap(),
            }),
            move |data, res| {
                let error_opt = match res {
                    Ok(api::Response::GaidStatus(resp)) => resp.error,
                    Ok(_) => Some("Unexpected response".to_string()),
                    Err(err) => Some(err.to_string()),
                };
                data.ui
                    .send(proto::from::Msg::GaidStatus(proto::from::GaidStatus {
                        gaid: msg.gaid,
                        asset_id: msg.asset_id,
                        error: error_opt,
                    }));
            },
        );
    }
}

fn process_timer_event(data: &mut Data, event: TimerEvent) {
    log::debug!("process timer event: {event:?}");
    match event {
        TimerEvent::SyncUtxos => {
            market_worker::sync_utxos(data);
        }

        TimerEvent::SendAck => {
            market_worker::send_ack(data);
        }

        TimerEvent::CleanQuotes => {
            market_worker::clean_quotes(data);
        }
    }
}

fn remove_timers(data: &mut Data, removed: TimerEvent) {
    data.timers.retain(|_timer, event| *event != removed);
}

fn add_timer(data: &mut Data, timeout: Duration, event: TimerEvent) {
    data.timers.insert(Instant::now() + timeout, event);
}

fn replace_timers(data: &mut Data, timeout: Duration, event: TimerEvent) {
    remove_timers(data, event);
    add_timer(data, timeout, event);
}

fn recv_message(data: &mut Data, msg_receiver: &mpsc::Receiver<Message>) -> Option<Message> {
    loop {
        if let Some(timer) = data.timers.keys().next() {
            let now = Instant::now();
            let duration = timer.duration_since(now);
            match msg_receiver.recv_timeout(duration) {
                Ok(msg) => break Some(msg),
                Err(err) => match err {
                    mpsc::RecvTimeoutError::Timeout => {
                        let (_timer, event) = data.timers.pop_first().expect("must exist");
                        process_timer_event(data, event);
                        continue;
                    }
                    mpsc::RecvTimeoutError::Disconnected => break None,
                },
            }
        } else {
            break msg_receiver.recv().ok();
        }
    }
}

pub fn start_processing(
    env: Env,
    msg_sender: mpsc::Sender<Message>,
    msg_receiver: mpsc::Receiver<Message>,
    from_callback: FromCallback,
    params: StartParams,
) {
    let ui = UiData {
        from_callback,
        ui_stopped: Default::default(),
    };
    let env_settings = proto::from::EnvSettings {
        policy_asset_id: env.nd().policy_asset.to_string(),
        usdt_asset_id: env.nd().known_assets.USDt.to_string(),
        eurx_asset_id: env.nd().known_assets.EURx.to_string(),
    };
    ui.send(proto::from::Msg::EnvSettings(env_settings));

    let (resp_sender, resp_receiver) = mpsc::channel::<ServerResp>();
    let msg_sender_copy = msg_sender.clone();
    let ws_resp_callback = Box::new(move |resp| {
        // Filter requests with string ids (they only used with blocking requests)
        if let ws::WrappedResponse::Response(api::ResponseMessage::Response(
            Some(api::RequestId::String(id)),
            res,
        )) = resp
        {
            let res = resp_sender.send(ServerResp(id, res));
            if let Err(err) = res {
                log::error!("sending resp message failed: {err}");
            }
        } else {
            let res = msg_sender_copy.send(Message::Ws(resp));
            if let Err(err) = res {
                log::error!("sending ws message failed: {err}");
            }
        }
    });
    let (ws_sender, ws_hint) = ws::start(ws_resp_callback);

    let ui_copy = ui.clone();
    let jade_status_callback: JadeStatusCallback =
        std::sync::Arc::new(Box::new(move |status: Option<JadeStatus>| {
            let status: i32 = match status {
                None => proto::from::jade_status::Status::Idle,
                Some(status) => match status {
                    JadeStatus::Connecting => proto::from::jade_status::Status::Connecting,
                    JadeStatus::ReadStatus => proto::from::jade_status::Status::ReadStatus,
                    JadeStatus::AuthUser => proto::from::jade_status::Status::AuthUser,
                    JadeStatus::MasterBlindingKey => {
                        proto::from::jade_status::Status::MasterBlindingKey
                    }
                    JadeStatus::SignMessage => proto::from::jade_status::Status::SignMessage,
                    JadeStatus::SignTx(tx_type) => match tx_type {
                        jade_mng::TxType::Normal => proto::from::jade_status::Status::SignTx,
                        jade_mng::TxType::Swap => proto::from::jade_status::Status::SignSwap,
                        jade_mng::TxType::MakerUtxo => {
                            proto::from::jade_status::Status::SignSwapOutput
                        }
                        jade_mng::TxType::OfflineSwap => {
                            proto::from::jade_status::Status::SignOfflineSwap
                        }
                    },
                },
            }
            .into();
            ui_copy.send(proto::from::Msg::JadeStatus(proto::from::JadeStatus {
                status,
            }));
        }));

    let settings_path = Data::data_path(env, &params.work_dir);
    let mut settings = settings::load_settings(&settings_path).unwrap_or_default();
    settings::prune(&mut settings);

    let policy_asset = env.nd().policy_asset;

    let msg_sender_copy = msg_sender.clone();
    let wallet_event_callback = Arc::new(move |account_id, event| {
        let res = msg_sender_copy.send(Message::WalletEvent(account_id, event));
        if let Err(err) = res {
            log::debug!("sending wallet event failed: {err}");
        }
    });

    let market = market_worker::new();

    let mut data = Data {
        app_active: true,
        active_page: proto::ActivePage::Other,
        amp_connected: false,
        ws_connected: false,
        server_status: None,
        env,
        ui,
        market,
        assets: BTreeMap::new(),
        amp_assets: BTreeSet::new(),
        msg_sender,
        ws_sender,
        ws_hint,
        resp_receiver,
        params,
        timers: BTreeMap::new(),
        settings,
        push_token: None,
        policy_asset,
        jade_mng: jade_mng::JadeMng::new(jade_status_callback),
        async_requests: BTreeMap::new(),
        network_settings: Default::default(),
        proxy_address: None,
        wallet_event_callback,
        wallet_data: None,
    };

    debug!("proxy: {:?}", data.proxy());

    let registry_path = data.registry_path();
    assets_registry::init(&registry_path);

    data.load_default_assets();

    while let Some(msg) = recv_message(&mut data, &msg_receiver) {
        let started = std::time::Instant::now();

        match msg {
            Message::Ui(msg) => data.process_ui(msg),
            Message::Ws(resp) => data.process_ws(resp),
            Message::WalletEvent(account_id, event) => data.process_wallet_event(account_id, event),
            Message::WalletNotif(account_id, msg) => data.process_wallet_notif(account_id, msg),
            Message::BackgroundMessage(msg, sender) => data.process_background_message(msg, sender),
            Message::Quit => {
                warn!("quit message received, exit");
                break;
            }
        }

        let processing_time = started.elapsed();
        if processing_time > std::time::Duration::from_millis(100) {
            warn!("processing time: {} seconds", processing_time.as_secs_f64());
        }

        if data
            .ui
            .ui_stopped
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            warn!("ui stopped, exit");
            break;
        }
    }
}
