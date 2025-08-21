use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow, bail, ensure};
use bitcoin::{
    bip32::{ChildNumber, Xpriv},
    hashes::Hash,
};
use elements::{
    AssetId, EcdsaSighashType, OutPoint, Transaction, TxOut, TxOutSecrets, Txid, UnblindError,
    pset::{PartiallySignedTransaction, serialize::Serialize},
    secp256k1_zkp,
};
use lwk_wollet::Chain;
use rand::Rng;
use secp256k1::{SECP256K1, SecretKey};
use serde_bytes::ByteBuf;
use sideswap_api::{
    self as api, AssetBlindingFactor, MarketType, ValueBlindingFactor,
    mkt::{
        self, AssetPair, AssetType, ClientEvent, HistStatus, HistoryOrder, MarketInfo,
        Notification, OrdId, OwnOrder, PublicOrder, QuoteId, QuoteSubId, Request, Response,
        TradeDir,
    },
};
use sideswap_common::{
    event_proofs::EventProofs,
    float_utils,
    green_backend::GREEN_DUMMY_SIG,
    pset::{
        p2pkh_script,
        swap_amount::{SwapAmount, get_swap_amount},
    },
    pset_blind::get_blinding_nonces,
    send_tx::pset::{ConstructPsetArgs, ConstructedPset, PsetInput, PsetOutput, construct_pset},
    target_os::TargetOs,
    types::{asset_float_amount_, asset_int_amount_, asset_scale},
    utxo_select::{self, WalletType},
    verify,
};
use sideswap_jade::jade_mng::{self, AE_STUB_DATA};
use sideswap_types::{
    duration_ms::DurationMs, hex_encoded::HexEncoded, normal_float::NormalFloat,
    timestamp_ms::TimestampMs,
};

use crate::{
    ffi::proto::{self, Account},
    gdk_ses::{JadeData, WalletInfo},
    models,
    settings::{AddressCacheEntry, AddressWallet},
    utils::{
        convert_chart_point, convert_to_swap_utxo, decode_pset, derive_amp_address,
        derive_native_address, derive_nested_address, encode_pset, get_jade_asset_info,
        get_jade_network, get_script_sig, get_witness, unlock_hw,
    },
    worker::{self, wallet},
};

use super::{CallError, SERVER_REQUEST_TIMEOUT_LONG};

// Some random path (not hardened)
pub const REGISTER_PATH: [u32; 1] = [0x4ec71ae];

struct StartedQuote {
    quote_sub_id: QuoteSubId,
    asset_pair: AssetPair,
    asset_type: AssetType,
    amount: u64,
    trade_dir: TradeDir,
    fee_asset: AssetType,
    order_id: Option<u64>,
    client_sub_id: Option<i64>,
    instant_swap: bool,
    ind_price: bool,

    utxos: Vec<models::Utxo>,
    receive_address: models::AddressInfo,
    change_address: models::AddressInfo,
}

pub struct Xprivs {
    pub register_priv: secp256k1::SecretKey,
    pub native_xpriv: Xpriv,
    pub nested_xpriv: Xpriv,
    pub amp_xpriv: Xpriv,
    pub event_proofs: EventProofs,
    pub ack_succeed: bool,
    pub expected_nonce: Option<u32>,
}

struct SwapInfo {
    send_asset: AssetId,
    recv_asset: AssetId,
    recv_amp_asset: bool,
    receive_wallet: Account,
    change_wallet: Account,
}

struct ReceivedQuote {
    started_quote: Arc<StartedQuote>,

    base_amount: u64,
    quote_amount: u64,
    server_fee: u64,
    fixed_fee: u64,

    expires_at: Instant,
}

struct RetryStartQuote {
    msg: proto::to::StartQuotes,
    order_id: Option<u64>,
    private_id: Option<String>,
}

pub struct Data {
    selected_market: Option<AssetPair>,
    own_orders: BTreeMap<OrdId, OwnOrder>,
    server_utxos: BTreeSet<OutPoint>,
    started_quote: Option<Arc<StartedQuote>>,
    received_quotes: BTreeMap<QuoteId, ReceivedQuote>,
    subscribed_charts: Option<AssetPair>,
    xprivs: Option<Xprivs>,
    server_markets: Vec<MarketInfo>,
    token_quotes: Vec<AssetId>,
    ui_markets: Vec<proto::MarketInfo>,
    retry_start_quote: Option<RetryStartQuote>,
}

pub fn new() -> Data {
    Data {
        selected_market: None,
        own_orders: BTreeMap::new(),
        server_utxos: BTreeSet::new(),
        started_quote: None,
        received_quotes: BTreeMap::new(),
        subscribed_charts: None,
        xprivs: None,
        server_markets: Vec::new(),
        token_quotes: Vec::new(),
        ui_markets: Vec::new(),
        retry_start_quote: None,
    }
}

impl From<OrdId> for proto::OrderId {
    fn from(value: OrdId) -> Self {
        proto::OrderId { id: value.value() }
    }
}

impl From<proto::OrderId> for OrdId {
    fn from(value: proto::OrderId) -> Self {
        OrdId::new(value.id)
    }
}

impl From<&proto::AssetPair> for AssetPair {
    fn from(value: &proto::AssetPair) -> Self {
        AssetPair {
            base: value.base.parse().expect("must be valid"),
            quote: value.quote.parse().expect("must be valid"),
        }
    }
}

impl From<AssetPair> for proto::AssetPair {
    fn from(value: AssetPair) -> Self {
        proto::AssetPair {
            base: value.base.to_string(),
            quote: value.quote.to_string(),
        }
    }
}

impl From<AssetType> for proto::AssetType {
    fn from(value: AssetType) -> Self {
        match value {
            AssetType::Base => proto::AssetType::Base,
            AssetType::Quote => proto::AssetType::Quote,
        }
    }
}

impl From<proto::AssetType> for AssetType {
    fn from(value: proto::AssetType) -> Self {
        match value {
            proto::AssetType::Base => AssetType::Base,
            proto::AssetType::Quote => AssetType::Quote,
        }
    }
}

impl From<TradeDir> for proto::TradeDir {
    fn from(value: TradeDir) -> Self {
        match value {
            TradeDir::Sell => proto::TradeDir::Sell,
            TradeDir::Buy => proto::TradeDir::Buy,
        }
    }
}

impl From<proto::TradeDir> for TradeDir {
    fn from(value: proto::TradeDir) -> Self {
        match value {
            proto::TradeDir::Sell => TradeDir::Sell,
            proto::TradeDir::Buy => TradeDir::Buy,
        }
    }
}

impl From<MarketType> for proto::MarketType {
    fn from(value: MarketType) -> Self {
        match value {
            MarketType::Stablecoin => proto::MarketType::Stablecoin,
            MarketType::Amp => proto::MarketType::Amp,
            MarketType::Token => proto::MarketType::Token,
        }
    }
}

impl From<MarketInfo> for proto::MarketInfo {
    fn from(value: MarketInfo) -> Self {
        proto::MarketInfo {
            asset_pair: value.asset_pair.into(),
            fee_asset: proto::AssetType::from(value.fee_asset).into(),
            r#type: proto::MarketType::from(value.type_).into(),
        }
    }
}

impl From<PublicOrder> for proto::PublicOrder {
    fn from(value: PublicOrder) -> Self {
        proto::PublicOrder {
            order_id: value.order_id.into(),
            asset_pair: value.asset_pair.into(),
            trade_dir: proto::TradeDir::from(value.trade_dir).into(),
            amount: value.amount,
            price: value.price.value(),
            two_step: !value.online,
        }
    }
}

impl From<&OwnOrder> for proto::OwnOrder {
    fn from(value: &OwnOrder) -> Self {
        proto::OwnOrder {
            order_id: value.order_id.into(),
            asset_pair: value.asset_pair.into(),
            trade_dir: proto::TradeDir::from(value.trade_dir).into(),
            orig_amount: value.orig_amount,
            active_amount: value.active_amount,
            price: value.price.value(),
            price_tracking: value
                .price_tracking
                .map(|price_tracking| price_tracking.value()),
            private_id: value.private_id.as_ref().map(|value| value.to_string()),
            ttl_seconds: value.ttl.map(|ttl| ttl.as_millis() / 1000),
            two_step: !value.online,
        }
    }
}

impl From<HistStatus> for proto::HistStatus {
    fn from(value: HistStatus) -> Self {
        match value {
            HistStatus::Mempool => proto::HistStatus::Mempool,
            HistStatus::Confirmed => proto::HistStatus::Confirmed,
            HistStatus::TxConflict => proto::HistStatus::TxConflict,
            HistStatus::TxNotFound => proto::HistStatus::TxNotFound,
            HistStatus::Elapsed => proto::HistStatus::Elapsed,
            HistStatus::Cancelled => proto::HistStatus::Cancelled,
            HistStatus::UtxoInvalidated => proto::HistStatus::UtxoInvalidated,
            HistStatus::Replaced => proto::HistStatus::Replaced,
        }
    }
}

impl From<HistoryOrder> for proto::HistoryOrder {
    fn from(value: HistoryOrder) -> Self {
        proto::HistoryOrder {
            id: value.id.value(),
            order_id: value.order_id.into(),
            asset_pair: value.asset_pair.into(),
            trade_dir: proto::TradeDir::from(value.trade_dir).into(),
            base_amount: value.base_amount,
            quote_amount: value.quote_amount,
            price: value.price.value(),
            status: proto::HistStatus::from(value.status).into(),
            txid: value.txid.map(|txid| txid.to_string()),
        }
    }
}

fn send_market_req(worker: &super::Data, req: Request) {
    worker.send_request_msg(api::Request::Market(req));
}

struct GetPriceTaker {
    asset_pair: AssetPair,
    fee_asset: AssetType,
    base_trade_dir: TradeDir,
    base_amount: u64,
    quote_amount: u64,
    server_fee: u64,
}

fn get_price_taker(
    worker: &super::Data,
    GetPriceTaker {
        asset_pair,
        fee_asset,
        base_trade_dir,
        base_amount,
        quote_amount,
        server_fee,
    }: GetPriceTaker,
) -> f64 {
    let base = worker.assets.get(&asset_pair.base).expect("must be known");
    let quote = worker.assets.get(&asset_pair.quote).expect("must be known");

    let (base_amount_taker, quote_amount_taker) = match (base_trade_dir, fee_asset) {
        (TradeDir::Sell, AssetType::Base) => (base_amount + server_fee, quote_amount),
        (TradeDir::Sell, AssetType::Quote) => (base_amount, quote_amount - server_fee),
        (TradeDir::Buy, AssetType::Base) => (base_amount - server_fee, quote_amount),
        (TradeDir::Buy, AssetType::Quote) => (base_amount, quote_amount + server_fee),
    };

    let base_amount_taker = asset_float_amount_(base_amount_taker, base.precision);
    let quote_amount_taker = asset_float_amount_(quote_amount_taker, quote.precision);

    quote_amount_taker / base_amount_taker
}

struct GetSendRecvAmount {
    fee_asset: AssetType,
    base_trade_dir: TradeDir,
    base_amount: u64,
    quote_amount: u64,
    server_fee: u64,
    fixed_fee: u64,
}

struct SendRecvAmount {
    send_amount: u64,
    recv_amount: u64,
}

fn get_send_recv_amount(
    GetSendRecvAmount {
        fee_asset,
        base_trade_dir,
        base_amount,
        quote_amount,
        server_fee,
        fixed_fee,
    }: GetSendRecvAmount,
) -> SendRecvAmount {
    let total_fee = server_fee.saturating_add(fixed_fee);

    let (send_amount, recv_amount) = match (base_trade_dir, fee_asset) {
        (TradeDir::Sell, AssetType::Base) => (base_amount.saturating_add(total_fee), quote_amount),
        (TradeDir::Sell, AssetType::Quote) => (base_amount, quote_amount.saturating_sub(total_fee)),
        (TradeDir::Buy, AssetType::Base) => (quote_amount, base_amount.saturating_sub(total_fee)),
        (TradeDir::Buy, AssetType::Quote) => (quote_amount.saturating_add(total_fee), base_amount),
    };

    SendRecvAmount {
        send_amount,
        recv_amount,
    }
}

pub fn get_wallet_account(wallet: WalletType) -> Account {
    match wallet {
        WalletType::Native => Account::Reg,
        WalletType::Nested => Account::Reg,
        WalletType::AMP => Account::Amp,
    }
}

fn market_list_subscribe(worker: &mut super::Data) {
    worker.make_async_request(
        api::Request::Market(Request::ListMarkets(mkt::ListMarketsRequest {})),
        move |worker, res| {
            match res {
                Ok(api::Response::Market(Response::ListMarkets(resp))) => {
                    worker.market.server_markets = resp.markets;
                    worker.market.token_quotes = resp.token_quotes;
                    sync_market_list(worker);
                }
                Ok(_) => {
                    log::error!("unexpected list markets response");
                }
                Err(err) => {
                    log::error!("market list failed: {err}");
                }
            };
        },
    );
}

fn public_orders_subscribe(worker: &mut super::Data) {
    if let Some(asset_pair) = worker.market.selected_market {
        worker.make_async_request(
            api::Request::Market(Request::Subscribe(mkt::SubscribeRequest { asset_pair })),
            move |worker, res| {
                let list = match res {
                    Ok(api::Response::Market(Response::Subscribe(resp))) => {
                        resp.orders.into_iter().map(Into::into).collect()
                    }
                    Ok(_) => {
                        log::error!("unexpected subscribe response");
                        Vec::new()
                    }
                    Err(err) => {
                        log::debug!("market subscribe failed: {err}");
                        Vec::new()
                    }
                };
                worker
                    .ui
                    .send(proto::from::Msg::PublicOrders(proto::from::PublicOrders {
                        asset_pair: asset_pair.into(),
                        list,
                    }));
            },
        );
    }
}

fn try_get_wallet_key_software(
    worker: &super::Data,
    message: String,
) -> Result<mkt::WalletKey, anyhow::Error> {
    let xprivs = worker
        .market
        .xprivs
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("xprivs are not set"))?;

    let public_key = xprivs.register_priv.public_key(SECP256K1);
    let message_hash = bitcoin::sign_message::signed_msg_hash(&message);
    let message = bitcoin::secp256k1::Message::from_digest(message_hash.to_byte_array());
    let signature = SECP256K1
        .sign_ecdsa(&message, &xprivs.register_priv)
        .to_string();

    Ok(mkt::WalletKey {
        public_key,
        signature,
    })
}

fn try_get_wallet_key_jade(
    hw_data: &JadeData,
    register_path: Vec<ChildNumber>,
    message: String,
) -> Result<mkt::WalletKey, anyhow::Error> {
    let network = get_jade_network(hw_data.env);

    unlock_hw(hw_data.env, &hw_data.jade)?;

    let root_xpub = hw_data.resolve_xpub(network, &[])?;

    let public_key = root_xpub
        .derive_pub(SECP256K1, &register_path)
        .expect("must not fail")
        .public_key;

    let _status = hw_data.jade.start_status(jade_mng::JadeStatus::SignMessage);
    let _resp = hw_data
        .jade
        .sign_message(sideswap_jade::models::SignMessageReq {
            path: register_path.iter().copied().map(u32::from).collect(),
            message,
            ae_host_commitment: AE_STUB_DATA,
        })?;

    let signature = hw_data
        .jade
        .get_signature(Some(AE_STUB_DATA))?
        .ok_or_else(|| anyhow!("empty signature"))?;

    // Convert signature into DER format
    let signature = match signature.len() {
        64 => signature.as_slice(),
        65 => &signature[1..],
        _ => bail!("unexpected signature size: {}", signature.len()),
    };
    let signature = secp256k1::ecdsa::Signature::from_compact(signature)?
        .serialize_der()
        .to_vec();

    let signature = hex::encode(&signature);

    Ok(mkt::WalletKey {
        public_key,
        signature,
    })
}

fn try_get_wallet_key(
    worker: &super::Data,
    challenge: String,
) -> Result<mkt::WalletKey, anyhow::Error> {
    let wallet = worker.get_wallet(Account::Reg).expect("must exist");

    let message = sideswap_common::registration::get_message(&challenge);
    log::debug!("sign message: {message}");

    let register_path = REGISTER_PATH
        .iter()
        .copied()
        .map(ChildNumber::from)
        .collect::<Vec<_>>();

    match &wallet.login_info().wallet_info {
        WalletInfo::Mnemonic(_mnemonic) => try_get_wallet_key_software(worker, message),

        WalletInfo::Jade(hw_data, _watch_only) => {
            try_get_wallet_key_jade(hw_data, register_path, message)
        }
    }
}

fn register_failed(worker: &mut super::Data, err: anyhow::Error) {
    log::error!("market registration failed: {err}");
    worker.show_message(&format!("registration failed: {err}"));
}

fn ws_register(worker: &mut super::Data) {
    log::debug!("start market register request...");
    worker.make_async_request(
        api::Request::Market(Request::Challenge(mkt::ChallengeRequest {})),
        move |worker, res| match res {
            Ok(api::Response::Market(Response::Challenge(resp))) => {
                log::debug!("received challenge: {}", resp.challenge);
                ws_register_with_challenge(worker, resp);
            }
            Ok(_) => {
                log::error!("unexpected response, expected Challenge");
            }
            Err(err) => {
                register_failed(worker, err.into());
            }
        },
    );
}

fn ws_register_with_challenge(worker: &mut super::Data, resp: mkt::ChallengeResponse) {
    let res = try_get_wallet_key(worker, resp.challenge);
    let wallet_key = match res {
        Ok(wallet_key) => {
            log::debug!("received wallet key, public key: {}", wallet_key.public_key);
            wallet_key
        }
        Err(err) => {
            register_failed(worker, err);
            return;
        }
    };

    worker.make_async_request(
        api::Request::Market(Request::Register(mkt::RegisterRequest {
            wallet_key: Some(wallet_key),
        })),
        move |worker, res| match res {
            Ok(api::Response::Market(Response::Register(resp))) => {
                log::debug!("market register succeed");
                worker.settings.market_token = Some(resp.token);
                worker.save_settings();

                ws_login(worker);
            }
            Ok(_) => {
                log::error!("unexpected response, expected Register");
            }
            Err(err) => {
                register_failed(worker, err.into());
            }
        },
    );
}

fn ws_login(worker: &mut super::Data) {
    match worker.settings.market_token.as_ref() {
        Some(token) => {
            log::debug!("start market login request...");

            let event_count = worker
                .market
                .xprivs
                .as_ref()
                .map(|xprivs| xprivs.event_proofs.count())
                .unwrap_or_default();

            worker.make_async_request(
                api::Request::Market(Request::Login(mkt::LoginRequest {
                    token: token.clone(),
                    is_mobile: TargetOs::get().is_mobile(),
                    is_jade: is_jade(worker),
                    event_count,
                })),
                move |worker, res| match res {
                    Ok(api::Response::Market(Response::Login(resp))) => {
                        log::debug!(
                            "market login succeed, {} orders found, {} utxos",
                            resp.orders.len(),
                            resp.utxos.len()
                        );

                        worker.market.own_orders = resp
                            .orders
                            .into_iter()
                            .map(|order| (order.order_id, order))
                            .collect();

                        worker.market.server_utxos = resp.utxos.into_iter().collect();

                        sync_utxos(worker);

                        worker
                            .ui
                            .send(proto::from::Msg::OwnOrders(proto::from::OwnOrders {
                                list: worker.market.own_orders.values().map(Into::into).collect(),
                            }));

                        if let Some(min_order_amounts) = resp.min_order_amounts {
                            if worker.settings.min_order_amounts != Some(min_order_amounts) {
                                worker.settings.min_order_amounts = Some(min_order_amounts);
                                worker.save_settings();
                            }

                            worker.ui.send(proto::from::Msg::MinMarketAmounts(
                                proto::from::MinMarketAmounts {
                                    lbtc: min_order_amounts.lbtc,
                                    usdt: min_order_amounts.usdt,
                                    eurx: min_order_amounts.eurx,
                                },
                            ));
                        }

                        if let Some(xprivs) = worker.market.xprivs.as_mut() {
                            for event in resp.new_events {
                                xprivs.event_proofs.add_event(event).expect("must not fail");
                            }
                        }

                        send_ack(worker);
                    }
                    Ok(_) => {
                        log::error!("unexpected login response");
                    }
                    Err(err) if err.code == api::ErrorCode::UnknownToken => {
                        log::debug!("market register failed: {err}");
                        ws_register(worker);
                    }
                    Err(err) => {
                        log::debug!("unexpected market login error: {err}");
                    }
                },
            );
        }
        None => {
            ws_register(worker);
        }
    }
}

pub fn send_ack(worker: &mut super::Data) {
    let xprivs = match worker.market.xprivs.as_mut() {
        Some(xprivs) => xprivs,
        None => return,
    };

    let nonce = rand::thread_rng().r#gen::<u32>();
    log::debug!("send ack request, nonce: {nonce}...");
    xprivs.expected_nonce = Some(nonce);
    xprivs.ack_succeed = false;
    let signature = xprivs
        .event_proofs
        .sign_client_event(mkt::ClientEvent::Ack { nonce }, &xprivs.register_priv);

    worker.make_async_request(
        api::Request::Market(Request::Ack(mkt::AckRequest { nonce, signature })),
        move |worker, res| match res {
            Ok(_) => {
                log::debug!("send ack succeed");
                worker::replace_timers(
                    worker,
                    Duration::from_secs(3600),
                    worker::TimerEvent::SendAck,
                );
            }
            Err(err) => {
                log::error!("send ack failed: {err}");
                worker::replace_timers(worker, Duration::from_secs(3), worker::TimerEvent::SendAck);
            }
        },
    );
}

pub fn ws_connected(worker: &mut super::Data) {
    market_list_subscribe(worker);
    public_orders_subscribe(worker);
    ws_login(worker);

    // TODO: Re-subscribe to charts?
    // TODO: Re-subscribe to quotes?
}

pub fn ws_disconnected(worker: &mut super::Data) {
    if let Some(xprivs) = worker.market.xprivs.as_mut() {
        xprivs.ack_succeed = false;
    }

    if let Some(asset_pair) = worker.market.selected_market {
        worker
            .ui
            .send(proto::from::Msg::PublicOrders(proto::from::PublicOrders {
                asset_pair: asset_pair.into(),
                list: Vec::new(),
            }));
    }

    worker
        .ui
        .send(proto::from::Msg::OwnOrders(proto::from::OwnOrders {
            list: Vec::new(),
        }));
}

pub fn wallet_utxos(worker: &mut super::Data, account_id: Account, utxos: models::UtxoList) {
    log::debug!(
        "loaded utxos: {}, account_id: {:?}",
        utxos.len(),
        account_id,
    );
    if let Some(wallet_data) = worker.wallet_data.as_mut() {
        wallet_data.wallet_utxos.insert(account_id, utxos);
    }

    sync_utxos(worker);
    sync_market_list(worker);
}

pub fn sync_utxos(worker: &mut super::Data) {
    if is_jade(worker) {
        // Jade can't be online maker, no need to sync UTXOs
        return;
    }

    let wallet_data = match worker.wallet_data.as_ref() {
        Some(wallet_data) => wallet_data,
        None => return,
    };

    let required_online_assets = worker
        .market
        .own_orders
        .values()
        .filter(|order| order.online)
        .map(|order| match order.trade_dir {
            TradeDir::Sell => order.asset_pair.base,
            TradeDir::Buy => order.asset_pair.quote,
        })
        .collect::<BTreeSet<_>>();

    if required_online_assets.is_empty() {
        return;
    }

    // Submit UTXOs from the both wallets

    let mut new_utxos = Vec::new();
    for wallet_utxos in wallet_data.wallet_utxos.values() {
        for (asset_id, utxo_list) in wallet_utxos.iter() {
            if required_online_assets.contains(asset_id) {
                for utxo in utxo_list.iter() {
                    let outpoint = OutPoint {
                        txid: utxo.txhash,
                        vout: utxo.vout,
                    };

                    if !worker.market.server_utxos.contains(&outpoint)
                        && utxo.assetblinder != AssetBlindingFactor::zero()
                        && utxo.amountblinder != ValueBlindingFactor::zero()
                    {
                        log::debug!("send new utxo: {outpoint}");
                        new_utxos.push(utxo);
                    }
                }
            }
        }
    }

    if !new_utxos.is_empty() {
        let new_utxo_count = new_utxos.len();
        log::debug!("send {new_utxo_count} new utxos");
        worker.make_async_request(
            api::Request::Market(mkt::Request::AddUtxos(mkt::AddUtxosRequest {
                utxos: new_utxos
                    .into_iter()
                    .cloned()
                    .map(convert_to_swap_utxo)
                    .collect(),
            })),
            move |data, res| match res {
                Ok(api::Response::Market(Response::AddUtxos(resp))) => {
                    if resp.utxos.len() != new_utxo_count {
                        log::debug!("not all utxos were added");
                        worker::add_timer(
                            data,
                            Duration::from_secs(3),
                            worker::TimerEvent::SyncUtxos,
                        );
                    }
                }
                Ok(_) => {
                    log::error!("unexpected markets response, AddUtxos expected");
                }
                Err(err) => {
                    log::error!("sending utxos failed unexpectedly: {err}");
                }
            },
        );
    }
}
pub fn process_resp(_worker: &mut super::Data, _resp: Response) {}

pub fn process_notif(worker: &mut super::Data, msg: Notification) {
    match msg {
        Notification::MarketAdded(notif) => process_ws_market_added(worker, notif),
        Notification::MarketRemoved(notif) => process_ws_market_removed(worker, notif),
        Notification::UtxoAdded(notif) => process_ws_utxo_added(worker, notif),
        Notification::UtxoRemoved(notif) => process_ws_utxo_removed(worker, notif),
        Notification::OwnOrderCreated(notif) => process_ws_own_order_added(worker, notif),
        Notification::OwnOrderRemoved(notif) => process_ws_own_order_removed(worker, notif),
        Notification::PublicOrderCreated(notif) => process_ws_public_order_added(worker, notif),
        Notification::PublicOrderRemoved(notif) => process_ws_public_order_removed(worker, notif),
        Notification::Quote(notif) => process_ws_quote(worker, notif),
        Notification::MakerSign(notif) => process_ws_maker_sign(worker, notif),
        Notification::MarketPrice(notif) => process_ws_market_price(worker, notif),
        Notification::ChartUpdate(notif) => process_ws_charts_update(worker, notif),
        Notification::HistoryUpdated(notif) => process_ws_hist_updated(worker, notif),
        Notification::NewEvent(notif) => process_ws_new_event(worker, notif),
        Notification::TxBroadcast(notif) => process_ws_tx_broadcast(worker, notif),
    }
}

fn process_ws_market_added(worker: &mut super::Data, notif: mkt::MarketAddedNotif) {
    worker.market.server_markets.push(notif.market);
    sync_market_list(worker);
}

fn process_ws_market_removed(worker: &mut super::Data, notif: mkt::MarketRemovedNotif) {
    let market_index = worker
        .market
        .server_markets
        .iter()
        .position(|market| market.asset_pair == notif.asset_pair);
    if let Some(market_index) = market_index {
        worker.market.server_markets.remove(market_index);
        sync_market_list(worker);
    }
}

fn process_ws_utxo_added(worker: &mut super::Data, notif: mkt::UtxoAddedNotif) {
    worker.market.server_utxos.insert(notif.utxo);
}

fn process_ws_utxo_removed(worker: &mut super::Data, notif: mkt::UtxoRemovedNotif) {
    worker.market.server_utxos.remove(&notif.utxo);

    sync_utxos(worker);
}

fn process_ws_public_order_added(worker: &mut super::Data, notif: mkt::PublicOrderCreatedNotif) {
    worker
        .ui
        .send(proto::from::Msg::PublicOrderCreated(notif.order.into()));
}

fn process_ws_public_order_removed(worker: &mut super::Data, notif: mkt::PublicOrderRemovedNotif) {
    worker
        .ui
        .send(proto::from::Msg::PublicOrderRemoved(notif.order_id.into()));
}

fn process_ws_quote(worker: &mut super::Data, notif: mkt::QuoteNotif) {
    let started_quote = match worker.market.started_quote.as_ref() {
        Some(started_quote) => started_quote,
        None => return,
    };

    if started_quote.quote_sub_id != notif.quote_sub_id {
        return;
    }

    let base_trade_dir = started_quote
        .trade_dir
        .base_trade_dir(started_quote.asset_type);

    let res = match notif.status {
        mkt::QuoteStatus::Success {
            quote_id,
            base_amount,
            quote_amount,
            server_fee,
            fixed_fee,
            ttl,
        } => {
            let price_taker = get_price_taker(
                worker,
                GetPriceTaker {
                    asset_pair: started_quote.asset_pair,
                    fee_asset: started_quote.fee_asset,
                    base_trade_dir,
                    base_amount,
                    quote_amount,
                    server_fee,
                },
            );

            let SendRecvAmount {
                send_amount,
                recv_amount,
            } = get_send_recv_amount(GetSendRecvAmount {
                fee_asset: started_quote.fee_asset,
                base_trade_dir,
                base_amount,
                quote_amount,
                server_fee,
                fixed_fee,
            });

            let expected_amount = match started_quote.trade_dir {
                TradeDir::Sell => send_amount,
                TradeDir::Buy => recv_amount,
            };

            if started_quote.instant_swap && started_quote.amount != expected_amount {
                // The total order book is less than the requested amount.
                // Show an error so that the user can enter lower amount.
                // The user will need to limit how much they are going to sell
                let send_asset = match base_trade_dir {
                    TradeDir::Sell => started_quote.asset_pair.base,
                    TradeDir::Buy => started_quote.asset_pair.quote,
                };
                let send_asset = worker.assets.get(&send_asset).expect("must be known");
                let send_amount = asset_float_amount_(send_amount, send_asset.precision);
                proto::from::quote::Result::Error(format!("Max: {send_amount}"))
            } else {
                worker.market.received_quotes.insert(
                    quote_id,
                    ReceivedQuote {
                        started_quote: Arc::clone(started_quote),
                        base_amount,
                        quote_amount,
                        server_fee,
                        fixed_fee,
                        expires_at: Instant::now() + ttl.duration(),
                    },
                );

                proto::from::quote::Result::Success(proto::from::quote::Success {
                    quote_id: quote_id.value(),
                    base_amount,
                    quote_amount,
                    server_fee,
                    fixed_fee,
                    ttl_milliseconds: ttl.as_millis(),
                    price_taker,
                    send_amount,
                    recv_amount,
                })
            }
        }
        mkt::QuoteStatus::LowBalance {
            base_amount,
            quote_amount,
            server_fee,
            fixed_fee,
            available,
        } => {
            let price_taker = get_price_taker(
                worker,
                GetPriceTaker {
                    asset_pair: started_quote.asset_pair,
                    fee_asset: started_quote.fee_asset,
                    base_trade_dir,
                    base_amount,
                    quote_amount,
                    server_fee,
                },
            );

            let SendRecvAmount {
                send_amount,
                recv_amount,
            } = get_send_recv_amount(GetSendRecvAmount {
                fee_asset: started_quote.fee_asset,
                base_trade_dir,
                base_amount,
                quote_amount,
                server_fee,
                fixed_fee,
            });

            let expected_amount = match started_quote.trade_dir {
                TradeDir::Sell => send_amount,
                TradeDir::Buy => recv_amount,
            };

            if started_quote.ind_price {
                proto::from::quote::Result::IndPrice(proto::from::quote::IndPrice { price_taker })
            } else if started_quote.instant_swap && started_quote.amount != expected_amount {
                // The total order book is less than the requested amount.
                // Show an error so that the user can enter lower amount.
                // The user will need to limit how much they are going to sell
                let send_asset = match base_trade_dir {
                    TradeDir::Sell => started_quote.asset_pair.base,
                    TradeDir::Buy => started_quote.asset_pair.quote,
                };
                let send_asset = worker.assets.get(&send_asset).expect("must be known");
                let send_amount = asset_float_amount_(send_amount, send_asset.precision);
                proto::from::quote::Result::Error(format!("Max: {send_amount}"))
            } else {
                proto::from::quote::Result::LowBalance(proto::from::quote::LowBalance {
                    base_amount,
                    quote_amount,
                    server_fee,
                    fixed_fee,
                    available,
                    price_taker,
                    send_amount,
                    recv_amount,
                })
            }
        }
        mkt::QuoteStatus::Error { error_msg } => proto::from::quote::Result::Error(error_msg),
    };

    worker.ui.send(proto::from::Msg::Quote(proto::from::Quote {
        asset_pair: started_quote.asset_pair.into(),
        asset_type: proto::AssetType::from(started_quote.asset_type).into(),
        amount: started_quote.amount,
        trade_dir: proto::TradeDir::from(started_quote.trade_dir).into(),
        order_id: started_quote.order_id,
        client_sub_id: started_quote.client_sub_id,
        result: Some(res),
    }));

    clean_quotes(worker);
}

pub fn try_sign_pset_software(
    worker: &super::Data,
    mut pset: PartiallySignedTransaction,
) -> Result<PartiallySignedTransaction, anyhow::Error> {
    let wallet_data = worker
        .wallet_data
        .as_ref()
        .ok_or_else(|| anyhow!("no wallet_data"))?;

    let tx = pset.extract_tx()?;
    let mut sighash_cache = elements::sighash::SighashCache::new(&tx);
    let bytes_to_grind = 1;

    let xprivs = worker
        .market
        .xprivs
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("xprivs are not set"))?;

    for (&_account_id, wallet) in wallet_data.wallet_utxos.iter() {
        for list in wallet.values() {
            for utxo in list.iter() {
                let input = pset
                    .inputs_mut()
                    .iter_mut()
                    .enumerate()
                    .find(|(_index, input)| {
                        input.previous_txid == utxo.txhash
                            && input.previous_output_index == utxo.vout
                    });

                if let Some((input_index, pset_input)) = input {
                    let priv_key = derive_priv_key(xprivs, utxo);

                    pset_input.final_script_sig = get_script_sig(utxo);

                    pset_input.final_script_witness = Some(get_witness(
                        &mut sighash_cache,
                        utxo,
                        input_index,
                        elements::EcdsaSighashType::All,
                        &priv_key,
                        bytes_to_grind,
                    ));
                }
            }
        }
    }

    Ok(pset)
}

/// Unblinds a transaction output, if it is confidential.
///
/// It returns the secret elements of the value and asset Pedersen commitments.
pub fn unblind(txout: &TxOut, shared_secret: SecretKey) -> Result<TxOutSecrets, UnblindError> {
    let (commitment, additional_generator) = match (txout.value, txout.asset) {
        (
            elements::confidential::Value::Confidential(com),
            elements::confidential::Asset::Confidential(r#gen),
        ) => (com, r#gen),
        _ => return Err(UnblindError::NotConfidential),
    };

    let rangeproof = txout
        .witness
        .rangeproof
        .as_ref()
        .ok_or(UnblindError::MissingRangeproof)?;

    let (opening, _) = rangeproof.rewind(
        SECP256K1,
        commitment,
        shared_secret,
        txout.script_pubkey.as_bytes(),
        additional_generator,
    )?;

    let (asset, asset_bf) = opening.message.as_ref().split_at(32);
    let asset = AssetId::from_slice(asset)?;
    let asset_bf = AssetBlindingFactor::from_slice(&asset_bf[..32])?;

    let value = opening.value;
    let value_bf = opening.blinding_factor.as_ref();
    let value_bf = ValueBlindingFactor::from_slice(value_bf).expect("must not fail");

    Ok(TxOutSecrets {
        asset,
        asset_bf,
        value,
        value_bf,
    })
}

/// Set blinding_nonces only with normal tx sending
pub fn try_sign_pset_jade(
    worker: &super::Data,
    utxos: &[&models::Utxo],
    receive_addresses: &[&models::AddressInfo],
    change_addresses: &[&models::AddressInfo],
    additional_info: Option<sideswap_jade::models::ReqSignTxAdditionalInfo>,
    mut pset: PartiallySignedTransaction,
    asset_ids: BTreeSet<AssetId>,
    blinding_nonces: Option<&Vec<String>>,
    tx_type: jade_mng::TxType,
) -> Result<PartiallySignedTransaction, anyhow::Error> {
    let network = get_jade_network(worker.env);

    let tx = pset.extract_tx()?;
    let tx_bin = elements::encode::serialize(&tx);

    // We can use any account here, jade instance will be the same
    let jade = Arc::clone(
        &worker
            .get_wallet(Account::Reg)?
            .login_info()
            .wallet_info
            .hw_data()
            .ok_or_else(|| anyhow!("jade is not set"))?
            .jade,
    );

    unlock_hw(worker.env, &jade)?;

    let _status = jade.start_status(jade_mng::JadeStatus::SignTx(tx_type));

    let mut trusted_commitments = Vec::new();
    let mut change = Vec::new();

    let watch_only = worker
        .settings
        .reg_info
        .as_ref()
        .ok_or_else(|| anyhow!("no reg_info"))?
        .watch_only
        .as_ref()
        .ok_or_else(|| anyhow!("no jade"))?;
    let master_blinding_key = watch_only.master_blinding_key.into_inner();

    for (index, (pset_output, tx_output)) in pset.outputs().iter().zip(tx.output.iter()).enumerate()
    {
        let receive_address = receive_addresses
            .iter()
            .find(|address| pset_output.script_pubkey == address.address.script_pubkey());
        let change_address = change_addresses
            .iter()
            .find(|address| pset_output.script_pubkey == address.address.script_pubkey());

        let own_address = receive_address.or(change_address);

        let shared_secret = if let Some(_own_address) = own_address {
            let blinding_key = master_blinding_key.blinding_private_key(&tx_output.script_pubkey);
            let shared_secret = tx_output
                .nonce
                .shared_secret(&blinding_key)
                .ok_or(UnblindError::MissingNonce)?;
            Some(shared_secret)
        } else {
            match blinding_nonces {
                Some(blinding_nonces) => {
                    let blinding_nonce = blinding_nonces.get(index).ok_or_else(|| {
                        anyhow!("blinding_nonces size is less than the tx output len")
                    })?;
                    if !blinding_nonce.is_empty() {
                        let shared_secret = SecretKey::from_str(blinding_nonce)?;
                        Some(shared_secret)
                    } else {
                        None
                    }
                }
                None => None,
            }
        };

        let trusted_commitment = if let Some(shared_secret) = shared_secret {
            let tx_sec = unblind(tx_output, shared_secret)
                .map_err(|err| anyhow!("unblinding output failed: {err}, index: {index}"))?;

            let output_blinding_pk = pset_output
                .blinding_key
                .as_ref()
                .ok_or_else(|| anyhow!("no blinding_key in PSET"))?;

            Some(sideswap_jade::models::TrustedCommitment {
                asset_id: tx_sec.asset.into(),
                value: tx_sec.value,
                asset_generator: tx_output
                    .asset
                    .commitment()
                    .ok_or_else(|| anyhow!("can't find asset_generator"))?,
                value_commitment: tx_output
                    .value
                    .commitment()
                    .ok_or_else(|| anyhow!("can't find value_commitment"))?,
                blinding_key: output_blinding_pk.inner.into(),
                abf: tx_sec.asset_bf,
                vbf: tx_sec.value_bf,
            })
        } else {
            None
        };

        let change_output = match own_address {
            Some(address_info) => {
                let variant = match address_info.address_type {
                    models::AddressType::P2wpkh => {
                        Some(sideswap_jade::models::OutputVariant::P2wpkh)
                    }
                    models::AddressType::P2shP2wpkh => {
                        Some(sideswap_jade::models::OutputVariant::P2wpkhP2sh)
                    }
                    models::AddressType::P2wsh => None,
                };

                let is_change = change_address.is_some();

                Some(sideswap_jade::models::Output {
                    variant,
                    path: address_info.user_path.clone(),
                    recovery_xpub: None,
                    is_change,
                })
            }
            None => None,
        };

        trusted_commitments.push(trusted_commitment);
        change.push(change_output);
    }

    let sign_tx = sideswap_jade::models::ReqSignTx {
        network,
        use_ae_signatures: true,
        txn: ByteBuf::from(tx_bin),
        num_inputs: tx.input.len() as u32,
        trusted_commitments,
        change,
        asset_info: get_jade_asset_info(&worker.assets, asset_ids),
        additional_info,
    };

    let resp = jade.sign_liquid_tx(sign_tx)?;
    ensure!(resp, "sign_tx failed");

    for input in pset.inputs_mut() {
        let utxo = utxos.iter().find(|utxo| {
            utxo.txhash == input.previous_txid && utxo.vout == input.previous_output_index
        });

        match utxo {
            Some(utxo) => {
                let user_path = match utxo.wallet_type {
                    WalletType::Nested | WalletType::Native => utxo
                        .user_path
                        .as_ref()
                        .ok_or_else(|| anyhow!("can't find user_path in UTXO"))?
                        .clone(),
                    WalletType::AMP => worker
                        .settings
                        .reg_info
                        .as_ref()
                        .ok_or_else(|| anyhow!("can't find reg_info"))?
                        .amp_user_path
                        .iter()
                        .copied()
                        .chain(std::iter::once(utxo.pointer))
                        .collect(),
                };

                let _resp = jade.tx_input(Some(sideswap_jade::models::ReqTxInput {
                    is_witness: true,
                    path: user_path,
                    script: ByteBuf::from(utxo.prevout_script.as_bytes()),
                    sighash: None,
                    asset_id: utxo.asset_id.into(),
                    value: utxo.satoshi,
                    abf: utxo.assetblinder,
                    vbf: utxo.amountblinder,
                    value_commitment: utxo
                        .value_commitment
                        .commitment()
                        .ok_or_else(|| anyhow!("the input must be blinded"))?,
                    asset_generator: utxo
                        .asset_commitment
                        .commitment()
                        .ok_or_else(|| anyhow!("the input must be blinded"))?,
                    ae_host_commitment: AE_STUB_DATA,
                    ae_host_entropy: AE_STUB_DATA,
                }))?;
            }
            None => {
                let _resp = jade.tx_input(None)?;
            }
        }
    }

    for input in pset.inputs_mut() {
        let utxo = utxos.iter().find(|utxo| {
            utxo.txhash == input.previous_txid && utxo.vout == input.previous_output_index
        });

        match utxo {
            Some(utxo) => {
                let signature = jade.get_signature(Some(AE_STUB_DATA))?.unwrap();

                let witness = match utxo.wallet_type {
                    WalletType::Nested | WalletType::Native => {
                        let public_key = utxo
                            .public_key
                            .ok_or_else(|| anyhow!("can't find public_key in UTXO"))?;
                        vec![signature, public_key.serialize()]
                    }
                    WalletType::AMP => {
                        vec![
                            vec![],
                            GREEN_DUMMY_SIG.to_vec(),
                            signature,
                            utxo.prevout_script.to_bytes(),
                        ]
                    }
                };

                input.final_script_sig = get_script_sig(utxo);
                input.final_script_witness = Some(witness);
            }
            None => {
                let _signature = jade.get_signature(None)?;
            }
        }
    }
    Ok(pset)
}

fn try_sign_maker_pset(
    worker: &super::Data,
    notif: &mkt::MakerSignNotif,
) -> Result<PartiallySignedTransaction, anyhow::Error> {
    let pset = decode_pset(&notif.pset)?;

    let xprivs = worker
        .market
        .xprivs
        .as_ref()
        .ok_or_else(|| anyhow!("xprivs must be set"))?;
    ensure!(xprivs.ack_succeed);
    ensure!(!notif.orders.is_empty());

    let first_known_order = xprivs
        .event_proofs
        .get_active_orders()
        .get(&notif.orders[0].order_id)
        .ok_or_else(|| anyhow!("can't find order {}", notif.orders[0].order_id))?;

    let base_precision = worker
        .assets
        .get(&first_known_order.asset_pair.base)
        .ok_or_else(|| anyhow!("can't find asset {}", first_known_order.asset_pair.base))?
        .precision;
    let quote_precision = worker
        .assets
        .get(&first_known_order.asset_pair.quote)
        .ok_or_else(|| anyhow!("can't find asset {}", first_known_order.asset_pair.quote))?
        .precision;

    let mut order_ids = BTreeSet::new();
    let mut total_base_amount = 0;
    let mut total_quote_amount = 0;
    for swap in notif.orders.iter() {
        let inserted = order_ids.insert(swap.order_id);
        ensure!(inserted);

        let known_order = xprivs
            .event_proofs
            .get_active_orders()
            .get(&swap.order_id)
            .ok_or_else(|| anyhow!("can't find order {}", swap.order_id))?;

        ensure!(known_order.asset_pair == first_known_order.asset_pair);
        ensure!(known_order.trade_dir == first_known_order.trade_dir);
        if let Some(price) = known_order.price {
            ensure!(
                float_utils::values_near_equal(
                    swap.price.value(),
                    price.value(),
                    float_utils::PRICE_EPS
                ),
                "unexpected price: {}, expected: {}",
                swap.price.value(),
                price.value(),
            );
        }
        if let Some(min_price) = known_order.min_price {
            ensure!(swap.price >= min_price);
        }
        if let Some(max_price) = known_order.max_price {
            ensure!(swap.price <= max_price);
        }
        ensure!(swap.base_amount > 0);
        ensure!(swap.base_amount <= known_order.base_amount);

        // Allow some tolerance in quote amount calculations
        let expected_quote_amount =
            asset_scale(quote_precision) * swap.base_amount as f64 * swap.price.value()
                / asset_scale(base_precision);
        let actual_quote_amount = swap.quote_amount as f64;
        let diff = (1.0 - actual_quote_amount / expected_quote_amount).abs();
        ensure!(
            diff < 0.0001,
            "actual_quote_amount: {actual_quote_amount}, expected_quote_amount: {expected_quote_amount}"
        );

        total_base_amount += swap.base_amount;
        total_quote_amount += swap.quote_amount;
    }

    // FIXME: Verify PSET amounts before signing it
    log::debug!("sign swap, base: {total_base_amount}, quote: {total_quote_amount}");

    let pset = try_sign_pset_software(worker, pset)?;
    Ok(pset)
}

fn process_ws_maker_sign(worker: &mut super::Data, notif: mkt::MakerSignNotif) {
    let res = try_sign_maker_pset(worker, &notif);

    let quote_id = notif.quote_id;
    match res {
        Ok(pset) => {
            worker.make_async_request(
                api::Request::Market(mkt::Request::MakerSign(mkt::MakerSignRequest {
                    quote_id,
                    pset: encode_pset(&pset),
                })),
                move |_data, res| match res {
                    Ok(_) => {
                        log::debug!("sending maker sign succeed, quote_id: {}", quote_id.value());
                    }
                    Err(err) => {
                        log::error!(
                            "sending maker sign failed: {err}, quote_id: {}",
                            quote_id.value()
                        );
                    }
                },
            );
        }
        Err(err) => {
            log::error!(
                "maker pset sign failed: {err}, quote_id: {}",
                quote_id.value()
            );
        }
    }
}

fn process_ws_market_price(worker: &mut super::Data, notif: mkt::MarketPriceNotif) {
    worker
        .ui
        .send(proto::from::Msg::MarketPrice(proto::from::MarketPrice {
            asset_pair: notif.asset_pair.into(),
            ind_price: notif.ind_price.map(NormalFloat::value),
            last_price: notif.last_price.map(NormalFloat::value),
        }));
}

fn process_ws_charts_update(worker: &mut super::Data, notif: mkt::ChartUpdateNotif) {
    if worker.market.subscribed_charts == Some(notif.asset_pair) {
        worker
            .ui
            .send(proto::from::Msg::ChartsUpdate(proto::from::ChartsUpdate {
                asset_pair: notif.asset_pair.into(),
                update: convert_chart_point(notif.update),
            }));
    }
}

fn process_ws_hist_updated(worker: &mut super::Data, notif: mkt::HistoryUpdatedNotif) {
    worker.add_gdk_assets_for_asset_pair(std::iter::once(&notif.order.asset_pair));

    worker.ui.send(proto::from::Msg::HistoryUpdated(
        proto::from::HistoryUpdated {
            order: notif.order.into(),
            is_new: notif.is_new,
        },
    ));
}

fn process_ws_own_order_added(worker: &mut super::Data, notif: mkt::OwnOrderCreatedNotif) {
    worker
        .ui
        .send(proto::from::Msg::OwnOrderCreated((&notif.order).into()));
    worker
        .market
        .own_orders
        .insert(notif.order.order_id, notif.order);
    sync_utxos(worker);
}

fn process_ws_own_order_removed(worker: &mut super::Data, notif: mkt::OwnOrderRemovedNotif) {
    worker
        .ui
        .send(proto::from::Msg::OwnOrderRemoved(notif.order_id.into()));
    worker.market.own_orders.remove(&notif.order_id);
}

fn process_ws_new_event(worker: &mut super::Data, notif: mkt::NewEventNotif) {
    if let Some(xprivs) = worker.market.xprivs.as_mut() {
        if let mkt::EventWithSignature::Client {
            event: ClientEvent::Ack { nonce },
            signature: _,
        } = &notif.event
        {
            log::debug!("ack nonce received: {nonce}");
            if xprivs.expected_nonce == Some(*nonce) {
                log::debug!("expected nonce received");
                xprivs.expected_nonce = None;
                xprivs.ack_succeed = true;
            }
        };

        xprivs
            .event_proofs
            .add_event(notif.event)
            .expect("must not fail");

        let json = serde_json::to_value(&xprivs.event_proofs).expect("must not fail");
        worker.settings.event_proofs = Some(json);
        worker.save_settings();
    }
}

pub fn process_ws_tx_broadcast(worker: &mut super::Data, notif: mkt::TxBroadcastNotif) {
    for account in [Account::Reg, Account::Amp] {
        let tx = notif.tx.clone();
        wallet::callback(
            account,
            worker,
            move |ses| ses.broadcast_tx(&tx),
            |_data, res| match res {
                Ok(()) => {
                    log::debug!("tx broadcast succeed");
                }
                Err(err) => {
                    log::error!("tx broadcast failed: {err}");
                }
            },
        );
    }
}

pub fn market_subscribe(worker: &mut super::Data, msg: proto::AssetPair) {
    market_unsubscribe(worker, proto::Empty {});

    worker.market.selected_market = Some(AssetPair::from(&msg));

    public_orders_subscribe(worker);
}

pub fn market_unsubscribe(worker: &mut super::Data, _msg: proto::Empty) {
    if let Some(asset_pair) = worker.market.selected_market {
        if worker.ws_connected {
            send_market_req(
                worker,
                Request::Unsubscribe(mkt::UnsubscribeRequest { asset_pair }),
            );
        }
        worker.market.selected_market = None;
    }
}

fn try_online_order_submit(
    worker: &mut super::Data,
    msg: proto::to::OrderSubmit,
    swap_info: &SwapInfo,
    receive_address: models::AddressInfo,
) -> Result<OwnOrder, anyhow::Error> {
    // TODO: Allow submitting online orders from mobile (if desktop is connected)
    ensure!(
        !TargetOs::get().is_mobile(),
        "can't submit online orders from mobile"
    );

    ensure!(!is_jade(worker), "Jade can't submit online orders");

    let asset_pair = AssetPair::from(&msg.asset_pair);
    let trade_dir = TradeDir::from(msg.trade_dir());
    let base_amount = msg.base_amount;
    let price = msg
        .price
        .map(|price| NormalFloat::new(price).expect("price must be valid"));
    let price_tracking = msg.price_tracking.map(|price_tracking| {
        NormalFloat::new(price_tracking).expect("price_tracking must be valid")
    });
    let ttl = msg
        .ttl_seconds
        .map(Duration::from_secs)
        .map(DurationMs::from);
    let private = msg.private;
    let client_order_id = None;
    let change_address = get_address(
        worker,
        swap_info.change_wallet,
        AddressType::Change,
        CachePolicy::Skip,
    )?;

    // TODO: Set allowed price range for price_tracking
    let min_price = None;
    let max_price = None;

    let signature = worker.market.xprivs.as_ref().map(|xprivs| {
        xprivs.event_proofs.sign_client_event(
            mkt::ClientEvent::AddOrder {
                asset_pair,
                base_amount,
                price,
                price_tracking,
                min_price,
                max_price,
                trade_dir,
                ttl,
                receive_address: receive_address.address.clone(),
                change_address: change_address.address.clone(),
                private,
                client_order_id: client_order_id.clone(),
            },
            &xprivs.register_priv,
        )
    });

    let resp = send_market_request!(
        worker,
        AddOrder,
        mkt::AddOrderRequest {
            asset_pair,
            base_amount: msg.base_amount,
            price,
            price_tracking,
            min_price,
            max_price,
            trade_dir,
            ttl,
            receive_address: receive_address.address,
            change_address: change_address.address,
            private,
            client_order_id,
            signature,
        },
        SERVER_REQUEST_TIMEOUT_LONG
    )?;

    Ok(resp.order)
}

fn try_create_funding_tx(
    worker: &mut super::Data,
    asset_id: &AssetId,
    target: u64,
) -> Result<(models::Utxo, Transaction), anyhow::Error> {
    let wallet_data = worker
        .wallet_data
        .as_ref()
        .ok_or_else(|| anyhow!("no wallet_data"))?;
    let utxos = wallet_data
        .wallet_utxos
        .values()
        .flat_map(|utxos| utxos.values())
        .flatten()
        .cloned()
        .collect::<Vec<_>>();

    let bitcoin_total = utxos
        .iter()
        .filter_map(|utxo| (utxo.asset_id == worker.policy_asset).then_some(utxo.satoshi))
        .sum::<u64>();

    let deduct_fee = if *asset_id == worker.policy_asset && bitcoin_total == target {
        Some(0)
    } else {
        None
    };

    let wallet_type = if worker.amp_assets.contains(asset_id) {
        WalletType::AMP
    } else {
        WalletType::Native
    };

    // It's not really necessary, but we prefer to receive non-AMP change to the nested Segwit wallet
    let force_change_wallets = worker
        .assets
        .values()
        .filter_map(|asset| {
            (asset.market_type != Some(MarketType::Amp))
                .then_some((asset.asset_id, WalletType::Nested))
        })
        .collect::<BTreeMap<_, _>>();

    let utxo_select_res = utxo_select::select(utxo_select::Args {
        policy_asset: worker.policy_asset,
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
            address: utxo_select::RecipientAddress::Unknown(wallet_type),
            asset_id: *asset_id,
            amount: target,
        }],
        deduct_fee,
        force_change_wallets,
        use_all_utxos: false,
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
    let updated_recipient = &updated_recipients[0];
    let account = get_wallet_account(wallet_type);
    let receive_address = get_address(worker, account, AddressType::Receive, CachePolicy::Skip)?;
    outputs.push(PsetOutput {
        address: receive_address.address.clone(),
        asset_id: updated_recipient.asset_id,
        amount: updated_recipient.amount,
    });

    let mut change_addresses = Vec::new();
    for output in change {
        let account = get_wallet_account(output.wallet);
        let change_address = get_address(worker, account, AddressType::Change, CachePolicy::Skip)?;
        outputs.push(PsetOutput {
            address: change_address.address.clone(),
            asset_id: output.asset_id,
            amount: output.value,
        });
        change_addresses.push(change_address);
    }

    let ConstructedPset {
        blinded_pset,
        blinded_outputs,
    } = construct_pset(ConstructPsetArgs {
        policy_asset: worker.policy_asset,
        offlines: Vec::new(),
        inputs,
        outputs,
        network_fee,
    })?;

    let change_addresses = change_addresses.iter().collect::<Vec<_>>();

    let pset = if is_jade(worker) {
        try_sign_pset_jade(
            worker,
            &selected_utxos,
            &[&receive_address],
            &change_addresses,
            None,
            blinded_pset,
            BTreeSet::from([*asset_id]),
            None,
            jade_mng::TxType::Swap,
        )?
    } else {
        try_sign_pset_software(worker, blinded_pset)?
    };

    let need_green_signature = selected_utxos.iter().any(|utxo| match utxo.wallet_type {
        WalletType::Native | WalletType::Nested => false,
        WalletType::AMP => true,
    });
    let pset = if need_green_signature {
        let wallet_data = worker
            .wallet_data
            .as_ref()
            .ok_or_else(|| anyhow!("no wallet_data"))?;

        let blinding_nonces = get_blinding_nonces(&blinded_outputs);

        wallet_data
            .wallet_amp
            .green_backend_sign(pset, blinding_nonces)?
    } else {
        pset
    };

    let tx = pset.extract_tx()?;

    let prevout_script = if let Some(script) = receive_address.prevout_script.clone() {
        script
    } else if let Some(public_key) = receive_address.public_key {
        p2pkh_script(&public_key)
    } else {
        bail!("script or public_key must be known");
    };

    let vout = tx
        .output
        .iter()
        .position(|output| output.script_pubkey == receive_address.address.script_pubkey())
        .expect("must exist");
    let user_tx_output = &tx.output[vout];

    let blinded_output = blinded_outputs.get(vout).expect("").as_ref().expect("");

    let utxo = models::Utxo {
        wallet_type,
        txhash: tx.txid(),
        pointer: receive_address.pointer,
        vout: vout as u32,
        asset_id: updated_recipient.asset_id,
        satoshi: updated_recipient.amount,
        amountblinder: blinded_output.vbf,
        assetblinder: blinded_output.abf,
        is_internal: receive_address.is_internal.unwrap_or_default(),
        prevout_script,
        is_blinded: true,
        public_key: receive_address.public_key,
        user_path: Some(receive_address.user_path),
        block_height: 0,
        script_pub_key: receive_address.address.script_pubkey(),
        asset_commitment: user_tx_output.asset,
        value_commitment: user_tx_output.value,
    };

    Ok((utxo, tx))
}

fn try_offline_order_submit(
    worker: &mut super::Data,
    msg: proto::to::OrderSubmit,
    swap_info: &SwapInfo,
    receive_address: models::AddressInfo,
) -> Result<OwnOrder, anyhow::Error> {
    let trade_dir = TradeDir::from(msg.trade_dir());
    let asset_pair = AssetPair::from(&msg.asset_pair);

    let base_amount = msg.base_amount;
    let price = msg.price.ok_or_else(|| anyhow!("price must be set"))?;
    let price = NormalFloat::new(price)?;
    ensure!(base_amount > 0);

    ensure!(price.value() > 0.0);
    let base_asset = worker
        .assets
        .get(&asset_pair.base)
        .ok_or_else(|| anyhow!("can't find base asset"))?;
    let quote_asset = worker
        .assets
        .get(&asset_pair.quote)
        .ok_or_else(|| anyhow!("can't find quote asset"))?;

    let base_amount_float = asset_float_amount_(base_amount, base_asset.precision);
    let quote_amount_float = base_amount_float * price.value();
    let quote_amount = asset_int_amount_(quote_amount_float, quote_asset.precision);
    ensure!(quote_amount > 0);

    let (send_amount, recv_amount) = match trade_dir {
        TradeDir::Sell => (base_amount, quote_amount),
        TradeDir::Buy => (quote_amount, base_amount),
    };

    let wallet_data = worker
        .wallet_data
        .as_ref()
        .ok_or_else(|| anyhow!("no wallet_data"))?;
    let utxo = wallet_data
        .wallet_utxos
        .iter()
        .flat_map(|(_account, utxos)| utxos.values())
        .flatten()
        .find(|utxo| {
            utxo.asset_id == swap_info.send_asset
                && utxo.satoshi == send_amount
                && utxo.amountblinder != ValueBlindingFactor::zero()
                && utxo.assetblinder != AssetBlindingFactor::zero()
        })
        .cloned();

    let asset_info = get_jade_asset_info(
        &worker.assets,
        BTreeSet::from([base_asset.asset_id, quote_asset.asset_id]),
    );

    let (utxo, funding_tx) = match utxo {
        Some(utxo) => (utxo, None),
        None => {
            let (utxo, funding_tx) =
                try_create_funding_tx(worker, &swap_info.send_asset, send_amount)?;
            (utxo, Some(HexEncoded::new(funding_tx)))
        }
    };

    let output_asset_id = swap_info.recv_asset;
    let output_script_pubkey = receive_address.address.script_pubkey();

    let output_blinding_pk = receive_address
        .address
        .blinding_pubkey
        .expect("blinding_pubkey must be set");

    let mut rng = rand::thread_rng();
    let output_asset_bf = AssetBlindingFactor::new(&mut rng);
    let output_value_bf = ValueBlindingFactor::new(&mut rng);

    let output_gen = secp256k1_zkp::Generator::new_blinded(
        SECP256K1,
        output_asset_id.into_tag(),
        output_asset_bf.into_inner(),
    );

    let output_asset = elements::confidential::Asset::Confidential(output_gen);

    let value_commitment = secp256k1_zkp::PedersenCommitment::new(
        SECP256K1,
        recv_amount,
        output_value_bf.into_inner(),
        output_gen,
    );

    let output_value = elements::confidential::Value::Confidential(value_commitment);

    let output_ephemeral_sk = secp256k1::SecretKey::new(&mut rng);

    let (output_nonce, _secret_key) = elements::confidential::Nonce::with_ephemeral_sk(
        SECP256K1,
        output_ephemeral_sk,
        &output_blinding_pk,
    );

    let txout = elements::TxOut {
        asset: output_asset,
        value: output_value,
        nonce: output_nonce,
        script_pubkey: output_script_pubkey,
        witness: Default::default(),
    };

    let tx = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            previous_output: OutPoint {
                txid: utxo.txhash,
                vout: utxo.vout,
            },
            is_pegin: false,
            script_sig: get_script_sig(&utxo).unwrap_or_default(),
            sequence: Default::default(),
            asset_issuance: Default::default(),
            witness: Default::default(),
        }],
        output: vec![txout],
    };

    let input_witness = if is_jade(worker) {
        let wallet = worker.get_wallet(Account::Reg)?;
        let network = get_jade_network(worker.env);

        let tx_bin = elements::encode::serialize(&tx);

        let jade = Arc::clone(
            &wallet
                .login_info()
                .wallet_info
                .hw_data()
                .ok_or_else(|| anyhow!("jade is not set"))?
                .jade,
        );
        let _status =
            jade.start_status(jade_mng::JadeStatus::SignTx(jade_mng::TxType::OfflineSwap));

        let additional_info = sideswap_jade::models::ReqSignTxAdditionalInfo {
            is_partial: true,
            tx_type: sideswap_jade::models::TxType::Swap,
            wallet_input_summary: vec![sideswap_jade::models::AdditionalInfoSummary {
                asset_id: swap_info.send_asset.into(),
                satoshi: send_amount,
            }],
            wallet_output_summary: vec![sideswap_jade::models::AdditionalInfoSummary {
                asset_id: swap_info.recv_asset.into(),
                satoshi: recv_amount,
            }],
        };

        let trusted_commitments = vec![Some(sideswap_jade::models::TrustedCommitment {
            asset_id: output_asset_id.into(),
            value: recv_amount,
            asset_generator: output_gen,
            value_commitment,
            blinding_key: output_blinding_pk.into(),
            abf: output_asset_bf,
            vbf: output_value_bf,
        })];

        let variant = match receive_address.address_type {
            models::AddressType::P2wpkh => Some(sideswap_jade::models::OutputVariant::P2wpkh),
            models::AddressType::P2shP2wpkh => {
                Some(sideswap_jade::models::OutputVariant::P2wpkhP2sh)
            }
            models::AddressType::P2wsh => None,
        };

        let change = vec![Some(sideswap_jade::models::Output {
            variant,
            path: receive_address.user_path,
            recovery_xpub: None,
            is_change: false,
        })];

        let sign_tx = sideswap_jade::models::ReqSignTx {
            network,
            use_ae_signatures: true,
            txn: ByteBuf::from(tx_bin),
            num_inputs: tx.input.len() as u32,
            trusted_commitments: trusted_commitments.clone(),
            change,
            asset_info,
            additional_info: Some(additional_info),
        };

        let resp = jade.sign_liquid_tx(sign_tx)?;
        ensure!(resp, "sign_tx failed");

        let user_path = match utxo.wallet_type {
            WalletType::Native | WalletType::Nested => utxo
                .user_path
                .as_ref()
                .ok_or_else(|| anyhow!("can't find user_path in UTXO"))?
                .clone(),
            WalletType::AMP => worker
                .settings
                .reg_info
                .as_ref()
                .ok_or_else(|| anyhow!("can't find reg_info"))?
                .amp_user_path
                .iter()
                .copied()
                .chain(std::iter::once(utxo.pointer))
                .collect(),
        };

        let _resp = jade.tx_input(Some(sideswap_jade::models::ReqTxInput {
            is_witness: true,
            path: user_path,
            script: ByteBuf::from(utxo.prevout_script.as_bytes()),
            sighash: Some(EcdsaSighashType::SinglePlusAnyoneCanPay as u8),
            asset_id: utxo.asset_id.into(),
            value: utxo.satoshi,
            abf: utxo.assetblinder,
            vbf: utxo.amountblinder,
            value_commitment: utxo
                .value_commitment
                .commitment()
                .ok_or_else(|| anyhow!("input must be blinded"))?,
            asset_generator: utxo
                .asset_commitment
                .commitment()
                .ok_or_else(|| anyhow!("input must be blinded"))?,
            ae_host_commitment: AE_STUB_DATA,
            ae_host_entropy: AE_STUB_DATA,
        }))?;

        let signature = jade.get_signature(Some(AE_STUB_DATA))?.unwrap();

        match utxo.wallet_type {
            WalletType::Native | WalletType::Nested => {
                let public_key = utxo
                    .public_key
                    .ok_or_else(|| anyhow!("can't find public_key in UTXO"))?;
                vec![signature, public_key.serialize()]
            }
            WalletType::AMP => {
                vec![
                    vec![],
                    GREEN_DUMMY_SIG.to_vec(),
                    signature,
                    utxo.prevout_script.to_bytes(),
                ]
            }
        }
    } else {
        let xprivs = worker
            .market
            .xprivs
            .as_ref()
            .ok_or_else(|| anyhow!("xprivs is not set"))?;

        let priv_key = derive_priv_key(xprivs, &utxo);

        let mut sighash_cache = elements::sighash::SighashCache::new(&tx);

        let bytes_to_grind = 1;
        get_witness(
            &mut sighash_cache,
            &utxo,
            0,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
            &priv_key,
            bytes_to_grind,
        )
    };

    let resp = send_market_request!(
        worker,
        AddOffline,
        mkt::AddOfflineRequest {
            asset_pair,
            ttl: msg
                .ttl_seconds
                .map(Duration::from_secs)
                .map(DurationMs::from),
            funding_tx,
            private: msg.private,
            client_order_id: None,
            input_utxo: convert_to_swap_utxo(utxo.clone()),
            input_witness,
            output_address: receive_address.address,
            output_amount: recv_amount,
            output_asset_bf,
            output_value_bf,
            output_ephemeral_sk
        },
        SERVER_REQUEST_TIMEOUT_LONG
    )?;

    Ok(resp.order)
}

#[derive(Debug)]
enum ResolveRes {
    Success { address_info: models::AddressInfo },
    UnregisteredGaid { domain_agent: String },
}

#[derive(Copy, Clone)]
pub enum CachePolicy {
    Use,
    Skip,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum AddressType {
    Receive,
    Change,
}

pub fn get_address(
    worker: &mut super::Data,
    account: Account,
    address_type: AddressType,
    cache_policy: CachePolicy,
) -> Result<models::AddressInfo, anyhow::Error> {
    let address_wallet = match (account, address_type) {
        (Account::Reg, AddressType::Receive) => AddressWallet::NativeReceive,
        (Account::Reg, AddressType::Change) => AddressWallet::NativeChange,
        (Account::Amp, _) => AddressWallet::Amp,
    };

    match cache_policy {
        CachePolicy::Use => {
            let cached_address = worker
                .settings
                .address_cache
                .iter()
                .find(|address| address.address_wallet == address_wallet);
            if let Some(address) = cached_address {
                let wallet_data = worker
                    .wallet_data
                    .as_ref()
                    .ok_or_else(|| anyhow!("no wallet_data"))?;

                let expected_address = match address_wallet {
                    AddressWallet::NativeReceive | AddressWallet::NativeChange => {
                        derive_native_address(
                            &wallet_data.xpubs.native_account,
                            worker.env.d().network,
                            address_type == AddressType::Change,
                            address.address.pointer,
                            Some(&wallet_data.xpubs.master_blinding_key),
                        )
                    }
                    AddressWallet::NestedReceive | AddressWallet::NestedChange => {
                        derive_nested_address(
                            &wallet_data.xpubs.nested_account,
                            worker.env.d().network,
                            address_type == AddressType::Change,
                            address.address.pointer,
                            Some(&wallet_data.xpubs.master_blinding_key),
                        )
                    }
                    AddressWallet::Amp => {
                        derive_amp_address(
                            &wallet_data.xpubs.amp_service_xpub,
                            &wallet_data.xpubs.amp_user_xpub,
                            worker.env.d().network,
                            address.address.pointer,
                            Some(&wallet_data.xpubs.master_blinding_key),
                        )
                        .address
                    }
                };
                assert_eq!(
                    expected_address, address.address.address,
                    "wrong cached address"
                );

                return Ok(address.address.clone());
            }
        }
        CachePolicy::Skip => {}
    }

    let wallet_data = worker
        .wallet_data
        .as_ref()
        .ok_or_else(|| anyhow!("no wallet_data"))?;

    let chain = match address_type {
        AddressType::Receive => Chain::External,
        AddressType::Change => Chain::Internal,
    };

    let address = match account {
        Account::Reg => wallet_data.wallet_reg.get_address(chain, None)?,
        Account::Amp => wallet_data.wallet_amp.get_address()?,
    };

    match cache_policy {
        CachePolicy::Use => {
            worker.settings.address_cache.push(AddressCacheEntry {
                address: address.clone(),
                address_wallet,
            });
            worker.save_settings();
        }
        CachePolicy::Skip => {}
    }

    Ok(address)
}

fn remove_cached_address(worker: &mut super::Data, address: &elements::Address) {
    worker
        .settings
        .address_cache
        .retain(|item| item.address.address != *address);
    worker.save_settings();
}

fn resolve_recv_address(
    worker: &mut super::Data,
    swap_info: &SwapInfo,
    cache_policy: CachePolicy,
) -> Result<ResolveRes, anyhow::Error> {
    if swap_info.recv_amp_asset {
        let gaid = worker
            .wallet_data
            .as_ref()
            .ok_or_else(|| anyhow!("no wallet_data"))?
            .gaid
            .clone()
            .ok_or_else(|| anyhow!("no gaid"))?;

        let res = send_market_request!(
            worker,
            ResolveGaid,
            mkt::ResolveGaidRequest {
                asset_id: swap_info.recv_asset,
                gaid
            },
            SERVER_REQUEST_TIMEOUT_LONG
        );

        match res {
            Ok(resp) => Ok({
                let address_info = worker.find_own_amp_address_info(&resp.address)?;
                ResolveRes::Success { address_info }
            }),
            Err(CallError::UnregisteredGaid(err)) => {
                log::debug!("unregistered GAID: {err}");
                let asset = worker
                    .assets
                    .get(&swap_info.recv_asset)
                    .ok_or_else(|| anyhow::anyhow!("can't find asset {}", swap_info.recv_asset))?;
                let domain_agent = asset.domain_agent.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("domain_agent is empty for asset {}", swap_info.recv_asset)
                })?;
                Ok(ResolveRes::UnregisteredGaid {
                    domain_agent: domain_agent.clone(),
                })
            }
            Err(err) => Err(err.into()),
        }
    } else {
        let address_info = get_address(
            worker,
            swap_info.receive_wallet,
            AddressType::Receive,
            cache_policy,
        )?;
        Ok(ResolveRes::Success { address_info })
    }
}

pub fn order_submit(worker: &mut super::Data, msg: proto::to::OrderSubmit) {
    let asset_pair = AssetPair::from(&msg.asset_pair);
    let trade_dir = TradeDir::from(msg.trade_dir());

    let swap_info = get_swap_info(worker, &asset_pair, trade_dir);

    let res = resolve_recv_address(worker, &swap_info, CachePolicy::Skip);

    let res = match res {
        Ok(ResolveRes::Success { address_info }) => Ok(address_info),
        Ok(ResolveRes::UnregisteredGaid { domain_agent }) => {
            Err(proto::from::order_submit::Result::UnregisteredGaid(
                proto::from::order_submit::UnregisteredGaid { domain_agent },
            ))
        }
        Err(err) => Err(proto::from::order_submit::Result::Error(err.to_string())),
    };

    let receive_address = match res {
        Ok(recv_address) => recv_address,
        Err(resp) => {
            worker
                .ui
                .send(proto::from::Msg::OrderSubmit(proto::from::OrderSubmit {
                    result: Some(resp),
                }));
            return;
        }
    };

    let res = if msg.two_step {
        try_offline_order_submit(worker, msg, &swap_info, receive_address)
    } else {
        try_online_order_submit(worker, msg, &swap_info, receive_address)
    };

    let res = match res {
        Ok(order) => proto::from::order_submit::Result::SubmitSucceed((&order).into()),
        Err(err) => proto::from::order_submit::Result::Error(err.to_string()),
    };
    worker
        .ui
        .send(proto::from::Msg::OrderSubmit(proto::from::OrderSubmit {
            result: Some(res),
        }));

    sync_utxos(worker);
}

pub fn try_order_edit(
    worker: &mut super::Data,
    msg: proto::to::OrderEdit,
) -> Result<(), anyhow::Error> {
    let order_id = OrdId::from(msg.order_id);
    let base_amount = msg.base_amount;
    let price = msg.price.map(NormalFloat::new).transpose()?;
    let price_tracking = msg.price_tracking.map(NormalFloat::new).transpose()?;
    // TODO: Set allowed price range for price_tracking
    let min_price = None;
    let max_price = None;
    let receive_address = None;
    let change_address = None;

    let signature = worker.market.xprivs.as_ref().map(|xprivs| {
        xprivs.event_proofs.sign_client_event(
            mkt::ClientEvent::EditOrder {
                order_id,
                base_amount,
                price,
                price_tracking,
                min_price,
                max_price,
                receive_address: receive_address.clone(),
                change_address: change_address.clone(),
            },
            &xprivs.register_priv,
        )
    });

    let _res = send_market_request!(
        worker,
        EditOrder,
        mkt::EditOrderRequest {
            order_id,
            base_amount,
            price,
            price_tracking,
            min_price,
            max_price,
            receive_address,
            change_address,
            signature,
        },
        SERVER_REQUEST_TIMEOUT_LONG
    )?;

    Ok(())
}

pub fn order_edit(worker: &mut super::Data, msg: proto::to::OrderEdit) {
    let res = try_order_edit(worker, msg);
    let result = proto::GenericResponse {
        success: res.is_ok(),
        error_msg: res.err().map(|err| err.to_string()),
    };
    worker.ui.send(proto::from::Msg::OrderEdit(result));
}

pub fn try_order_cancel(
    worker: &mut super::Data,
    msg: proto::to::OrderCancel,
) -> Result<(), anyhow::Error> {
    let _res = send_market_request!(
        worker,
        CancelOrder,
        mkt::CancelOrderRequest {
            order_id: msg.order_id.into(),
        },
        SERVER_REQUEST_TIMEOUT_LONG
    )?;

    Ok(())
}

pub fn order_cancel(worker: &mut super::Data, msg: proto::to::OrderCancel) {
    let res = try_order_cancel(worker, msg);
    let result = proto::GenericResponse {
        success: res.is_ok(),
        error_msg: res.err().map(|err| err.to_string()),
    };
    worker.ui.send(proto::from::Msg::OrderCancel(result));
}

#[derive(thiserror::Error, Debug)]
pub enum StartQuoteError {
    #[error(transparent)]
    Call(#[from] CallError),
    #[error("asset is not registered, asset_id: {0}")]
    UnknownAsset(AssetId),
    #[error("min_order_amounts is not known")]
    NoMinAmount,
    #[error("can't find asset in min_order_amounts")]
    UnknownMinAmountAsset,
    #[error("no wallet_data")]
    NoWalletData,
    #[error(transparent)]
    Address(anyhow::Error),
}

fn try_start_quotes(
    worker: &mut super::Data,
    msg: proto::to::StartQuotes,
    swap_info: SwapInfo,
    receive_address: models::AddressInfo,
    order_id: Option<u64>,
    private_id: Option<String>,
) -> Result<StartedQuote, StartQuoteError> {
    let asset_pair = AssetPair::from(&msg.asset_pair);

    worker.add_gdk_assets_for_asset_pair(std::iter::once(&asset_pair));

    for asset_id in [asset_pair.base, asset_pair.quote] {
        verify!(
            worker.assets.contains_key(&asset_id),
            StartQuoteError::UnknownAsset(asset_id)
        );
    }

    let instant_swap = msg.instant_swap;
    let ind_price = instant_swap && msg.amount == 0;
    let msg_amount = msg.amount;

    let (asset_type, trade_dir, amount) = if ind_price {
        // Start quotes with some small amount to get the best order book price.
        // It's used to show something to users when they just open the instant swaps page.
        let min_order_amounts = worker
            .settings
            .min_order_amounts
            .as_ref()
            .ok_or(StartQuoteError::NoMinAmount)?;
        let known_assets = &worker.env.nd().known_assets;

        let selected_assets = [
            (worker.policy_asset, min_order_amounts.lbtc),
            (known_assets.USDt, min_order_amounts.usdt),
            (known_assets.EURx, min_order_amounts.eurx),
        ];

        let (selected_asset, min_amount) = selected_assets
            .iter()
            .find(|(asset_id, _min_amount)| {
                *asset_id == asset_pair.base || *asset_id == asset_pair.quote
            })
            .ok_or_else(|| StartQuoteError::UnknownMinAmountAsset)?;

        let orig_asset_type = AssetType::from(msg.asset_type());
        let orig_trade_dir = TradeDir::from(msg.trade_dir());
        let base_trade_dir = orig_trade_dir.base_trade_dir(orig_asset_type);

        let asset_type = if *selected_asset == asset_pair.base {
            AssetType::Base
        } else {
            AssetType::Quote
        };

        let trade_dir = match asset_type {
            AssetType::Base => base_trade_dir,
            AssetType::Quote => base_trade_dir.inv(),
        };

        (asset_type, trade_dir, *min_amount)
    } else {
        (
            AssetType::from(msg.asset_type()),
            TradeDir::from(msg.trade_dir()),
            msg.amount,
        )
    };

    let client_sub_id = msg.client_sub_id;
    drop(msg);

    let wallet_data = worker
        .wallet_data
        .as_ref()
        .ok_or(StartQuoteError::NoWalletData)?;

    let utxos = if !ind_price {
        wallet_data
            .wallet_utxos
            .iter()
            .flat_map(|(_account, utxos)| utxos.values())
            .flatten()
            .filter(|utxo| utxo.asset_id == swap_info.send_asset)
            .cloned()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let change_address = get_address(
        worker,
        swap_info.change_wallet,
        AddressType::Change,
        CachePolicy::Use,
    )
    .map_err(StartQuoteError::Address)?;

    let resp = send_market_request!(
        worker,
        StartQuotes,
        mkt::StartQuotesRequest {
            asset_pair,
            asset_type,
            amount,
            trade_dir,
            utxos: utxos.iter().cloned().map(convert_to_swap_utxo).collect(),
            receive_address: receive_address.address.clone(),
            change_address: change_address.address.clone(),
            order_id: order_id.map(OrdId::new),
            private_id: private_id.clone().map(Box::new),
            instant_swap,
            dealer_filter: None,
        },
        SERVER_REQUEST_TIMEOUT_LONG
    )?;

    Ok(StartedQuote {
        quote_sub_id: resp.quote_sub_id,
        asset_pair,
        asset_type,
        amount: msg_amount,
        trade_dir,
        fee_asset: resp.fee_asset,
        instant_swap,
        ind_price,
        utxos,
        receive_address,
        change_address,
        order_id,
        client_sub_id,
    })
}

fn get_swap_info(
    worker: &super::Data,
    asset_pair: &AssetPair,
    base_trade_dir: TradeDir,
) -> SwapInfo {
    let (recv_asset, send_asset) = match base_trade_dir {
        TradeDir::Sell => (asset_pair.quote, asset_pair.base),
        TradeDir::Buy => (asset_pair.base, asset_pair.quote),
    };

    let send_amp_asset = worker.amp_assets.contains(&send_asset);
    let recv_amp_asset = worker.amp_assets.contains(&recv_asset);

    let receive_wallet = if recv_amp_asset {
        Account::Amp
    } else {
        Account::Reg
    };

    let change_wallet = if send_amp_asset {
        Account::Amp
    } else {
        Account::Reg
    };

    SwapInfo {
        send_asset,
        recv_asset,
        recv_amp_asset,
        receive_wallet,
        change_wallet,
    }
}

pub fn start_quotes(
    worker: &mut super::Data,
    msg: proto::to::StartQuotes,
    order_id: Option<u64>,
    private_id: Option<String>,
) {
    stop_quotes(worker, proto::Empty {});

    let asset_pair = AssetPair::from(&msg.asset_pair);
    let trade_dir = TradeDir::from(msg.trade_dir());

    let base_trade_dir = trade_dir.base_trade_dir(msg.asset_type().into());

    let swap_info = get_swap_info(worker, &asset_pair, base_trade_dir);

    let res = resolve_recv_address(worker, &swap_info, CachePolicy::Use);

    let res = match res {
        Ok(ResolveRes::Success { address_info }) => Ok(address_info),
        Ok(ResolveRes::UnregisteredGaid { domain_agent }) => {
            Err(proto::from::quote::Result::UnregisteredGaid(
                proto::from::quote::UnregisteredGaid { domain_agent },
            ))
        }
        Err(err) => Err(proto::from::quote::Result::Error(err.to_string())),
    };

    let receive_address = match res {
        Ok(recv_address) => recv_address,
        Err(resp) => {
            worker.ui.send(proto::from::Msg::Quote(proto::from::Quote {
                asset_pair: msg.asset_pair,
                asset_type: msg.asset_type,
                amount: msg.amount,
                trade_dir: msg.trade_dir,
                order_id,
                client_sub_id: msg.client_sub_id,
                result: Some(resp),
            }));
            return;
        }
    };

    let res = try_start_quotes(
        worker,
        msg.clone(),
        swap_info,
        receive_address,
        order_id,
        private_id.clone(),
    );

    match res {
        Ok(started_quote) => {
            worker.market.started_quote = Some(Arc::new(started_quote));
        }
        Err(err) => {
            worker.ui.send(proto::from::Msg::Quote(proto::from::Quote {
                asset_pair: msg.asset_pair.clone(),
                asset_type: msg.asset_type,
                amount: msg.amount,
                trade_dir: msg.trade_dir,
                order_id,
                client_sub_id: msg.client_sub_id,
                result: Some(proto::from::quote::Result::Error(err.to_string())),
            }));

            let retry = match err {
                StartQuoteError::Call(err) => match err {
                    CallError::UnknownUtxo | CallError::Disconnected => true,

                    CallError::Backend(_)
                    | CallError::UnregisteredGaid(_)
                    | CallError::Timeout
                    | CallError::UnexpectedResponse => false,
                },

                StartQuoteError::UnknownAsset(_)
                | StartQuoteError::NoMinAmount
                | StartQuoteError::UnknownMinAmountAsset
                | StartQuoteError::NoWalletData
                | StartQuoteError::Address(_) => false,
            };

            if retry {
                worker.market.retry_start_quote = Some(RetryStartQuote {
                    msg,
                    order_id,
                    private_id,
                });

                worker::replace_timers(
                    worker,
                    Duration::from_secs(1),
                    worker::TimerEvent::RetryStartQuote,
                );
            }
        }
    }
}

pub fn start_order(
    worker: &mut super::Data,
    proto::to::StartOrder {
        order_id,
        private_id,
    }: proto::to::StartOrder,
) {
    stop_quotes(worker, proto::Empty {});

    let res = send_market_request!(
        worker,
        GetOrder,
        mkt::GetOrderRequest {
            order_id: OrdId::new(order_id),
            private_id: private_id.clone().map(Box::new),
        },
        SERVER_REQUEST_TIMEOUT_LONG
    );

    match res {
        Ok(order) => {
            worker
                .ui
                .send(proto::from::Msg::StartOrder(proto::from::StartOrder {
                    result: Some(proto::from::start_order::Result::Success(
                        proto::from::start_order::Success {
                            asset_pair: order.asset_pair.into(),
                            trade_dir: proto::TradeDir::from(order.trade_dir).into(),
                            amount: order.amount,
                            price: order.price.value(),
                            fee_asset: proto::AssetType::from(order.fee_asset).into(),
                            two_step: !order.online,
                        },
                    )),
                    order_id,
                }));

            start_quotes(
                worker,
                proto::to::StartQuotes {
                    asset_pair: order.asset_pair.into(),
                    asset_type: proto::AssetType::Base.into(),
                    amount: u64::MAX,
                    trade_dir: proto::TradeDir::from(order.trade_dir.inv()).into(),
                    instant_swap: false,
                    client_sub_id: None,
                },
                Some(order_id),
                private_id,
            );
        }

        Err(err) => {
            worker
                .ui
                .send(proto::from::Msg::StartOrder(proto::from::StartOrder {
                    result: Some(proto::from::start_order::Result::Error(err.to_string())),
                    order_id,
                }));
        }
    }
}

pub fn stop_quotes(worker: &mut super::Data, _msg: proto::Empty) {
    worker.market.started_quote = None;

    send_market_req(worker, mkt::Request::StopQuotes(mkt::StopQuotesRequest {}));

    worker.market.retry_start_quote = None;
    super::remove_timers(worker, worker::TimerEvent::RetryStartQuote);
}

fn try_accept_quote(
    worker: &mut super::Data,
    msg: proto::to::AcceptQuote,
) -> Result<Txid, anyhow::Error> {
    clean_quotes(worker);

    let quote_id = QuoteId::new(msg.quote_id);

    let received_quote = worker
        .market
        .received_quotes
        .get(&quote_id)
        .ok_or_else(|| anyhow!("Quote expired"))?;

    let started_quote = Arc::clone(&received_quote.started_quote);

    let resp = send_market_request!(
        worker,
        GetQuote,
        mkt::GetQuoteRequest { quote_id },
        SERVER_REQUEST_TIMEOUT_LONG
    )?;

    let pset = decode_pset(&resp.pset)?;

    let base_trade_dir = started_quote
        .trade_dir
        .base_trade_dir(started_quote.asset_type);

    let (send_asset, recv_asset) = match base_trade_dir {
        TradeDir::Sell => (
            started_quote.asset_pair.base,
            started_quote.asset_pair.quote,
        ),
        TradeDir::Buy => (
            started_quote.asset_pair.quote,
            started_quote.asset_pair.base,
        ),
    };

    let SendRecvAmount {
        send_amount,
        recv_amount,
    } = get_send_recv_amount(GetSendRecvAmount {
        fee_asset: started_quote.fee_asset,
        base_trade_dir,
        base_amount: received_quote.base_amount,
        quote_amount: received_quote.quote_amount,
        server_fee: received_quote.server_fee,
        fixed_fee: received_quote.fixed_fee,
    });

    let additional_info = sideswap_jade::models::ReqSignTxAdditionalInfo {
        is_partial: false,
        tx_type: sideswap_jade::models::TxType::Swap,
        wallet_input_summary: vec![sideswap_jade::models::AdditionalInfoSummary {
            asset_id: send_asset.into(),
            satoshi: send_amount,
        }],
        wallet_output_summary: vec![sideswap_jade::models::AdditionalInfoSummary {
            asset_id: recv_asset.into(),
            satoshi: recv_amount,
        }],
    };

    let tx = pset.extract_tx()?;

    let actual_swap_amounts = get_swap_amount(
        &tx,
        &started_quote
            .utxos
            .iter()
            .cloned()
            .map(convert_to_swap_utxo)
            .collect::<Vec<_>>(),
        &started_quote.receive_address.address,
        &started_quote.change_address.address,
        &resp.receive_ephemeral_sk,
        &resp.change_ephemeral_sk,
    )
    .with_context(|| "swap amount error")?;

    let expected_swap_amount = SwapAmount {
        send_asset,
        send_amount,
        recv_asset,
        recv_amount,
    };

    ensure!(actual_swap_amounts == expected_swap_amount);

    let pset = if is_jade(worker) {
        let utxos = started_quote.utxos.iter().collect::<Vec<_>>();
        try_sign_pset_jade(
            worker,
            &utxos,
            &[&started_quote.receive_address],
            &[&started_quote.change_address],
            Some(additional_info),
            pset,
            BTreeSet::from([send_asset, recv_asset]),
            None,
            jade_mng::TxType::Swap,
        )?
    } else {
        try_sign_pset_software(worker, pset)?
    };

    let resp = send_market_request!(
        worker,
        TakerSign,
        mkt::TakerSignRequest {
            quote_id,
            pset: encode_pset(&pset)
        },
        SERVER_REQUEST_TIMEOUT_LONG
    )?;

    remove_cached_address(worker, &started_quote.receive_address.address);
    remove_cached_address(worker, &started_quote.change_address.address);

    Ok(resp.txid)
}

pub fn accept_quote(worker: &mut super::Data, msg: proto::to::AcceptQuote) {
    let res = try_accept_quote(worker, msg);

    let resp = match res {
        Ok(txid) => {
            worker.start_fast_sync();
            proto::from::accept_quote::Result::Success(proto::from::accept_quote::Success {
                txid: txid.to_string(),
            })
        }
        Err(err) => proto::from::accept_quote::Result::Error(err.to_string()),
    };

    worker
        .ui
        .send(proto::from::Msg::AcceptQuote(proto::from::AcceptQuote {
            result: Some(resp),
        }));
}

pub fn charts_subscribe(worker: &mut super::Data, msg: proto::AssetPair) {
    charts_unsubscribe(worker, proto::Empty {});

    let asset_pair = AssetPair::from(&msg);

    worker.make_async_request(
        api::Request::Market(Request::ChartSub(mkt::ChartSubRequest { asset_pair })),
        move |worker, res| {
            let data = match res {
                Ok(api::Response::Market(Response::ChartSub(resp))) => resp.data,
                Ok(_) => {
                    log::error!("unexpected markets response, expected ChartSub");
                    Vec::new()
                }
                Err(err) => {
                    log::debug!("ChartSub failed: {err}");
                    Vec::new()
                }
            };

            worker.market.subscribed_charts = Some(asset_pair);

            worker.ui.send(proto::from::Msg::ChartsSubscribe(
                proto::from::ChartsSubscribe {
                    asset_pair: asset_pair.into(),
                    data: data.into_iter().map(convert_chart_point).collect(),
                },
            ));
        },
    );
}

pub fn charts_unsubscribe(worker: &mut super::Data, _msg: proto::Empty) {
    if let Some(asset_pair) = worker.market.subscribed_charts {
        send_market_req(
            worker,
            mkt::Request::ChartUnsub(mkt::ChartUnsubRequest { asset_pair }),
        );

        worker.market.subscribed_charts = None;
    }
}

pub fn load_history(worker: &mut super::Data, msg: proto::to::LoadHistory) {
    worker.make_async_request(
        api::Request::Market(Request::LoadHistory(mkt::LoadHistoryRequest {
            start_time: msg.start_time.map(TimestampMs::from_millis),
            end_time: msg.end_time.map(TimestampMs::from_millis),
            skip: msg.skip.map(|value| value as usize),
            count: msg.count.map(|value| value as usize),
        })),
        move |worker, res| {
            match res {
                Ok(api::Response::Market(Response::LoadHistory(resp))) => {
                    worker.add_gdk_assets_for_asset_pair(
                        resp.list.iter().map(|item| &item.asset_pair),
                    );

                    worker
                        .ui
                        .send(proto::from::Msg::LoadHistory(proto::from::LoadHistory {
                            list: resp.list.into_iter().map(Into::into).collect(),
                            total: resp.total as u32,
                        }));
                }
                Ok(_) => {
                    log::error!("unexpected markets response, expected LoadHistory");
                }
                Err(err) => {
                    worker.show_message(&format!("History loading failed: {err}"));
                }
            };
        },
    );
}

pub fn is_jade(worker: &super::Data) -> bool {
    worker.market.xprivs.is_none()
}

pub fn set_xprivs(worker: &mut super::Data, xprivs: Xprivs) {
    worker.market.xprivs = Some(xprivs);
}

fn derive_priv_key(xprivs: &Xprivs, utxo: &models::Utxo) -> SecretKey {
    match utxo.wallet_type {
        WalletType::Native => {
            xprivs
                .native_xpriv
                .derive_priv(
                    SECP256K1,
                    &[
                        ChildNumber::from_normal_idx(utxo.is_internal.into())
                            .expect("must not fail"),
                        ChildNumber::from_normal_idx(utxo.pointer).expect("must not fail"),
                    ],
                )
                .expect("must not fail")
                .private_key
        }
        WalletType::Nested => {
            xprivs
                .nested_xpriv
                .derive_priv(
                    SECP256K1,
                    &[
                        ChildNumber::from_normal_idx(utxo.is_internal.into())
                            .expect("must not fail"),
                        ChildNumber::from_normal_idx(utxo.pointer).expect("must not fail"),
                    ],
                )
                .expect("must not fail")
                .private_key
        }
        WalletType::AMP => {
            xprivs
                .amp_xpriv
                .derive_priv(
                    SECP256K1,
                    &[ChildNumber::from_normal_idx(utxo.pointer).expect("must not fail")],
                )
                .expect("must not fail")
                .private_key
        }
    }
}

fn sync_market_list(worker: &mut super::Data) {
    if worker.market.server_markets.is_empty() {
        return;
    }

    let server_assets = worker
        .market
        .server_markets
        .iter()
        .flat_map(|market| [market.asset_pair.base, market.asset_pair.quote])
        .collect::<BTreeSet<_>>();

    let wallet_data = match worker.wallet_data.as_ref() {
        Some(wallet_data) => wallet_data,
        None => return,
    };

    let wallet_token_assets = wallet_data
        .wallet_utxos
        .iter()
        .filter_map(|(account, utxos)| (*account == Account::Reg).then_some(utxos.keys()))
        .flatten()
        .copied()
        .collect::<BTreeSet<_>>();

    let all_assets = server_assets
        .union(&wallet_token_assets)
        .copied()
        .collect::<Vec<_>>();
    worker.add_missing_assets(all_assets.iter(), false);

    let mut market_list = Vec::<proto::MarketInfo>::new();
    let mut asset_pairs = BTreeSet::<AssetPair>::new();
    for market in worker.market.server_markets.iter() {
        if worker.assets.contains_key(&market.asset_pair.base)
            && worker.assets.contains_key(&market.asset_pair.quote)
        {
            market_list.push(market.clone().into());
            asset_pairs.insert(market.asset_pair);
        }
    }

    for asset in worker.assets.values() {
        for quote_asset in worker.market.token_quotes.iter() {
            let asset_pair = AssetPair {
                base: asset.asset_id,
                quote: *quote_asset,
            };
            if asset.market_type == Some(MarketType::Token)
                && !asset_pairs.contains(&asset_pair)
                && wallet_token_assets.contains(&asset.asset_id)
            {
                market_list.push(proto::MarketInfo {
                    asset_pair: asset_pair.into(),
                    fee_asset: proto::AssetType::Quote.into(),
                    r#type: proto::MarketType::Token.into(),
                });
            }
        }
    }

    if worker.market.ui_markets != market_list {
        worker.market.ui_markets = market_list.clone();
        worker
            .ui
            .send(proto::from::Msg::MarketList(proto::from::MarketList {
                markets: market_list,
            }));
    }
}

pub fn clean_quotes(worker: &mut super::Data) {
    let now = Instant::now();
    worker
        .market
        .received_quotes
        .retain(|_quote_id, quote| quote.expires_at > now);

    if worker.market.received_quotes.is_empty() {
        worker::remove_timers(worker, worker::TimerEvent::CleanQuotes);
        return;
    }

    worker::replace_timers(
        worker,
        Duration::from_secs(1),
        worker::TimerEvent::CleanQuotes,
    );
}

pub fn retry_start_quote(worker: &mut super::Data) {
    if let Some(RetryStartQuote {
        msg,
        order_id,
        private_id,
    }) = worker.market.retry_start_quote.take()
    {
        start_quotes(worker, msg, order_id, private_id);
    }
}
