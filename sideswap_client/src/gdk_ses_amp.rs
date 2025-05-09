use std::{sync::Arc, time::Duration};

use bitcoin::bip32::{ChildNumber, Xpub};
use elements::{pset::PartiallySignedTransaction, secp256k1_zkp::global::SECP256K1};
use elements_miniscript::slip77::MasterBlindingKey;
use sideswap_amp::{sw_signer::SwSigner, tx_cache::TxCache, Credentials, Signer};
use sideswap_api::{AssetBlindingFactor, ValueBlindingFactor};
use sideswap_common::{
    channel_helpers::UncheckedOneshotSender,
    cipher::{aes::AesCipher, derive_key},
    file_cache::FileCache,
    network::Network,
    retry_delay::RetryDelay,
    utxo_select::WalletType,
};
use sideswap_jade::{jade_mng::AE_STUB_DATA, models::SignMessageReq};
use tokio::{
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
    task::JoinHandle,
};

use crate::{
    ffi::proto::Account,
    gdk_ses::{
        self, AddressList, GetTransactionsOpt, JadeData, NotifCallback, TransactionList,
        WalletNotif,
    },
    models::{self, AddressType},
    utils::{get_jade_network, unlock_hw},
};

type TxFileCache = FileCache<TxCache, AesCipher>;

pub struct GdkSesAmp {
    command_sender: UnboundedSender<Command>,
    login_info: gdk_ses::LoginInfo,
}

type ResSender<T> = UncheckedOneshotSender<Result<T, anyhow::Error>>;

type ConnectRes = Result<sideswap_amp::Wallet, sideswap_amp::Error>;

enum Command {
    GetTransactions(GetTransactionsOpt, ResSender<TransactionList>),
    GetAddress(ResSender<models::AddressInfo>),
    GetUtxos(ResSender<models::UtxoList>),
    GetPreviousAddresses(ResSender<AddressList>),
    BroadcastTx(String, ResSender<()>),
    GreenBackendSign(
        PartiallySignedTransaction,
        Vec<String>,
        ResSender<PartiallySignedTransaction>,
    ),
}

impl Signer for JadeData {
    fn network(&self) -> Network {
        self.env.d().network
    }

    fn get_master_blinding_key(&self) -> Result<MasterBlindingKey, sideswap_amp::Error> {
        unlock_hw(self.env, &self.jade)
            .map_err(|err| sideswap_amp::Error::Signer(err.to_string()))?;

        let master_blinding_key = self
            .master_blinding_key()
            .map_err(|err| sideswap_amp::Error::Signer(err.to_string()))?;

        Ok(master_blinding_key)
    }

    fn get_xpub(&self, path: &[ChildNumber]) -> Result<Xpub, sideswap_amp::Error> {
        let path = path.iter().copied().map(u32::from).collect::<Vec<_>>();
        let network = get_jade_network(self.env);
        let xpub = self
            .resolve_xpub(network, &path)
            .map_err(|err| sideswap_amp::Error::Signer(err.to_string()))?;
        Ok(xpub)
    }

    fn sign_message(
        &self,
        path: &[ChildNumber],
        message: String,
    ) -> Result<secp256k1::ecdsa::Signature, sideswap_amp::Error> {
        let path = path.iter().copied().map(u32::from).collect::<Vec<_>>();

        self.jade
            .sign_message(SignMessageReq {
                path,
                message,
                ae_host_commitment: AE_STUB_DATA,
            })
            .map_err(|err| sideswap_amp::Error::Signer(err.to_string()))?;

        let signature = self
            .jade
            .get_signature(Some(AE_STUB_DATA))
            .map_err(|err| sideswap_amp::Error::Signer(err.to_string()))?
            .ok_or_else(|| sideswap_amp::Error::Signer("empty signature response".to_owned()))?;

        let signature = secp256k1::ecdsa::Signature::from_compact(&signature)
            .map_err(|err| sideswap_amp::Error::Signer(err.to_string()))?;

        Ok(signature)
    }
}

impl GdkSesAmp {
    pub fn green_backend_sign(
        &self,
        pset: PartiallySignedTransaction,
        blinding_nonces: Vec<String>,
    ) -> Result<PartiallySignedTransaction, anyhow::Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender.send(Command::GreenBackendSign(
            pset,
            blinding_nonces,
            res_sender.into(),
        ))?;
        res_receiver.blocking_recv()?
    }
}

impl crate::gdk_ses::GdkSes for GdkSesAmp {
    fn login_info(&self) -> &gdk_ses::LoginInfo {
        &self.login_info
    }

    fn get_transactions(&self, opts: GetTransactionsOpt) -> Result<TransactionList, anyhow::Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::GetTransactions(opts, res_sender.into()))?;
        res_receiver.blocking_recv()?
    }

    fn get_address(&self, _is_internal: bool) -> Result<models::AddressInfo, anyhow::Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::GetAddress(res_sender.into()))?;
        res_receiver.blocking_recv()?
    }

    fn broadcast_tx(&self, tx: &str) -> Result<(), anyhow::Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::BroadcastTx(tx.to_owned(), res_sender.into()))?;
        res_receiver.blocking_recv()?
    }

    fn get_utxos(&self) -> Result<models::UtxoList, anyhow::Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::GetUtxos(res_sender.into()))?;
        res_receiver.blocking_recv()?
    }

    fn get_previous_addresses(&self) -> Result<AddressList, anyhow::Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.command_sender
            .send(Command::GetPreviousAddresses(res_sender.into()))?;
        res_receiver.blocking_recv()?
    }
}

type WalletOpt = Option<sideswap_amp::Wallet>;

struct Data {
    login_info: gdk_ses::LoginInfo,
    event_callback: sideswap_amp::EventCallback,
    wallet: WalletOpt,
    connection_task: Option<JoinHandle<ConnectRes>>,
    tx_cache: TxFileCache,
    account: Account,
    notif_callback: NotifCallback,
    retry_delay: RetryDelay,
}

fn get_wallet(wallet: &WalletOpt) -> Result<&sideswap_amp::Wallet, anyhow::Error> {
    wallet
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("the AMP wallet is disconnected"))
}

// TODO: Can this work in background?
async fn get_transactions(
    data: &mut Data,
    opts: GetTransactionsOpt,
) -> Result<TransactionList, anyhow::Error> {
    let wallet = get_wallet(&data.wallet)?;
    let tip_height = wallet.block_height().await?;
    let pending_tip_height = tip_height.saturating_sub(1);

    wallet.reload_txs(data.tx_cache.data_mut()).await?;

    let res = data.tx_cache.save();
    match res {
        Ok(size) => log::debug!("tx cache save succeed ({size} bytes)"),
        Err(err) => log::error!("tx cache save failed: {err}"),
    }

    let pending_only = match opts {
        GetTransactionsOpt::PendingOnly => true,
        GetTransactionsOpt::All => false,
    };

    let txs = data
        .tx_cache
        .data()
        .txs()
        .iter()
        .filter(|tx| !pending_only || tx.block_height == 0 || tx.block_height >= pending_tip_height)
        .map(|tx| models::Transaction {
            txid: tx.txid,
            network_fee: tx.network_fee,
            vsize: tx.vsize,
            created_at: tx.created_at.as_millis(),
            block_height: tx.block_height,
            inputs: tx
                .inputs
                .iter()
                .map(|input| models::InputOutput {
                    unblinded: input.unblinded,
                })
                .collect(),
            outputs: tx
                .outputs
                .iter()
                .map(|output| models::InputOutput {
                    unblinded: output.unblinded,
                })
                .collect(),
        })
        .collect();

    Ok(TransactionList {
        tip_height,
        list: txs,
    })
}

async fn get_recv_address(wallet: &WalletOpt) -> Result<models::AddressInfo, anyhow::Error> {
    let wallet = get_wallet(&wallet)?;
    let address_info = wallet.receive_address().await?;

    Ok(models::AddressInfo {
        address: address_info.address,
        address_type: AddressType::P2wsh,
        pointer: address_info.pointer,
        user_path: address_info.user_path,
        is_internal: None,
        public_key: None,
        prevout_script: Some(address_info.prevout_script),
        service_xpub: Some(address_info.service_xpub),
    })
}

async fn get_utxos(wallet: &WalletOpt) -> Result<models::UtxoList, anyhow::Error> {
    let wallet = get_wallet(wallet)?;
    let mut res = models::UtxoList::new();
    let utxos = wallet.unspent_outputs().await?;
    for utxo in utxos {
        let list = res.entry(utxo.tx_out_sec.asset).or_default();

        let is_blinded = utxo.tx_out_sec.asset_bf != AssetBlindingFactor::zero()
            && utxo.tx_out_sec.value_bf != ValueBlindingFactor::zero();

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

        list.push(models::Utxo {
            wallet_type: WalletType::AMP,
            block_height: utxo.block_height.unwrap_or_default(),
            txhash: utxo.outpoint.txid,
            vout: utxo.outpoint.vout,
            pointer: utxo.pointer,
            is_internal: false,
            is_blinded,
            prevout_script: utxo.prevout_script,
            asset_id: utxo.tx_out_sec.asset,
            satoshi: utxo.tx_out_sec.value,
            asset_commitment,
            value_commitment,
            amountblinder: utxo.tx_out_sec.value_bf,
            assetblinder: utxo.tx_out_sec.asset_bf,
            script_pub_key: utxo.script_pub_key,
            public_key: None,
            user_path: None,
        });
    }
    Ok(res)
}

async fn get_previous_addresses(wallet: &WalletOpt) -> Result<AddressList, anyhow::Error> {
    let wallet = get_wallet(&wallet)?;
    let list = wallet.previous_addresses().await?;
    let list = list
        .into_iter()
        .map(|addr| models::AddressInfo {
            address: addr.address,
            address_type: AddressType::P2wsh,
            pointer: addr.pointer,
            user_path: addr.user_path,
            is_internal: None,
            public_key: None,
            prevout_script: Some(addr.prevout_script),
            service_xpub: Some(addr.service_xpub.to_string()),
        })
        .collect();
    Ok(AddressList { list })
}

async fn broadcast_tx(wallet: &WalletOpt, tx: String) -> Result<(), anyhow::Error> {
    let wallet = get_wallet(&wallet)?;
    let _txid = wallet.broadcast_tx(tx.to_owned()).await?;
    Ok(())
}

async fn green_backend_sign(
    data: &mut Data,
    pset: PartiallySignedTransaction,
    blinding_nonces: Vec<String>,
) -> Result<PartiallySignedTransaction, anyhow::Error> {
    if data
        .wallet
        .as_ref()
        .map(|wallet| wallet.watch_only())
        .unwrap_or(false)
    {
        log::debug!("start full jade session");
        let full_wallet = connect(
            data.login_info.clone(),
            data.event_callback.clone(),
            true,
            Duration::ZERO,
        )
        .await?;
        data.wallet = Some(full_wallet);
    }

    let wallet = get_wallet(&data.wallet)?;

    let pset = wallet
        .green_backend_sign(pset, blinding_nonces, sideswap_amp::SignAction::SignOnly)
        .await?;

    Ok(pset)
}

async fn connect(
    login_info: gdk_ses::LoginInfo,
    event_callback: sideswap_amp::EventCallback,
    full_session: bool,
    delay: Duration,
) -> ConnectRes {
    tokio::time::sleep(delay).await;

    match &login_info.wallet_info {
        gdk_ses::WalletInfo::Mnemonic(mnemonic) => {
            sideswap_amp::Wallet::connect_once(
                &sideswap_amp::LoginType::Full(Arc::new(SwSigner::new(
                    login_info.env.d().network,
                    mnemonic,
                ))),
                event_callback,
                &login_info.proxy,
            )
            .await
        }

        gdk_ses::WalletInfo::Jade(jade, watch_only) => {
            if full_session {
                sideswap_amp::Wallet::connect_once(
                    &sideswap_amp::LoginType::Full(Arc::new(jade.clone())),
                    event_callback,
                    &login_info.proxy,
                )
                .await
            } else {
                let credentials = derive_amp_wo_login(watch_only.master_blinding_key.as_ref());
                sideswap_amp::Wallet::connect_once(
                    &sideswap_amp::LoginType::WatchOnly {
                        master_blinding_key: watch_only.master_blinding_key.into_inner(),
                        credentials,
                        network: jade.network(),
                        amp_user_xpub: watch_only.amp_user_xpub,
                    },
                    event_callback,
                    &login_info.proxy,
                )
                .await
            }
        }
    }
}

fn reconnect(data: &mut Data) {
    data.wallet = None;

    let handle = tokio::spawn(connect(
        data.login_info.clone(),
        data.event_callback.clone(),
        false,
        data.retry_delay.next_delay(),
    ));

    data.connection_task = Some(handle);
}

async fn get_reconnect_result(data: &mut Data) -> ConnectRes {
    // Must be cancel-safe!
    match data.connection_task.as_mut() {
        Some(connection_task) => {
            let res = connection_task.await.expect("the task must not panic");
            data.connection_task = None;
            res
        }
        None => std::future::pending().await,
    }
}

fn process_reconnect_result(data: &mut Data, res: ConnectRes) {
    match res {
        Ok(wallet) => {
            log::debug!("amp connection succeed");
            data.retry_delay = Default::default();
            data.wallet = Some(wallet);
        }

        Err(err) => {
            let is_fatal = err.is_fatal();
            log::debug!("amp connection failed: {err}, is_fatal: {is_fatal}");
            if is_fatal {
                (data.notif_callback)(
                    data.account,
                    WalletNotif::AmpFailed {
                        error_msg: err.to_string(),
                    },
                );
            } else {
                reconnect(data);
            }
        }
    }
}

async fn process_command(data: &mut Data, command: Command) {
    match command {
        Command::GetTransactions(opts, res_sender) => {
            let res = get_transactions(data, opts).await;
            res_sender.send(res);
        }

        Command::GetAddress(res_sender) => {
            let wallet = data.wallet.clone();
            tokio::spawn(async move {
                let res = get_recv_address(&wallet).await;
                res_sender.send(res);
            });
        }

        Command::GetUtxos(res_sender) => {
            let wallet = data.wallet.clone();
            tokio::spawn(async move {
                let res = get_utxos(&wallet).await;
                res_sender.send(res);
            });
        }

        Command::GetPreviousAddresses(sender) => {
            let wallet = data.wallet.clone();
            tokio::spawn(async move {
                let res = get_previous_addresses(&wallet).await;
                sender.send(res);
            });
        }

        Command::BroadcastTx(tx, res_sender) => {
            let wallet = data.wallet.clone();
            tokio::spawn(async move {
                let res = broadcast_tx(&wallet, tx).await;
                res_sender.send(res);
            });
        }

        Command::GreenBackendSign(pset, blinding_nonces, res_sender) => {
            let res = green_backend_sign(data, pset, blinding_nonces).await;
            res_sender.send(res);
        }
    }
}

async fn process_event(data: &mut Data, event: sideswap_amp::Event) {
    let notif_callback = &data.notif_callback;
    let account = data.account;

    match event {
        sideswap_amp::Event::Connected {
            gaid,
            subaccount,
            block_height: _,
        } => {
            notif_callback(account, WalletNotif::AmpConnected { subaccount, gaid });
        }

        sideswap_amp::Event::Disconnected => {
            notif_callback(account, WalletNotif::AmpDisconnected);
            data.wallet = None;
            reconnect(data);
        }

        sideswap_amp::Event::BalanceUpdated { balances: _ } => {
            notif_callback(account, WalletNotif::AmpBalanceUpdated);
        }

        sideswap_amp::Event::NewBlock { block_height: _ } => {
            notif_callback(account, WalletNotif::Block);
        }

        sideswap_amp::Event::NewTx { txid } => {
            notif_callback(account, WalletNotif::Transaction(txid));
        }
    }
}

async fn run(
    login_info: gdk_ses::LoginInfo,
    notif_callback: NotifCallback,
    mut command_receiver: UnboundedReceiver<Command>,
) {
    let (event_sender, mut event_receiver) = unbounded_channel::<sideswap_amp::Event>();

    let event_callback = Arc::new(move |event: sideswap_amp::Event| {
        let res = event_sender.send(event);
        if res.is_err() {
            log::debug!("sending AMP wallet event failed: channel is closed");
        }
    });

    let account = login_info.account;

    let master_blinding_key = login_info.wallet_info.master_blinding_key();

    let dir_name = derive_key(
        master_blinding_key.as_bytes(),
        b"sideswap_client/amp_cache_dir_name",
    );
    let dir_name = hex::encode(&dir_name);

    let cipher_key = derive_key(
        master_blinding_key.as_bytes(),
        b"sideswap_client/amp_cache_key",
    );

    let cache_dir_path = login_info.cache_dir.join(dir_name);
    std::fs::create_dir_all(&cache_dir_path).expect("must not fail");
    let cache_file_path = cache_dir_path.join("amp_cache.bin");

    let cache_cipher = AesCipher::new(&cipher_key);
    let tx_cache = TxFileCache::new(cache_file_path, cache_cipher);

    let mut data = Data {
        login_info,
        event_callback,
        wallet: None,
        connection_task: None,
        tx_cache,
        account,
        notif_callback,
        retry_delay: Default::default(),
    };

    reconnect(&mut data);

    loop {
        tokio::select! {
            command = command_receiver.recv() => {
                match command {
                    Some(command) => process_command(&mut data, command).await,
                    None => break,
                }
            },

            event = event_receiver.recv() => {
                let event = event.expect("channel must be open");
                process_event(&mut data, event).await;
            },

            res = get_reconnect_result(&mut data) => {
                process_reconnect_result(&mut data, res);
            },
        }
    }
}

pub fn start_processing(
    login_info: gdk_ses::LoginInfo,
    notif_callback: NotifCallback,
) -> Arc<GdkSesAmp> {
    let (command_sender, command_receiver) = unbounded_channel();

    let ses = GdkSesAmp {
        login_info: login_info.clone(),
        command_sender,
    };

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("must not fail");

        runtime.block_on(run(login_info, notif_callback, command_receiver));
    });

    Arc::new(ses)
}

pub fn derive_amp_wo_login(key: &MasterBlindingKey) -> Credentials {
    let username = derive_key(key.as_bytes(), b"sideswap_client/amp_login");
    let password = derive_key(key.as_bytes(), b"sideswap_client/amp_password");
    let username = format!("sswp_{}", hex::encode(&username[0..10]));
    let password = hex::encode(&password[0..16]);
    Credentials { username, password }
}
