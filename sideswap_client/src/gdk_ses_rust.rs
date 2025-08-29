use std::{
    collections::HashMap,
    sync::{
        Arc, RwLock, Weak,
        atomic::AtomicUsize,
        mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError},
    },
    time::{Duration, Instant},
};

use anyhow::anyhow;
use bitcoin::bip32::{ChildNumber, Fingerprint, Xpub};
use elements::Txid;
use elements_miniscript::descriptor::checksum::desc_checksum;
use gdk_common::{be::BEScriptConvert, electrum_client::Socks5Config};
use lwk_common::Singlesig;
use lwk_wollet::{
    Chain, ElectrumClient, ElectrumOptions, ElementsNetwork, WolletDescriptor,
    blocking::BlockchainBackend,
};
use secp256k1::SECP256K1;
use sideswap_amp::{Signer, sw_signer::SwSigner};
use sideswap_api::{AssetBlindingFactor, ValueBlindingFactor};
use sideswap_common::{
    cipher::derive_key, env::Env, network::Network, path_helpers::path_from_u32,
    retry_delay::RetryDelay, utxo_select::WalletType,
};
use sideswap_types::{proxy_address::ProxyAddress, timestamp_ms::TimestampMs};

use crate::{
    ffi::proto::Account,
    gdk_ses::{
        self, AddressList, ElectrumServer, GetTransactionsOpt, NotifCallback, TransactionList,
        WalletNotif,
    },
    models::{self, AddressType},
};

struct AccountData {
    xpub: Xpub,
    singlesig: Singlesig,
    wallet: Arc<RwLock<lwk_wollet::Wollet>>,
    command_sender: Sender<Command>,
}

struct WorkerData {
    env: Env,
    wallet: Weak<RwLock<lwk_wollet::Wollet>>,
    notif_callback: Arc<NotifCallback>,
    account_count: Arc<AtomicUsize>,
    total_account_count: usize,
    electrum_server: ElectrumServer,
    proxy: Option<ProxyAddress>,
    app_active: bool,
    fast_sync_started_at: Instant,
}

pub struct GdkSesRust {
    is_mainnet: bool,
    login_info: gdk_ses::LoginInfo,
    accounts: Vec<AccountData>,
}

type ResSender<T> = Sender<Result<T, anyhow::Error>>;

enum Command {
    StartFastSync,
    BroadcastTx(elements::Transaction, ResSender<elements::Txid>),
    SetAppState { active: bool },
}

pub fn full_user_path(
    is_mainnet: bool,
    singlesig: Singlesig,
    ext_int: Chain,
    wildcard_index: u32,
) -> [u32; 5] {
    let wallet_path = match singlesig {
        Singlesig::Wpkh => 84,
        Singlesig::ShWpkh => 49,
    };

    let coin_type = if is_mainnet { 1776 } else { 1 };

    let account_index = 0;

    let chain = match ext_int {
        Chain::External => 0,
        Chain::Internal => 1,
    };

    [
        ChildNumber::Hardened { index: wallet_path }.into(),
        ChildNumber::Hardened { index: coin_type }.into(),
        ChildNumber::Hardened {
            index: account_index,
        }
        .into(),
        ChildNumber::Normal { index: chain }.into(),
        ChildNumber::Normal {
            index: wildcard_index,
        }
        .into(),
    ]
}

fn public_key(account_xpub: &Xpub, ext_int: Chain, wildcard_index: u32) -> bitcoin::PublicKey {
    let chain = match ext_int {
        Chain::External => 0,
        Chain::Internal => 1,
    };

    account_xpub
        .derive_pub(
            SECP256K1,
            &[
                ChildNumber::Normal { index: chain },
                ChildNumber::Normal {
                    index: wildcard_index,
                },
            ],
        )
        .expect("must not fail")
        .public_key
        .into()
}

impl GdkSesRust {
    pub fn start_fast_sync(&self) {
        let _ = self
            .default_account()
            .command_sender
            .send(Command::StartFastSync);
    }

    pub fn set_app_state(&self, active: bool) {
        for account in self.accounts.iter() {
            let _ = account.command_sender.send(Command::SetAppState { active });
        }
    }

    fn default_account(&self) -> &AccountData {
        self.accounts.get(0).expect("must exist")
    }

    fn get_transactions_impl(
        &self,
        opts: GetTransactionsOpt,
    ) -> Result<TransactionList, anyhow::Error> {
        let (pending_only, watching_txid) = match opts {
            GetTransactionsOpt::PendingOnly { watching_txid } => (true, watching_txid),
            GetTransactionsOpt::All => (false, None),
        };

        let mut combined = HashMap::<Txid, models::Transaction>::new();

        let mut max_tip_height = 0;

        for account in self.accounts.iter() {
            let wallet = account.wallet.read().expect("must not fail");

            let tip_height = wallet.store.cache.tip.0;
            let pending_tip_height = tip_height.saturating_sub(1);
            max_tip_height = std::cmp::max(tip_height, max_tip_height);

            let my_txids = wallet
                .store
                .cache
                .heights
                .iter()
                .filter(|(txid, height)| {
                    !pending_only
                        || height
                            .map(|height| height >= pending_tip_height)
                            .unwrap_or(true)
                        || watching_txid == Some(**txid)
                })
                .collect::<Vec<_>>();

            for (txid, _height) in my_txids {
                let tx = wallet
                    .transaction(txid)?
                    .ok_or_else(|| anyhow!("can't find transaction {txid}"))?;

                let created_at = tx
                    .timestamp
                    .map(|timestamp| TimestampMs::from_millis(u64::from(timestamp) * 1000))
                    .unwrap_or_else(|| TimestampMs::now());

                let entry = combined
                    .entry(*txid)
                    .or_insert_with(|| models::Transaction {
                        txid: *txid,
                        network_fee: tx.fee,
                        vsize: tx.tx.vsize(),
                        created_at,
                        block_height: tx.height.unwrap_or_default(),
                        inputs: Vec::new(),
                        outputs: Vec::new(),
                    });

                for tx_input in tx.inputs.iter() {
                    if let Some(input) = tx_input {
                        entry.inputs.push(models::InputOutput {
                            unblinded: input.unblinded,
                        });
                    }
                }

                for tx_output in tx.outputs.iter() {
                    if let Some(output) = tx_output {
                        entry.outputs.push(models::InputOutput {
                            unblinded: output.unblinded,
                        });
                    }
                }
            }
        }

        let txs = combined.into_values().collect();

        Ok(TransactionList {
            tip_height: max_tip_height,
            list: txs,
        })
    }

    pub fn get_address(
        &self,
        ext_int: Chain,
        index: Option<u32>,
    ) -> Result<models::AddressInfo, anyhow::Error> {
        let account = self.default_account();
        let wallet = account.wallet.read().expect("must not fail");

        let address_res = match ext_int {
            Chain::External => wallet.address(index)?,
            Chain::Internal => wallet.change(index)?,
        };

        let address_type = match account.singlesig {
            Singlesig::Wpkh => AddressType::P2wpkh,
            Singlesig::ShWpkh => AddressType::P2shP2wpkh,
        };

        let wildcard_index = address_res.index();

        let user_path = full_user_path(self.is_mainnet, account.singlesig, ext_int, wildcard_index);

        let public_key = public_key(&account.xpub, ext_int, wildcard_index);

        let is_internal = match ext_int {
            Chain::External => false,
            Chain::Internal => true,
        };

        Ok(models::AddressInfo {
            address: address_res.address().clone(),
            address_type,
            pointer: address_res.index(),
            user_path: user_path.to_vec(),
            is_internal: Some(is_internal),
            public_key: Some(public_key),
            prevout_script: None,
            service_xpub: None,
            branch: None,
        })
    }

    pub fn get_previous_addresses(
        &self,
        next_recv_address_index: u32,
    ) -> Result<AddressList, anyhow::Error> {
        let mut list = Vec::new();
        for account in self.accounts.iter() {
            for ext_int in [Chain::External, Chain::Internal] {
                let wallet = account.wallet.read().expect("must not fail");

                let count = match ext_int {
                    Chain::External => match account.singlesig {
                        Singlesig::Wpkh => {
                            let last_unused = wallet.address(None)?.index();
                            std::cmp::max(last_unused, next_recv_address_index)
                        }
                        Singlesig::ShWpkh => wallet.address(None)?.index(),
                    },
                    Chain::Internal => wallet.change(None)?.index(),
                };

                let address_type = match account.singlesig {
                    Singlesig::Wpkh => AddressType::P2wpkh,
                    Singlesig::ShWpkh => AddressType::P2shP2wpkh,
                };

                for wildcard_index in 0..count {
                    let address_res = match ext_int {
                        Chain::External => wallet.address(Some(wildcard_index))?,
                        Chain::Internal => wallet.change(Some(wildcard_index))?,
                    };

                    let user_path =
                        full_user_path(self.is_mainnet, account.singlesig, ext_int, wildcard_index);

                    let public_key = public_key(&account.xpub, ext_int, wildcard_index);

                    let is_internal = match ext_int {
                        Chain::External => false,
                        Chain::Internal => true,
                    };

                    list.push(models::AddressInfo {
                        address: address_res.address().clone(),
                        address_type,
                        pointer: wildcard_index,
                        user_path: user_path.to_vec(),
                        is_internal: Some(is_internal),
                        public_key: Some(public_key),
                        prevout_script: None,
                        service_xpub: None,
                        branch: None,
                    });
                }
            }
        }
        Ok(AddressList { list })
    }
}

impl crate::gdk_ses::GdkSes for GdkSesRust {
    fn login_info(&self) -> &gdk_ses::LoginInfo {
        &self.login_info
    }

    fn get_transactions(&self, opts: GetTransactionsOpt) -> Result<TransactionList, anyhow::Error> {
        self.get_transactions_impl(opts).map_err(Into::into)
    }

    fn broadcast_tx(&self, tx: &str) -> Result<(), anyhow::Error> {
        let account = self.default_account();
        let (res_sender, res_receiver) = mpsc::channel();

        let tx = hex::decode(&tx)?;
        let tx = elements::encode::deserialize(&tx)?;

        account
            .command_sender
            .send(Command::BroadcastTx(tx, res_sender))?;
        res_receiver.recv()??;
        Ok(())
    }

    fn get_utxos(&self) -> Result<models::UtxoList, anyhow::Error> {
        let mut res = models::UtxoList::new();

        for account in self.accounts.iter() {
            let wallet = account.wallet.read().expect("must not fail");
            let utxos = wallet.utxos()?;
            for utxo in utxos {
                res.entry(utxo.unblinded.asset).or_default().push({
                    let is_internal = match utxo.ext_int {
                        Chain::External => false,
                        Chain::Internal => true,
                    };

                    let is_blinded = utxo.unblinded.asset_bf != AssetBlindingFactor::zero()
                        && utxo.unblinded.value_bf != ValueBlindingFactor::zero();

                    let asset_commitment = if utxo.unblinded.asset_bf != AssetBlindingFactor::zero()
                    {
                        elements::confidential::Asset::new_confidential(
                            SECP256K1,
                            utxo.unblinded.asset,
                            utxo.unblinded.asset_bf,
                        )
                    } else {
                        elements::confidential::Asset::Explicit(utxo.unblinded.asset)
                    };

                    let value_commitment = if utxo.unblinded.value_bf != ValueBlindingFactor::zero()
                    {
                        elements::confidential::Value::new_confidential_from_assetid(
                            SECP256K1,
                            utxo.unblinded.value,
                            utxo.unblinded.asset,
                            utxo.unblinded.value_bf,
                            utxo.unblinded.asset_bf,
                        )
                    } else {
                        elements::confidential::Value::Explicit(utxo.unblinded.value)
                    };

                    let public_key = public_key(&account.xpub, utxo.ext_int, utxo.wildcard_index);

                    let wallet_type = match account.singlesig {
                        Singlesig::Wpkh => WalletType::Native,
                        Singlesig::ShWpkh => WalletType::Nested,
                    };

                    let prevout_script =
                        bitcoin::Address::p2pkh(&public_key, bitcoin::Network::Regtest)
                            .script_pubkey();

                    let user_path = full_user_path(
                        self.is_mainnet,
                        account.singlesig,
                        utxo.ext_int,
                        utxo.wildcard_index,
                    );

                    models::Utxo {
                        wallet_type,
                        block_height: utxo.height.unwrap_or_default(),
                        txhash: utxo.outpoint.txid,
                        vout: utxo.outpoint.vout,
                        pointer: utxo.wildcard_index,
                        is_internal,
                        is_blinded,
                        prevout_script: prevout_script.into_elements(),
                        asset_id: utxo.unblinded.asset,
                        satoshi: utxo.unblinded.value,
                        asset_commitment,
                        value_commitment,
                        assetblinder: utxo.unblinded.asset_bf,
                        amountblinder: utxo.unblinded.value_bf,
                        script_pub_key: utxo.script_pubkey,
                        public_key: Some(public_key),
                        user_path: Some(user_path.into_iter().map(u32::from).collect()),
                    }
                });
            }
        }

        Ok(res)
    }
}

pub fn singlesig_desc(
    fingerprint: Fingerprint,
    script_variant: Singlesig,
    is_mainnet: bool,
    xpub: Xpub,
    blinding_key: elements_miniscript::confidential::slip77::MasterBlindingKey,
) -> String {
    let coin_type = if is_mainnet { 1776 } else { 1 };
    let (prefix, path, suffix) = match script_variant {
        Singlesig::Wpkh => ("elwpkh", format!("84h/{coin_type}h/0h"), ""),
        Singlesig::ShWpkh => ("elsh(wpkh", format!("49h/{coin_type}h/0h"), ")"),
    };

    // m / purpose' / coin_type' / account' / change / address_index
    let desc = format!(
        "ct(slip77({blinding_key}),{prefix}([{fingerprint}/{path}]{xpub}/<0;1>/*){suffix})"
    );
    let checksum = desc_checksum(&desc).expect("must not fail");

    format!("{desc}#{checksum}")
}

fn process_command(data: &mut WorkerData, electrum_client: &ElectrumClient, command: Command) {
    match command {
        Command::StartFastSync => {
            data.fast_sync_started_at = Instant::now();
        }

        Command::BroadcastTx(tx, sender) => {
            let res = electrum_client
                .broadcast(&tx)
                .map_err(|err| anyhow!("{err}"));
            let _ = sender.send(res);
        }

        Command::SetAppState { active } => {
            data.app_active = active;
        }
    }
}

fn run(mut data: WorkerData, command_receiver: Receiver<Command>) {
    let (host, port, use_tls) = match (&data.electrum_server, data.env.d().network) {
        (ElectrumServer::Blockstream, Network::Liquid) => {
            ("elements-mainnet.blockstream.info", 50002, true)
        }
        (ElectrumServer::Blockstream, Network::LiquidTestnet) => {
            ("elements-testnet.blockstream.info", 50002, true)
        }

        (ElectrumServer::SideSwap, Network::Liquid) => ("electrs.sideswap.io", 12001, true),
        (ElectrumServer::SideSwap, Network::LiquidTestnet) => ("electrs.sideswap.io", 12002, true),

        (ElectrumServer::SideSwapCn, Network::Liquid) => ("cn.sideswap.io", 12001, true),
        (ElectrumServer::SideSwapCn, Network::LiquidTestnet) => unimplemented!(),

        (
            ElectrumServer::Custom {
                host,
                port,
                use_tls,
            },
            _,
        ) => (host.as_str(), *port, *use_tls),

        (_, Network::Regtest) => ("127.0.0.1", 19002, false),
    };

    let validate_domain = use_tls;

    let url = format!("{host}:{port}");

    let electrum_url = match lwk_wollet::ElectrumUrl::new(&url, use_tls, validate_domain) {
        Ok(electrum_url) => electrum_url,
        Err(err) => {
            (data.notif_callback)(
                Account::Reg,
                WalletNotif::LwkFailed {
                    error_msg: format!("Invalid Electrum URL: {url}: {err}"),
                },
            );
            return;
        }
    };

    let mut retry_delay = RetryDelay::default();

    let mut electrum_client = loop {
        let socks5 = data
            .proxy
            .as_ref()
            .and_then(ProxyAddress::socks5_address)
            .map(|socket| Socks5Config {
                addr: socket.to_string(),
                credentials: None,
            });

        let res = ElectrumClient::with_options(
            &electrum_url,
            ElectrumOptions {
                timeout: Some(15),
                socks5,
            },
        );

        match res {
            Ok(electrum_client) => break electrum_client,

            Err(err) => {
                log::error!("electrum_client connect failed: {err}");
                std::thread::sleep(retry_delay.next_delay());

                if data.wallet.upgrade().is_none() {
                    log::debug!("stop update thread (wallet dropped)");
                    return;
                }
            }
        }
    };

    let mut tip_height = 0;

    let mut first_sync = true;

    let mut error_delay = RetryDelay::default();

    loop {
        loop {
            let command = command_receiver.try_recv();

            match command {
                Ok(command) => {
                    process_command(&mut data, &electrum_client, command);
                }
                Err(TryRecvError::Disconnected) => {
                    log::debug!("stop update thread (channel disconnected)");
                    return;
                }
                Err(TryRecvError::Empty) => break,
            }
        }

        let recv_timeout = if data.app_active {
            if data.fast_sync_started_at.elapsed() < Duration::from_secs(30) {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(10)
            }
        } else {
            Duration::MAX
        };
        let command = command_receiver.recv_timeout(recv_timeout);

        match command {
            Ok(command) => {
                process_command(&mut data, &electrum_client, command);
            }
            Err(RecvTimeoutError::Disconnected) => {
                log::debug!("stop update thread (channel disconnected)");
                return;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }

        let wallet = match data.wallet.upgrade() {
            Some(wallet) => wallet,
            None => {
                log::debug!("stop update thread (wallet dropped)");
                return;
            }
        };

        // TODO: Do we need recreate electrum_client if the request failed?
        let res = electrum_client.full_scan(&*wallet.read().expect("must not fail"));

        match res {
            Ok(Some(update)) => {
                let new_tip_height = update.tip.height;

                let new_txids = update
                    .new_txs
                    .txs
                    .iter()
                    .map(|(txid, _tx)| *txid)
                    .collect::<Vec<_>>();

                let res = wallet.write().expect("must not fail").apply_update(update);
                match res {
                    Ok(()) => {
                        if first_sync {
                            first_sync = false;
                            let total = data
                                .account_count
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if total + 1 == data.total_account_count {
                                (data.notif_callback)(Account::Reg, WalletNotif::LwkSynced);
                            }
                        }

                        if new_tip_height != tip_height {
                            tip_height = new_tip_height;
                            (data.notif_callback)(Account::Reg, WalletNotif::Block);
                        }

                        for new_txid in new_txids {
                            (data.notif_callback)(Account::Reg, WalletNotif::Transaction(new_txid));
                        }

                        error_delay.reset();
                    }

                    Err(err) => {
                        log::error!("apply_update failed: {err}");
                        std::thread::sleep(error_delay.next_delay());
                    }
                }
            }

            Ok(None) => {
                error_delay.reset();
            }

            Err(err) => {
                log::error!("full_scan failed: {err}");
                std::thread::sleep(error_delay.next_delay());
            }
        }
    }
}

pub fn start_processing(
    login_info: gdk_ses::LoginInfo,
    notif_callback: NotifCallback,
) -> Arc<GdkSesRust> {
    let notif_callback = Arc::new(notif_callback);

    let is_mainnet = login_info.env.d().mainnet;

    let (master_blinding_key, xpub_native, xpub_nested, master_xpub_fingerprint) = match &login_info
        .wallet_info
    {
        gdk_ses::WalletInfo::Mnemonic(mnemonic) => {
            let env = login_info.env;
            let sw_signer = SwSigner::new(env.d().network, mnemonic);
            let master_blinding_key = sw_signer.get_master_blinding_key().expect("must not fail");
            let xpub_root = sw_signer.get_xpub(&[]).expect("must not fail");
            let master_xpub_fingerprint = xpub_root.fingerprint();

            let xpub_native = sw_signer
                .get_xpub(&path_from_u32(&env.nd().account_path_wpkh))
                .expect("must not fail");

            let xpub_nested = sw_signer
                .get_xpub(&path_from_u32(&env.nd().account_path_sh_wpkh))
                .expect("must not fail");

            (
                master_blinding_key,
                xpub_native,
                xpub_nested,
                master_xpub_fingerprint,
            )
        }
        gdk_ses::WalletInfo::Jade(_hw_data, watch_only) => (
            watch_only.master_blinding_key.into_inner(),
            watch_only.native_xpub,
            watch_only.nested_xpub,
            watch_only.master_xpub_fingerprint,
        ),
    };

    let lwk_network = match login_info.env.d().network {
        Network::Liquid => ElementsNetwork::Liquid,
        Network::LiquidTestnet => ElementsNetwork::LiquidTestnet,
        Network::Regtest => ElementsNetwork::ElementsRegtest {
            policy_asset: login_info.env.nd().policy_asset,
        },
    };

    let accounts = [
        (xpub_native, Singlesig::Wpkh),
        (xpub_nested, Singlesig::ShWpkh),
    ];

    let total_account_count = accounts.len();

    let account_count = Arc::new(AtomicUsize::new(0));

    let wallets = accounts
        .into_iter()
        .map(|(xpub, single_sig)| {
            let descriptor = singlesig_desc(
                master_xpub_fingerprint,
                single_sig,
                is_mainnet,
                xpub,
                master_blinding_key,
            );

            let descriptor = descriptor
                .parse::<WolletDescriptor>()
                .expect("must not fail");

            let cache_dir_name = hex::encode(&derive_key(
                &xpub.encode(),
                b"sideswap_client/lwk_wallet_path",
            ));

            // TODO: Should we load wallets in backgroun?

            let wallet_dir = login_info.cache_dir.join("lwk").join(&cache_dir_name);
            let wallet = match lwk_wollet::Wollet::with_fs_persist(
                lwk_network,
                descriptor.clone(),
                &wallet_dir,
            ) {
                Ok(wallet) => {
                    log::debug!("lwk wallet loading succeed, path: {wallet_dir:?}");
                    wallet
                }
                Err(err) => {
                    log::warn!("lwk wallet loading failed: {err}");

                    log::debug!("try to remove the cache directory: {wallet_dir:?}");
                    std::fs::remove_dir_all(&wallet_dir)
                        .expect("removing lwk wallet directory should not fail");

                    lwk_wollet::Wollet::with_fs_persist(
                        lwk_network,
                        descriptor.clone(),
                        &wallet_dir,
                    )
                    .expect("creating lwk wallet with a clean cache directory should not fail")
                }
            };

            let wallet = Arc::new(RwLock::new(wallet));

            let (command_sender, command_receiver) = mpsc::channel();

            let worker_data = WorkerData {
                env: login_info.env,
                wallet: Arc::downgrade(&wallet),
                notif_callback: Arc::clone(&notif_callback),
                account_count: Arc::clone(&account_count),
                total_account_count,
                electrum_server: login_info.electrum_server.clone(),
                proxy: login_info.proxy.clone(),
                app_active: true,
                fast_sync_started_at: Instant::now(),
            };

            std::thread::spawn(move || run(worker_data, command_receiver));

            AccountData {
                xpub,
                singlesig: single_sig,
                wallet,
                command_sender,
            }
        })
        .collect();

    let ses = GdkSesRust {
        is_mainnet,
        login_info,
        accounts: wallets,
    };

    Arc::new(ses)
}
