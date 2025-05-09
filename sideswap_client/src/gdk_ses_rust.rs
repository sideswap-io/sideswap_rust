use std::{collections::HashMap, path::Path, str::FromStr, sync::Arc, u32};

use anyhow::bail;
use elements::TxOutSecrets;
use gdk_common::{
    be::BETxid,
    model::{
        AccountData, GetAddressOpt, GetPreviousAddressesOpt, GetUnspentOpt, WatchOnlyCredentials,
    },
    session::Session,
    util::MasterBlindingKey,
};
use sideswap_amp::{sw_signer::SwSigner, Signer};
use sideswap_common::{
    env::Env, network::Network, path_helpers::path_from_u32, utxo_select::WalletType,
};
use sideswap_types::timestamp_ms::TimestampMs;
use ureq::json;

use crate::{
    gdk_ses::{
        self, AddressList, ElectrumServer, GetTransactionsOpt, NotifCallback, TransactionList,
        WalletNotif,
    },
    models::{self, AddressType},
};

struct GdkSesRust {
    login_info: gdk_ses::LoginInfo,
    session: gdk_electrum::ElectrumSession,
    subaccounts: Vec<(WalletType, u32)>,
    default_subaccount: u32,
}

impl GdkSesRust {
    fn login(&mut self) {
        let accounts = match &self.login_info.wallet_info {
            gdk_ses::WalletInfo::Mnemonic(mnemonic) => {
                let env = self.login_info.env;

                let sw_signer = SwSigner::new(env.d().network, mnemonic);

                let master_blinding_key =
                    sw_signer.get_master_blinding_key().expect("must not fail");

                let xpub_root = sw_signer.get_xpub(&[]).expect("must not fail");

                let master_xpub_fingerprint = Some(xpub_root.fingerprint());

                let xpub_nested = sw_signer
                    .get_xpub(&path_from_u32(&env.nd().account_path_sh_wpkh))
                    .expect("must not fail");

                let xpub_native = sw_signer
                    .get_xpub(&path_from_u32(&env.nd().account_path_wpkh))
                    .expect("must not fail");

                vec![
                    AccountData {
                        account_num: 0,
                        xpub: xpub_nested,
                        master_xpub_fingerprint,
                        master_blinding_key: Some(MasterBlindingKey(master_blinding_key)),
                    },
                    AccountData {
                        account_num: 1,
                        xpub: xpub_native,
                        master_xpub_fingerprint,
                        master_blinding_key: Some(MasterBlindingKey(master_blinding_key)),
                    },
                ]
            }
            gdk_ses::WalletInfo::Jade(_hw_data, watch_only) => {
                let master_xpub_fingerprint = Some(watch_only.master_xpub_fingerprint);
                let master_blinding_key = Some(MasterBlindingKey(
                    watch_only.master_blinding_key.into_inner(),
                ));

                vec![
                    AccountData {
                        account_num: 0,
                        xpub: watch_only.nested_xpub,
                        master_xpub_fingerprint,
                        master_blinding_key: master_blinding_key.clone(),
                    },
                    AccountData {
                        account_num: 1,
                        xpub: watch_only.native_xpub,
                        master_xpub_fingerprint,
                        master_blinding_key,
                    },
                ]
            }
        };

        // TODO: Review and test that the methods won't fail

        // FIXME: This can crash if wrong electrum server or proxy is used.
        // Make sure only valid values are stored.
        let _login_data = self
            .session
            .login_wo(WatchOnlyCredentials::Parsed(accounts))
            .expect("must not fail");
    }

    fn connect(&mut self) {
        let net_params = json!({"proxy": self.login_info.proxy.clone()});

        // FIXME: Should we return error instead?
        self.session.connect(&net_params).expect("should not fail");
    }

    fn get_transactions_impl(
        &self,
        opts: GetTransactionsOpt,
    ) -> Result<TransactionList, gdk_electrum::error::Error> {
        let tip_height = self.session.store()?.lock()?.cache.tip_height();

        let pending_only = match opts {
            GetTransactionsOpt::PendingOnly => true,
            GetTransactionsOpt::All => false,
        };

        let mut combined = HashMap::<BETxid, models::Transaction>::new();

        for (_wallet_type, subaccount) in self.subaccounts.iter().copied() {
            let txs = self
                .session
                .get_transactions(&gdk_common::model::GetTransactionsOpt {
                    subaccount,
                    pending_only,
                })?;

            for tx in txs.0 {
                let entry = combined
                    .entry(tx.txhash)
                    .or_insert_with(|| models::Transaction {
                        txid: *tx.txhash.ref_elements().expect("must be set"),
                        network_fee: tx.fee,
                        vsize: tx.transaction_vsize,
                        created_at: TimestampMs::from_millis(tx.created_at_ts / 1000),
                        block_height: tx.block_height,
                        inputs: tx
                            .inputs
                            .iter()
                            .map(|_input| models::InputOutput { unblinded: None })
                            .collect(),
                        outputs: tx
                            .outputs
                            .iter()
                            .map(|_output| models::InputOutput { unblinded: None })
                            .collect(),
                    });

                assert_eq!(tx.inputs.len(), entry.inputs.len());
                for (tx_input, entry_input) in tx.inputs.iter().zip(entry.inputs.iter_mut()) {
                    if tx_input.is_relevant {
                        if let (Some(asset), Some(asset_bf), Some(value_bf)) = (
                            tx_input.asset_id,
                            tx_input.asset_blinder,
                            tx_input.amount_blinder,
                        ) {
                            entry_input.unblinded = Some(TxOutSecrets {
                                asset,
                                asset_bf,
                                value: tx_input.satoshi,
                                value_bf,
                            });
                        }
                    }
                }

                assert_eq!(tx.outputs.len(), entry.outputs.len());
                for (tx_output, entry_output) in tx.outputs.iter().zip(entry.outputs.iter_mut()) {
                    if tx_output.is_relevant {
                        if let (Some(asset), Some(asset_bf), Some(value_bf)) = (
                            tx_output.asset_id,
                            tx_output.asset_blinder,
                            tx_output.amount_blinder,
                        ) {
                            entry_output.unblinded = Some(TxOutSecrets {
                                asset,
                                asset_bf,
                                value: tx_output.satoshi,
                                value_bf,
                            });
                        }
                    }
                }
            }
        }

        let txs = combined.into_values().collect();

        Ok(TransactionList {
            tip_height,
            list: txs,
        })
    }
}

impl crate::gdk_ses::GdkSes for GdkSesRust {
    fn login_info(&self) -> &gdk_ses::LoginInfo {
        &self.login_info
    }

    fn get_transactions(&self, opts: GetTransactionsOpt) -> Result<TransactionList, anyhow::Error> {
        self.get_transactions_impl(opts).map_err(Into::into)
    }

    fn get_address(&self, is_internal: bool) -> Result<models::AddressInfo, anyhow::Error> {
        let address_info = self.session.get_receive_address(&GetAddressOpt {
            subaccount: self.default_subaccount,
            address_type: None,
            is_internal: Some(is_internal),
            ignore_gap_limit: None,
        })?;

        let address_type = match address_info.address_type {
            gdk_common::scripts::ScriptType::P2shP2wpkh => AddressType::P2shP2wpkh,
            gdk_common::scripts::ScriptType::P2wpkh => AddressType::P2wpkh,
            gdk_common::scripts::ScriptType::P2pkh | gdk_common::scripts::ScriptType::P2tr => {
                bail!(
                    "unsupported address_type value: {}",
                    address_info.address_type
                )
            }
        };

        Ok(models::AddressInfo {
            address: address_info.address.parse().expect("must not fail"),
            address_type,
            pointer: address_info.pointer,
            user_path: address_info
                .user_path
                .iter()
                .copied()
                .map(u32::from)
                .collect(),
            is_internal: Some(address_info.is_internal),
            public_key: Some(address_info.public_key),
            prevout_script: None,
            service_xpub: None,
        })
    }

    fn broadcast_tx(&self, tx: &str) -> Result<(), anyhow::Error> {
        self.session.broadcast_transaction(tx)?;
        Ok(())
    }

    fn get_utxos(&self) -> Result<models::UtxoList, anyhow::Error> {
        let mut res = models::UtxoList::new();

        for (wallet_type, subaccount) in self.subaccounts.iter().copied() {
            let utxos = self.session.get_unspent_outputs(&GetUnspentOpt {
                subaccount,
                num_confs: None,
                confidential_utxos_only: None,
                all_coins: None,
            })?;

            for (asset_id, utxos) in utxos.0.into_iter() {
                let asset_id = asset_id.expect("must be set");
                let combined = res.entry(asset_id).or_default();

                for utxo in utxos {
                    let txhash = *utxo.txhash.ref_elements().expect("must not fail");
                    let prevout_script = utxo.script_code.into_elements();
                    let asset_commitment = utxo.asset_commitment.expect("must be set");
                    let value_commitment = utxo.value_commitment.expect("must be set");
                    let amount_blinder = utxo.amount_blinder.expect("must be set");
                    let asset_blinder = utxo.asset_blinder.expect("must be set");
                    let public_key = utxo.public_key;
                    let user_path = utxo.user_path.iter().copied().map(u32::from).collect();
                    let script_pub_key = utxo.scriptpubkey.into_elements();

                    let utxo = models::Utxo {
                        wallet_type,
                        block_height: utxo.block_height,
                        txhash,
                        vout: utxo.pt_idx,
                        pointer: utxo.pointer,
                        is_internal: utxo.is_internal,
                        is_blinded: utxo.is_blinded.unwrap_or_default(),
                        prevout_script,
                        asset_id,
                        satoshi: utxo.satoshi,
                        asset_commitment,
                        value_commitment,
                        amountblinder: amount_blinder,
                        assetblinder: asset_blinder,
                        script_pub_key,
                        public_key: Some(public_key),
                        user_path: Some(user_path),
                    };

                    combined.push(utxo);
                }
            }
        }

        Ok(res)
    }

    fn get_previous_addresses(&self) -> Result<AddressList, anyhow::Error> {
        let mut list = Vec::new();
        for (wallet_type, subaccount) in self.subaccounts.iter().copied() {
            for is_internal in [false, true] {
                let resp = self
                    .session
                    .get_previous_addresses(&GetPreviousAddressesOpt {
                        subaccount,
                        last_pointer: None,
                        is_internal,
                        count: u32::MAX,
                    })?;

                for addr in resp.list {
                    let address =
                        elements::Address::from_str(&addr.address).expect("must not fail");

                    let user_path = addr
                        .user_path
                        .into_iter()
                        .map(u32::from)
                        .collect::<Vec<_>>();

                    list.push(models::AddressInfo {
                        address,
                        address_type: wallet_type.into(),
                        pointer: addr.pointer,
                        user_path,
                        is_internal: Some(addr.is_internal),
                        public_key: Some(addr.public_key),
                        prevout_script: None,
                        service_xpub: None,
                    });
                }
            }
        }
        Ok(AddressList { list })
    }
}

fn get_default_network(env: Env) -> gdk_common::NetworkParameters {
    match env {
        Env::Prod | Env::LocalLiquid => gdk_common::NetworkParameters {
            name: "Liquid (Electrum)".to_string(),
            network: "electrum-liquid".to_string(),
            development: false,
            liquid: true,
            mainnet: true,
            tx_explorer_url: "https://blockstream.info/liquid/tx/".to_string(),
            address_explorer_url: "https://blockstream.info/liquid/address/".to_string(),
            electrum_tls: Some(true),
            electrum_url: Some("elements-mainnet.blockstream.info:50002".to_string()),
            electrum_onion_url: Some(
                "liqm3aeuthw4eacn2gssv4qg4zfhmy24rmtghp3vujintldu7jaxqyid.onion:50001".to_string(),
            ),
            validate_domain: Some(true),
            policy_asset: Some(
                "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d".to_string(),
            ),
            sync_interval: None,
            spv_enabled: Some(false),
            asset_registry_url: Some("https://assets.blockstream.info".to_string()),
            asset_registry_onion_url: Some(
                "http://lhquhzzpzg5tyymcqep24fynpzzqqg3m3rlh7ascnw5cpqsro35bfxyd.onion".to_string(),
            ),
            pin_server_url: "https://jadepin.blockstream.com".to_string(),
            pin_server_onion_url:
                "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion".to_string(),
            pin_server_public_key:
                "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547".to_string(),
            spv_multi: Some(false),
            spv_servers: Some(vec![]),
            proxy: None,
            use_tor: None,
            max_reorg_blocks: Some(2),
            state_dir: String::new(),
            gap_limit: None,
        },

        Env::Testnet | Env::LocalTestnet => gdk_common::NetworkParameters {
            name: "Testnet Liquid (Electrum)".to_string(),
            network: "electrum-testnet-liquid".to_string(),
            development: false,
            liquid: true,
            mainnet: false,
            tx_explorer_url: "https://blockstream.info/liquidtestnet/tx/".to_string(),
            address_explorer_url: "https://blockstream.info/liquidtestnet/address/".to_string(),
            electrum_tls: None,
            electrum_url: Some("electrs.sideswap.io:12002".to_string()),
            electrum_onion_url: Some(
                "liqtzdv3soz7onazmbqzvzbrcgz73bdqlcuhbqlkucjj7i6irbdmoryd.onion:50001".to_string(),
            ),
            validate_domain: Some(true),
            policy_asset: Some(
                "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49".to_string(),
            ),
            sync_interval: None,
            spv_enabled: Some(false),
            asset_registry_url: Some("https://assets-testnet.blockstream.info/".to_string()),
            asset_registry_onion_url: Some(
                "http://lhquhzzpzg5tyymcqep24fynpzzqqg3m3rlh7ascnw5cpqsro35bfxyd.onion/testnet/"
                    .to_string(),
            ),
            pin_server_url: "https://jadepin.blockstream.com".to_string(),
            pin_server_onion_url:
                "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion".to_string(),
            pin_server_public_key:
                "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547".to_string(),
            spv_multi: Some(false),
            spv_servers: Some(vec![]),
            proxy: None,
            use_tor: None,
            max_reorg_blocks: Some(2),
            state_dir: String::new(),
            gap_limit: None,
        },

        Env::LocalRegtest => gdk_common::NetworkParameters {
            name: "Localtest Liquid (Electrum)".to_string(),
            network: "electrum-localtest-liquid".to_string(),
            development: true,
            liquid: true,
            mainnet: false,
            tx_explorer_url: "http://127.0.0.1:8080/tx/".to_string(),
            address_explorer_url: "http://127.0.0.1:8080/address/".to_string(),
            electrum_tls: Some(false),
            electrum_url: Some("127.0.0.1:19002".to_string()),
            electrum_onion_url: None,
            validate_domain: None,
            policy_asset: Some(
                "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225".to_string(),
            ),
            sync_interval: None,
            spv_enabled: Some(false),
            asset_registry_url: Some("".to_string()),
            asset_registry_onion_url: None,
            pin_server_url: "https://jadepin.blockstream.com".to_string(),
            pin_server_onion_url:
                "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion".to_string(),
            pin_server_public_key:
                "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547".to_string(),
            spv_multi: Some(false),
            spv_servers: Some(vec![]),
            proxy: None,
            use_tor: None,
            max_reorg_blocks: Some(2),
            state_dir: String::new(),
            gap_limit: None,
        },
    }
}

fn get_network_parameters(
    env: Env,
    electrum_server: &ElectrumServer,
    state_dir: &Path,
    proxy: &Option<String>,
) -> gdk_common::NetworkParameters {
    let network = env.d().network;

    let (host, port, use_tls) = match (electrum_server, network) {
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

        (_, Network::Regtest) => unimplemented!(),
    };

    let mut network = get_default_network(env);

    network.state_dir = state_dir.to_str().expect("must be valid").to_owned();

    network.electrum_url = Some(format!("{host}:{port}"));
    network.electrum_tls = Some(use_tls);
    network.electrum_onion_url = None;

    network.proxy = proxy.clone();

    network
}

pub fn start_processing(
    login_info: gdk_ses::LoginInfo,
    notif_callback: NotifCallback,
) -> Arc<dyn crate::gdk_ses::GdkSes> {
    let params = get_network_parameters(
        login_info.env,
        &login_info.electrum_server,
        &login_info.cache_dir,
        &login_info.proxy,
    );

    let mut session = gdk_electrum::ElectrumSession::new(params).expect("must not fail");

    let subaccounts = vec![(WalletType::Nested, 0), (WalletType::Native, 1)];

    // Native SegWit
    let default_subaccount = 1;

    let subaccounts_len = subaccounts.len();

    let account = login_info.account;
    session.notify.callback = Some(Arc::new(move |notif| {
        log::debug!(
            "new rust wallet notification: {}",
            serde_json::to_string(&notif).expect("must not fail")
        );

        match notif.event {
            gdk_common::notification::Kind::Network => {}
            gdk_common::notification::Kind::Transaction => {
                let transaction = notif.transaction.expect("must be set");
                let txid = elements::Txid::from_raw_hash(*transaction.txid.as_raw_hash());
                notif_callback(account, WalletNotif::Transaction(txid));
            }
            gdk_common::notification::Kind::Block => {
                notif_callback(account, WalletNotif::Block);
            }
            gdk_common::notification::Kind::Subaccount => {
                let subaccount = notif.subaccount.expect("must be set");
                match subaccount.event_type {
                    gdk_common::notification::SubaccountEventType::New => {}
                    gdk_common::notification::SubaccountEventType::Synced => {
                        if subaccount.accounts.len() == subaccounts_len {
                            notif_callback(account, WalletNotif::AccountSynced);
                        }
                    }
                }
            }
            gdk_common::notification::Kind::Settings => {}
        }
    }));

    let mut ses = GdkSesRust {
        login_info,
        session,
        subaccounts,
        default_subaccount,
    };

    ses.connect();

    ses.login();

    Arc::new(ses)
}
