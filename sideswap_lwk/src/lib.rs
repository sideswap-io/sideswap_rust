use std::{
    collections::BTreeSet,
    path::PathBuf,
    str::FromStr,
    sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender},
    time::{Duration, Instant},
};

use elements::{
    bitcoin::bip32,
    confidential::{AssetBlindingFactor, ValueBlindingFactor},
    Txid,
};
use lwk_common::{singlesig_desc, Signer};
use lwk_wollet::{
    blocking::BlockchainBackend, elements_miniscript, secp256k1::SECP256K1, ElementsNetwork,
    WolletDescriptor,
};
use sideswap_common::{
    channel_helpers::{UncheckedOneshotSender, UncheckedUnboundedSender},
    network::Network,
    recipient::Recipient,
    retry_delay::RetryDelay,
};
use sideswap_dealer::{
    market::{SendAssetReq, SendAssetResp},
    utxo_data::{self, UtxoData, UtxoWithKey},
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

pub use lwk_wollet::{WalletTx, WalletTxOut};

#[derive(Debug, Copy, Clone)]
pub struct ScriptVariant(lwk_common::Singlesig);

impl<'de> serde::Deserialize<'de> for ScriptVariant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let value =
            lwk_common::Singlesig::from_str(&value).map_err(|err| serde::de::Error::custom(err))?;
        Ok(ScriptVariant(value))
    }
}

pub struct Params {
    pub network: Network,
    pub work_dir: PathBuf,
    pub mnemonic: bip39::Mnemonic,
    pub script_variant: ScriptVariant,
}

pub struct Wallet {
    network: Network,
    script_variant: ScriptVariant,
    descriptor: lwk_wollet::WolletDescriptor,
    master_key: bip32::Xpriv,
    wallet: lwk_wollet::Wollet,
    signer: lwk_signer::SwSigner,
}

pub struct NewAddrReq {
    pub change: bool,
    pub index: Option<u32>,
}

pub struct NewAddrResp {
    pub change: bool,
    pub index: u32,
    pub address: elements::Address,
}

pub struct GetTxsReq {
    pub txids: Option<BTreeSet<elements::Txid>>,
}

pub struct GetTxsResp {
    pub txs: Vec<WalletTx>,
}

pub struct GetUtxosReq {}

pub struct GetUtxosResp {
    pub utxos: Vec<WalletTxOut>,
}

pub struct CreateTxReq {
    pub recipients: Vec<Recipient>,
}

pub struct CreateTxResp {
    pub tx: elements::Transaction,
}

pub enum Command {
    NewAdddress {
        req: NewAddrReq,
        res_sender: UncheckedOneshotSender<Result<NewAddrResp, Error>>,
    },
    CreateTx {
        req: CreateTxReq,
        res_sender: UncheckedOneshotSender<Result<CreateTxResp, Error>>,
    },
    BroadcastTx {
        tx: String,
        res_sender: Option<UncheckedOneshotSender<Result<elements::Txid, Error>>>,
    },
    SendAsset {
        req: SendAssetReq,
        res_sender: UncheckedOneshotSender<Result<SendAssetResp, anyhow::Error>>,
    },
    GetTxs {
        req: GetTxsReq,
        res_sender: UncheckedOneshotSender<Result<GetTxsResp, Error>>,
    },
    GetUtxos {
        req: GetUtxosReq,
        res_sender: UncheckedOneshotSender<Result<GetUtxosResp, Error>>,
    },
}

pub enum Event {
    Utxos {
        utxo_data: UtxoData,
    },

    /// Reported if any changes were found during scanning
    Updated,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArg(&'static str),
    #[error("wollet error: {0}")]
    WolletError(#[from] lwk_wollet::Error),
    #[error("signer error: {0}")]
    SignerError(#[from] lwk_signer::SignError),
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("decode error: {0}")]
    Decode(#[from] elements::encode::Error),
}

fn create_tx(
    req: CreateTxReq,
    wallet: &lwk_wollet::Wollet,
    signer: &lwk_signer::SwSigner,
) -> Result<CreateTxResp, Error> {
    let mut tx_builder = wallet.tx_builder().enable_ct_discount();
    for recipient in req.recipients {
        tx_builder = tx_builder.add_unvalidated_recipient(&lwk_wollet::UnvalidatedRecipient {
            satoshi: recipient.amount,
            address: recipient.address.to_string(),
            asset: recipient.asset_id.to_string(),
        })?;
    }
    let mut pset = tx_builder.finish()?;
    signer.sign(&mut pset)?;
    let tx = wallet.finalize(&mut pset)?;
    Ok(CreateTxResp { tx })
}

fn broadcast_tx(electrum_client: &lwk_wollet::ElectrumClient, tx: &str) -> Result<Txid, Error> {
    let tx = hex::decode(&tx)?;
    let tx = elements::encode::deserialize::<elements::Transaction>(&tx)?;
    let txid = electrum_client.broadcast(&tx)?;
    Ok(txid)
}

fn send_asset(
    req: SendAssetReq,
    wallet: &lwk_wollet::Wollet,
    signer: &lwk_signer::SwSigner,
    electrum_client: &lwk_wollet::ElectrumClient,
) -> Result<SendAssetResp, Error> {
    let mut pset = wallet
        .tx_builder()
        .enable_ct_discount()
        .add_recipient(&req.address, req.amount, req.asset_id)?
        .finish()?;
    signer.sign(&mut pset)?;
    let tx = wallet.finalize(&mut pset)?;
    let txid = electrum_client.broadcast(&tx)?;
    Ok(SendAssetResp { txid })
}

fn get_txs(
    GetTxsReq { txids }: GetTxsReq,
    wallet: &lwk_wollet::Wollet,
) -> Result<GetTxsResp, Error> {
    let txs = match txids {
        Some(txids) => {
            let mut txs = Vec::new();
            for txid in txids.iter() {
                let tx = wallet.transaction(txid)?;
                if let Some(tx) = tx {
                    txs.push(tx);
                }
            }
            txs
        }

        None => wallet.transactions()?,
    };

    Ok(GetTxsResp { txs })
}

fn get_utxos(
    GetUtxosReq {}: GetUtxosReq,
    wallet: &lwk_wollet::Wollet,
) -> Result<GetUtxosResp, Error> {
    let utxos = wallet.utxos()?;
    Ok(GetUtxosResp { utxos })
}

fn run(
    Wallet {
        network,
        script_variant,
        descriptor,
        master_key,
        mut wallet,
        signer,
    }: Wallet,
    command_receiver: Receiver<Command>,
    event_sender: UncheckedUnboundedSender<Event>,
) {
    let electrum_url = match network {
        Network::Liquid => "electrs.sideswap.io:12001",
        Network::LiquidTestnet => "electrs.sideswap.io:12002",
        Network::Regtest => todo!(),
    };
    let electrum_url =
        lwk_wollet::ElectrumUrl::new(electrum_url, true, true).expect("must not fail");

    let mut retry = RetryDelay::default();
    let mut error_count = 0;
    let mut electrum_client = loop {
        let res = lwk_wollet::ElectrumClient::new(&electrum_url);
        match res {
            Ok(client) => break client,
            Err(err) => {
                log::error!("electrum connection failed: {err}");
                error_count += 1;
                if error_count > 20 {
                    panic!("connection failed");
                }
                std::thread::sleep(retry.next_delay());
            }
        }
    };

    let mut utxo_data = UtxoData::new(utxo_data::Params {
        confifential_only: true,
    });

    'outer: loop {
        let res = electrum_client.full_scan(&wallet);

        let update = match res {
            Ok(update) => update,
            Err(err) => {
                log::error!("full_scan failed: {err}");
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        if let Some(update) = update {
            wallet.apply_update(update).expect("must not fail");

            let utxos = wallet.utxos().expect("must not fail");

            let utxos_with_key = utxos
                .into_iter()
                .filter(|utxo| {
                    utxo.unblinded.asset_bf != AssetBlindingFactor::zero()
                        && utxo.unblinded.value_bf != ValueBlindingFactor::zero()
                })
                .map(|utxo| {
                    let utxo_desc = descriptor
                        .definite_descriptor(utxo.ext_int, utxo.wildcard_index)
                        .expect("must not fail");

                    let mut utxo_details = None;

                    use elements_miniscript::ForEachKey;
                    utxo_desc.for_each_key(|d| {
                        let full_path = d.full_derivation_path().expect("must be set");

                        let priv_key = master_key
                            .derive_priv(SECP256K1, &full_path)
                            .expect("must not fail")
                            .to_priv();

                        let redeem_script = match script_variant.0 {
                            lwk_common::Singlesig::Wpkh => None,
                            lwk_common::Singlesig::ShWpkh => {
                                let pub_key = priv_key.public_key(&SECP256K1);
                                Some(sideswap_common::pset::p2shwpkh_redeem_script(&pub_key))
                            }
                        };

                        assert!(utxo_details.is_none());
                        utxo_details = Some((redeem_script, priv_key));

                        true
                    });

                    let (redeem_script, priv_key) = utxo_details.expect("must be set");

                    UtxoWithKey {
                        utxo: sideswap_api::Utxo {
                            txid: utxo.outpoint.txid,
                            vout: utxo.outpoint.vout,
                            asset: utxo.unblinded.asset,
                            asset_bf: utxo.unblinded.asset_bf,
                            value: utxo.unblinded.value,
                            value_bf: utxo.unblinded.value_bf,
                            redeem_script,
                        },
                        priv_key,
                    }
                })
                .collect::<Vec<_>>();

            utxo_data.reset(utxos_with_key);

            event_sender.send(Event::Utxos {
                utxo_data: utxo_data.clone(),
            });

            event_sender.send(Event::Updated {});
        }

        let deadline = Instant::now() + Duration::from_secs(1);

        loop {
            let timeout = deadline.saturating_duration_since(Instant::now());
            let res = command_receiver.recv_timeout(timeout);
            match res {
                Ok(command) => match command {
                    Command::NewAdddress { req, res_sender } => {
                        let res = if req.change {
                            wallet.change(req.index)
                        } else {
                            wallet.address(req.index)
                        };

                        let res = res
                            .map(|addr| NewAddrResp {
                                index: addr.index(),
                                address: addr.address().clone(),
                                change: req.change,
                            })
                            .map_err(Error::WolletError);

                        res_sender.send(res);
                    }

                    Command::CreateTx { req, res_sender } => {
                        let res = create_tx(req, &wallet, &signer);
                        res_sender.send(res);
                    }

                    Command::BroadcastTx { tx, res_sender } => {
                        let res = broadcast_tx(&electrum_client, &tx);
                        if let Some(res_sender) = res_sender {
                            res_sender.send(res);
                        } else {
                            match res {
                                Ok(txid) => log::debug!("tx broadcast succeed: {txid}"),
                                Err(err) => log::error!("tx broadcast failed: {err}"),
                            }
                        }
                    }

                    Command::SendAsset { req, res_sender } => {
                        let res =
                            send_asset(req, &wallet, &signer, &electrum_client).map_err(Into::into);
                        res_sender.send(res);
                    }

                    Command::GetTxs { req, res_sender } => {
                        let res = get_txs(req, &wallet);
                        res_sender.send(res);
                    }

                    Command::GetUtxos { req, res_sender } => {
                        let res = get_utxos(req, &wallet);
                        res_sender.send(res);
                    }
                },

                Err(err) => match err {
                    RecvTimeoutError::Timeout => {
                        break;
                    }
                    RecvTimeoutError::Disconnected => {
                        log::debug!("stop wallet");
                        break 'outer;
                    }
                },
            }
        }
    }
}

impl Wallet {
    pub fn new(params: Params) -> Wallet {
        let Params {
            network,
            work_dir: _,
            mnemonic,
            script_variant,
        } = params;

        let is_mainnet = match network {
            Network::Liquid => true,
            Network::LiquidTestnet | Network::Regtest => false,
        };

        let seed = mnemonic.to_seed("");
        let bitcoin_network = network.d().bitcoin_network;
        let master_key = bip32::Xpriv::new_master(bitcoin_network, &seed).unwrap();

        let signer =
            lwk_signer::SwSigner::new(&mnemonic.to_string(), is_mainnet).expect("must not fail");

        let descriptor = singlesig_desc(
            &signer,
            script_variant.0,
            lwk_common::DescriptorBlindingKey::Slip77,
            is_mainnet,
        )
        .expect("must not fail");

        let descriptor = descriptor
            .parse::<WolletDescriptor>()
            .expect("must not fail");

        let lwk_network = match network {
            Network::Liquid => ElementsNetwork::Liquid,
            Network::LiquidTestnet => ElementsNetwork::LiquidTestnet,
            Network::Regtest => todo!(),
        };

        let wallet = lwk_wollet::Wollet::without_persist(lwk_network, descriptor.clone())
            .expect("must not fail");
        // let mut wallet =
        //     lwk_wollet::Wollet::with_fs_persist(lwk_network, descriptor.clone(), &work_dir)
        //         .expect("must not fail");

        Wallet {
            network,
            script_variant,
            descriptor,
            master_key,
            wallet,
            signer,
        }
    }

    pub fn descriptor(&self) -> &lwk_wollet::WolletDescriptor {
        &self.descriptor
    }

    pub fn wallet_id(&self) -> String {
        use elements::bitcoin::hashes::Hash;
        sideswap_common::wallet_id::WalletIdHash::hash(self.descriptor().to_string().as_bytes())
            .to_string()
    }

    pub fn start(self) -> (Sender<Command>, UnboundedReceiver<Event>) {
        let (command_sender, command_receiver) = channel::<Command>();
        let (event_sender, event_receiver) = unbounded_channel::<Event>();

        std::thread::spawn(move || run(self, command_receiver, event_sender.into()));

        (command_sender, event_receiver)
    }
}
