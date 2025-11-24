use crate::ffi::proto;
use crate::models;
use crate::worker::TX_CONF_COUNT_LIQUID;
use anyhow::{bail, ensure};
use bitcoin::bip32::{ChildNumber, Xpub};
use elements::{AssetId, EcdsaSighashType};
use elements::{hashes::Hash, pset::PartiallySignedTransaction, secp256k1_zkp::global::SECP256K1};
use elements_miniscript::slip77::MasterBlindingKey;
use secp256k1::SecretKey;
use sideswap_api::{Asset, Hash32};
use sideswap_common::green_backend::GREEN_DUMMY_SIG;
use sideswap_common::utxo_select::WalletType;
use sideswap_jade::{
    jade_mng::{self, JadeStatus},
    models::JadeNetwork,
};
use sideswap_types::b64;
use sideswap_types::env::Env;
use sideswap_types::network::Network;
use std::collections::{BTreeMap, BTreeSet};

pub fn encode_pset(pset: &PartiallySignedTransaction) -> String {
    let pset = elements::encode::serialize(pset);
    b64::encode(&pset)
}

pub fn decode_pset(pset: &str) -> Result<PartiallySignedTransaction, anyhow::Error> {
    let pset = b64::decode(pset)?;
    let pset = elements::encode::deserialize(&pset)?;
    Ok(pset)
}

pub fn unlock_hw(env: Env, jade: &jade_mng::ManagedJade) -> Result<(), anyhow::Error> {
    // (status_callback)(gdk_ses::JadeStatus::ReadStatus);
    let res = jade.read_status();
    // (status_callback)(gdk_ses::JadeStatus::Idle);
    let status = res?;
    log::debug!("jade state: {:?}", status.jade_state);

    match status.jade_state {
        sideswap_jade::models::State::Ready => {
            log::debug!("jade already unlocked");
        }
        sideswap_jade::models::State::Locked => {
            let network = get_jade_network(env);
            let _status = jade.start_status(JadeStatus::AuthUser);
            let resp = jade.auth_user(network)?;
            log::debug!("jade unlock result: {}", resp);
            ensure!(resp, "unlock failed");
        }
        sideswap_jade::models::State::Uninit => {
            bail!("please initialize Jade first")
        }
        sideswap_jade::models::State::Unsaved | sideswap_jade::models::State::Temp => {
            bail!("unexpected jade state: {:?}", status.jade_state);
        }
    }

    Ok(())
}

// Do it manually, because otherwise numbers will be converted as Map([(Text("$serde_json::private::Number"), Text("8"))]))
fn convert_value(value: &serde_json::Value) -> ciborium::Value {
    match value {
        serde_json::Value::Null => ciborium::Value::Null,
        serde_json::Value::Bool(val) => ciborium::Value::Bool(*val),
        serde_json::Value::Number(val) if val.is_i64() => {
            ciborium::Value::Integer(val.as_i64().expect("must be set").into())
        }
        serde_json::Value::Number(val) if val.is_f64() => {
            ciborium::Value::Float(val.as_f64().expect("must be set"))
        }
        serde_json::Value::Number(val) => ciborium::Value::Text(val.to_string()),
        serde_json::Value::String(val) => ciborium::Value::Text(val.clone()),
        serde_json::Value::Array(arr) => {
            ciborium::Value::Array(arr.iter().map(convert_value).collect())
        }
        serde_json::Value::Object(map) => ciborium::Value::Map(
            map.iter()
                .map(|(key, value)| (ciborium::Value::Text(key.clone()), convert_value(value)))
                .collect(),
        ),
    }
}

pub fn encode_jade_tx(mut tx: elements::Transaction) -> serde_bytes::ByteBuf {
    // Remove unnecessary data to ensure that the request fits into DIY Jade
    for output in tx.output.iter_mut() {
        output.witness.rangeproof = None;
    }
    serde_bytes::ByteBuf::from(elements::encode::serialize(&tx))
}

pub fn get_jade_asset_info(
    all_assets: &BTreeMap<AssetId, Asset>,
    required: BTreeSet<AssetId>,
) -> Vec<sideswap_jade::models::AssetInfo> {
    required
        .into_iter()
        .filter_map(|asset_id| {
            let asset = all_assets.get(&asset_id)?;
            let issuance_prevout = asset.issuance_prevout.as_ref()?;
            let contract = asset.contract.as_ref()?;
            let contract = convert_value(contract);
            if contract.is_null() {
                return None;
            }
            Some(sideswap_jade::models::AssetInfo {
                asset_id: asset_id.to_string(),
                contract,
                issuance_prevout: sideswap_jade::models::Prevout {
                    txid: issuance_prevout.txid.to_string(),
                    vout: issuance_prevout.vout,
                },
            })
        })
        .collect()
}

pub fn get_jade_network(env: Env) -> JadeNetwork {
    match env.d().network {
        Network::Liquid => JadeNetwork::Liquid,
        Network::LiquidTestnet => JadeNetwork::TestnetLiquid,
        Network::Regtest => unimplemented!(),
    }
}

pub fn get_redeem_script(utxo: &models::Utxo) -> Option<elements::Script> {
    match utxo.wallet_type {
        WalletType::Native => None,
        WalletType::Nested => Some(sideswap_common::pset::p2shwpkh_redeem_script(
            utxo.public_key.as_ref().expect("must be set"),
        )),
        WalletType::AMP => Some(
            elements::script::Builder::new()
                .push_int(0)
                .push_slice(&elements::WScriptHash::hash(utxo.prevout_script.as_bytes())[..])
                .into_script(),
        ),
    }
}

pub fn get_script_sig(utxo: &models::Utxo) -> Option<elements::Script> {
    get_redeem_script(utxo).map(|redeem_script| {
        elements::script::Builder::new()
            .push_slice(redeem_script.as_bytes())
            .into_script()
    })
}

pub fn get_witness(
    sighash_cache: &mut elements::sighash::SighashCache<&elements::Transaction>,
    utxo: &models::Utxo,
    input_index: usize,
    sighash_type: EcdsaSighashType,
    priv_key: &SecretKey,
    bytes_to_grind: usize,
) -> Vec<Vec<u8>> {
    let value = utxo.value_commitment;
    let sighash =
        sighash_cache.segwitv0_sighash(input_index, &utxo.prevout_script, value, sighash_type);
    let message =
        elements::secp256k1_zkp::Message::from_digest_slice(&sighash[..]).expect("must not fail");

    let signature = SECP256K1.sign_ecdsa_grind_r(&message, priv_key, bytes_to_grind);
    let signature = elements_miniscript::elementssig_to_rawsig(&(signature, sighash_type));

    match utxo.wallet_type {
        WalletType::Nested | WalletType::Native => {
            let pub_key = priv_key.public_key(SECP256K1);
            vec![signature, pub_key.serialize().to_vec()]
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
}

pub fn redact_str(v: &mut String) {
    *v = format!("<{} bytes>", v.len());
}

pub fn redact_to_msg(mut msg: proto::to::Msg) -> proto::to::Msg {
    match &mut msg {
        proto::to::Msg::Login(v) => {
            if let Some(proto::to::login::Wallet::Mnemonic(mnemonic)) = v.wallet.as_mut() {
                redact_str(mnemonic);
            }
        }
        proto::to::Msg::EncryptPin(v) => {
            redact_str(&mut v.pin);
            redact_str(&mut v.mnemonic);
        }
        proto::to::Msg::DecryptPin(v) => {
            redact_str(&mut v.pin);
            redact_str(&mut v.encrypted_data);
        }
        _ => {}
    }
    msg
}

pub fn redact_from_msg(mut msg: proto::from::Msg) -> proto::from::Msg {
    match &mut msg {
        proto::from::Msg::DecryptPin(v) => {
            if let Some(proto::from::decrypt_pin::Result::Mnemonic(v)) = v.result.as_mut() {
                redact_str(v);
            }
        }
        proto::from::Msg::EncryptPin(v) => {
            if let Some(proto::from::encrypt_pin::Result::Data(v)) = v.result.as_mut() {
                redact_str(&mut v.encrypted_data);
            }
        }
        proto::from::Msg::NewAsset(v) => {
            redact_str(&mut v.icon);
        }
        _ => {}
    }
    msg
}

pub fn convert_chart_point(point: sideswap_api::ChartPoint) -> proto::ChartPoint {
    proto::ChartPoint {
        time: point.time,
        open: point.open,
        close: point.close,
        high: point.high,
        low: point.low,
        volume: point.volume,
    }
}

pub struct TxSize {
    pub input_count: i32,
    pub output_count: i32,
    pub size: i64,
    pub vsize: i64,
    pub discount_vsize: i64,
    pub network_fee: i64,
    pub fee_per_byte: f64,
}

pub fn get_tx_size(
    mut tx: elements::Transaction,
    policy_asset: &AssetId,
    utxos: &[models::Utxo],
) -> TxSize {
    let network_fee = tx.fee_in(*policy_asset);

    let tx_copy = tx.clone();
    let mut sighash_cache = elements::sighash::SighashCache::new(&tx_copy);

    let bytes_to_grind = 0; // Upper bound (because Jade can't grind)
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("must not fail");

    for (input_index, input) in tx.input.iter_mut().enumerate() {
        let utxo = utxos.iter().find(|utxo| {
            utxo.txhash == input.previous_output.txid && utxo.vout == input.previous_output.vout
        });

        if let Some(utxo) = utxo {
            input.script_sig = get_script_sig(utxo).unwrap_or_default();

            input.witness.script_witness = get_witness(
                &mut sighash_cache,
                utxo,
                input_index,
                elements::EcdsaSighashType::All,
                &secret_key,
                bytes_to_grind,
            );
        }
    }

    TxSize {
        input_count: tx.input.len() as i32,
        output_count: tx.output.len() as i32,
        size: tx.size() as i64,
        vsize: tx.vsize() as i64,
        discount_vsize: tx.discount_vsize() as i64,
        network_fee: network_fee as i64,
        fee_per_byte: network_fee as f64 / tx.discount_vsize() as f64,
    }
}

fn peg_txitem_id(send_txid: &Hash32, send_vout: i32) -> String {
    format!("{}/{}", send_txid, send_vout)
}

pub fn get_peg_item(
    peg: &sideswap_api::PegStatus,
    tx: &sideswap_api::TxStatus,
) -> proto::TransItem {
    let peg_details = proto::Peg {
        is_peg_in: peg.peg_in,
        amount_send: tx.amount,
        amount_recv: tx.payout.unwrap_or_default(),
        addr_send: peg.addr.clone(),
        addr_recv: peg.addr_recv.clone(),
        txid_send: tx.tx_hash.to_string(),
        txid_recv: tx.payout_txid.map(|hash| hash.to_string()),
    };
    let confs = tx.detected_confs.and_then(|count| {
        tx.total_confs.map(|total| proto::Confs {
            count: count as u32,
            total: total as u32,
        })
    });
    let id = peg_txitem_id(&tx.tx_hash, tx.vout);

    proto::TransItem {
        id,
        created_at: tx.created_at,
        confs,
        item: Some(proto::trans_item::Item::Peg(peg_details)),
    }
}

pub fn derive_nested_address(
    account_xpub: &Xpub,
    network: Network,
    is_internal: bool,
    pointer: u32,
    master_blinding_key: Option<&MasterBlindingKey>,
) -> elements::Address {
    let pub_key = account_xpub
        .derive_pub(
            SECP256K1,
            &[
                ChildNumber::from_normal_idx(is_internal as u32).unwrap(),
                ChildNumber::from_normal_idx(pointer).unwrap(),
            ],
        )
        .unwrap()
        .to_pub();
    let pub_key = elements::bitcoin::PublicKey::new(pub_key.0);
    let address = elements::Address::p2shwpkh(&pub_key, None, network.d().elements_params);

    match master_blinding_key {
        Some(master_blinding_key) => {
            let blinding_pubkey =
                master_blinding_key.blinding_key(SECP256K1, &address.script_pubkey());
            address.to_confidential(blinding_pubkey)
        }
        None => address,
    }
}

pub fn derive_native_address(
    account_xpub: &Xpub,
    network: Network,
    is_internal: bool,
    pointer: u32,
    master_blinding_key: Option<&MasterBlindingKey>,
) -> elements::Address {
    let pub_key = account_xpub
        .derive_pub(
            SECP256K1,
            &[
                ChildNumber::from_normal_idx(is_internal as u32).unwrap(),
                ChildNumber::from_normal_idx(pointer).unwrap(),
            ],
        )
        .expect("must not fail")
        .to_pub();
    let pub_key = elements::bitcoin::PublicKey::new(pub_key.0);
    let address = elements::Address::p2wpkh(&pub_key, None, network.d().elements_params);

    match master_blinding_key {
        Some(master_blinding_key) => {
            let blinding_pubkey =
                master_blinding_key.blinding_key(SECP256K1, &address.script_pubkey());
            address.to_confidential(blinding_pubkey)
        }
        None => address,
    }
}

pub struct AmpAddress {
    pub pointer: u32,
    pub address: elements::Address,
    pub prevout_script: elements::Script,
}

pub fn derive_amp_address(
    amp_service_xpub: &Xpub,
    amp_user_xpub: &Xpub,
    network: Network,
    pointer: u32,
    master_blinding_key: Option<&MasterBlindingKey>,
) -> AmpAddress {
    let prevout_script =
        sideswap_amp::derive_prevout_script(amp_user_xpub, amp_service_xpub, pointer);

    let script_to_hash = elements::script::Builder::new()
        .push_int(0)
        .push_slice(&elements::WScriptHash::hash(prevout_script.as_bytes())[..])
        .into_script();

    let script_hash = elements::ScriptHash::hash(script_to_hash.as_bytes());

    let payload = elements::address::Payload::ScriptHash(script_hash);

    let address = elements::Address {
        params: network.d().elements_params,
        payload,
        blinding_pubkey: None,
    };

    match master_blinding_key {
        Some(master_blinding_key) => {
            let blinding_pubkey =
                master_blinding_key.blinding_key(SECP256K1, &address.script_pubkey());
            AmpAddress {
                pointer,
                address: address.to_confidential(blinding_pubkey),
                prevout_script,
            }
        }
        None => AmpAddress {
            pointer,
            address,
            prevout_script,
        },
    }
}

pub fn convert_to_swap_utxo(utxo: &models::Utxo) -> sideswap_api::Utxo {
    sideswap_api::Utxo {
        txid: utxo.txhash,
        vout: utxo.vout,
        asset: utxo.asset_id,
        asset_bf: utxo.assetblinder,
        value: utxo.satoshi,
        value_bf: utxo.amountblinder,
        redeem_script: get_redeem_script(utxo),
    }
}

pub fn confirmed_tx(tx_block: u32, tip_height: u32) -> bool {
    tx_block != 0
        && tip_height != 0
        && tx_block <= tip_height
        && tip_height + 1 - tx_block >= TX_CONF_COUNT_LIQUID
}

pub fn get_tx_item_confs(tx_block: u32, tip_height: u32) -> Option<proto::Confs> {
    // Because of a race, reported transaction height might be more than last block height
    let tx_block = if tx_block > tip_height { 0 } else { tx_block };
    if !confirmed_tx(tx_block, tip_height) {
        let count = if tx_block == 0 {
            0
        } else {
            tip_height + 1 - tx_block
        };
        Some(proto::Confs {
            count,
            total: TX_CONF_COUNT_LIQUID,
        })
    } else {
        None
    }
}

pub fn convert_tx(
    tx_memos: &BTreeMap<elements::Txid, String>,
    tip_height: u32,
    tx: &models::Transaction,
) -> proto::TransItem {
    let id = tx.txid.to_string();

    let confs = get_tx_item_confs(tx.block_height, tip_height);

    let mut balances = BTreeMap::<AssetId, i64>::new();
    let mut balances_all = Vec::new();

    for input in tx.inputs.iter() {
        *balances.entry(input.unblinded.asset).or_default() -= input.unblinded.value as i64;
        balances_all.push(proto::Balance {
            asset_id: input.unblinded.asset.to_string(),
            amount: -(input.unblinded.value as i64),
        });
    }

    for output in tx.outputs.iter() {
        *balances.entry(output.unblinded.asset).or_default() += output.unblinded.value as i64;
        balances_all.push(proto::Balance {
            asset_id: output.unblinded.asset.to_string(),
            amount: output.unblinded.value as i64,
        });
    }

    let balances = balances
        .iter()
        .map(|(asset_id, amount)| proto::Balance {
            asset_id: asset_id.to_string(),
            amount: *amount,
        })
        .collect();

    let tx_details = proto::Tx {
        balances,
        memo: tx_memos.get(&tx.txid).cloned().unwrap_or_default(),
        network_fee: tx.network_fee as i64,
        txid: tx.txid.to_string(),
        vsize: tx.vsize as i64,
        balances_all,
    };

    proto::TransItem {
        id,
        created_at: tx.created_at.millis() as i64,
        confs,
        item: Some(proto::trans_item::Item::Tx(tx_details)),
    }
}
