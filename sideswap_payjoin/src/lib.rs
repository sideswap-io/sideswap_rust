use std::{collections::BTreeMap, time::Duration};

use anyhow::{bail, ensure};
use base64::Engine;
use elements::{pset::PartiallySignedTransaction, secp256k1_zkp::SECP256K1, AssetId, TxOutSecrets};
use sideswap_common::{
    network::Network,
    pset_blind::get_blinding_nonces,
    recipient::Recipient,
    send_tx::pset::{construct_pset, ConstructPsetArgs, ConstructedPset, PsetInput, PsetOutput},
    utxo_select,
};

use crate::server_api::{SignResponse, StartResponse};

pub mod server_api;

pub const BASE_URL_PROD: &str = "https://api.sideswap.io";
pub const BASE_URL_TESTNET: &str = "https://api-testnet.sideswap.io";

pub struct GetAcceptedAssets {
    pub base_url: String,
}

pub struct AcceptedAssets {
    pub assets: Vec<AssetId>,
}

pub struct Utxo {
    pub txid: elements::Txid,
    pub vout: u32,
    pub asset_id: elements::AssetId,
    pub value: u64,
    pub asset_bf: elements::confidential::AssetBlindingFactor,
    pub value_bf: elements::confidential::ValueBlindingFactor,
    pub script_pub_key: elements::script::Script,
}

pub struct CreatePayjoin {
    pub network: Network,
    pub base_url: String,
    pub user_agent: String,
    pub utxos: Vec<Utxo>,
    pub multisig_wallet: bool,
    pub use_all_utxos: bool,
    pub recipients: Vec<Recipient>,
    pub deduct_fee: Option<usize>,
    pub fee_asset: AssetId,
}

#[derive(Clone)]
pub struct CreatedPayjoin {
    pub pset: PartiallySignedTransaction,
    pub blinding_nonces: Vec<String>,
    pub asset_fee: u64,
    pub network_fee: u64,
}

pub trait Wallet {
    fn change_address(&mut self) -> Result<elements::Address, anyhow::Error>;
}

static AGENT: std::sync::LazyLock<ureq::Agent> = std::sync::LazyLock::new(|| {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build()
});

fn get_url(base_url: &str) -> String {
    format!("{base_url}/payjoin")
}

pub fn accepted_assets(req: GetAcceptedAssets) -> Result<AcceptedAssets, anyhow::Error> {
    let GetAcceptedAssets { base_url } = req;

    let url = get_url(&base_url);

    let resp = make_server_request(
        &AGENT,
        &url,
        server_api::Request::AcceptedAssets(server_api::AcceptedAssetsRequest {}),
    )?;

    let server_api::AcceptedAssetsResponse { accepted_asset } = match resp {
        server_api::Response::AcceptedAssets(resp) => resp,
        _ => bail!("unexpected response {resp:?}"),
    };

    ensure!(!accepted_asset.is_empty(), "empty payjoin asset list");

    Ok(AcceptedAssets {
        assets: accepted_asset
            .into_iter()
            .map(|asset| asset.asset_id)
            .collect(),
    })
}

pub fn create_payjoin(
    wallet: &mut impl Wallet,
    req: CreatePayjoin,
) -> Result<CreatedPayjoin, anyhow::Error> {
    let CreatePayjoin {
        network,
        base_url,
        user_agent,
        utxos: client_utxos,
        multisig_wallet,
        use_all_utxos,
        recipients,
        deduct_fee,
        fee_asset,
    } = req;

    ensure!(!client_utxos.is_empty());
    ensure!(recipients.iter().all(|r| r.address.is_blinded()));
    ensure!(recipients.iter().all(|r| r.amount > 0));

    let url = get_url(&base_url);

    let req = server_api::Request::Start(server_api::StartRequest {
        asset_id: fee_asset,
        user_agent,
        api_key: None,
    });
    let resp = make_server_request(&AGENT, &url, req)?;
    let StartResponse {
        order_id,
        expires_at: _,
        fee_address: server_fee_address,
        change_address: server_change_address,
        utxos: server_utxos,
        price,
        fixed_fee,
    } = match resp {
        server_api::Response::Start(resp) => resp,
        _ => bail!("unexpected response {resp:?}"),
    };

    ensure!(server_fee_address.is_blinded());
    ensure!(server_change_address.is_blinded());
    ensure!(!server_utxos.is_empty());

    let wallet_type = if multisig_wallet {
        utxo_select::WalletType::AMP
    } else {
        utxo_select::WalletType::Nested
    };

    let policy_asset = network.d().policy_asset.asset_id();
    let args = utxo_select::payjoin::Args {
        policy_asset,
        fee_asset,
        price,
        fixed_fee,
        use_all_utxos,
        utxos: client_utxos
            .iter()
            .map(|utxo| utxo_select::Utxo {
                asset_id: utxo.asset_id,
                value: utxo.value,
                wallet: wallet_type,
                txid: utxo.txid,
                vout: utxo.vout,
            })
            .collect(),
        server_utxos: server_utxos
            .iter()
            .map(|utxo| utxo_select::Utxo {
                wallet: utxo_select::WalletType::Native,
                txid: utxo.txid,
                vout: utxo.vout,
                asset_id: utxo.asset_id,
                value: utxo.value,
            })
            .collect(),
        recipients: recipients
            .iter()
            .map(|r| utxo_select::Recipient {
                address: utxo_select::RecipientAddress::Known(r.address.clone()),
                asset_id: r.asset_id,
                amount: r.amount,
            })
            .collect(),
        deduct_fee,
        force_change_wallets: BTreeMap::new(),
    };
    let res = utxo_select::payjoin::select(args)?;
    let utxo_select::payjoin::Res {
        inputs: selected_utxos,
        updated_recipients,
        change,
        server_inputs,
        server_change,
        network_fee,
        server_fee,
    } = res;

    let mut inputs = Vec::new();
    let mut outputs = Vec::new();

    let server_utxos = server_utxos
        .into_iter()
        .map(|utxo| Utxo {
            txid: utxo.txid,
            vout: utxo.vout,
            asset_id: utxo.asset_id,
            value: utxo.value,
            asset_bf: utxo.asset_bf,
            value_bf: utxo.value_bf,
            script_pub_key: utxo.script_pub_key,
        })
        .collect::<Vec<_>>();

    inputs.append(&mut take_utxos(client_utxos, selected_utxos.iter()));
    inputs.append(&mut take_utxos(server_utxos, server_inputs.iter()));

    for recipient in updated_recipients {
        // Use corrected amount if deduct_fee was set
        outputs.push(PsetOutput {
            asset_id: recipient.asset_id,
            amount: recipient.amount,
            address: recipient.address.known().expect("must be known").clone(),
        });
    }

    for output in change.iter() {
        let address = wallet.change_address()?;
        outputs.push(PsetOutput {
            asset_id: output.asset_id,
            amount: output.value,
            address,
        });
    }

    outputs.push(PsetOutput {
        asset_id: fee_asset,
        amount: server_fee,
        address: server_fee_address,
    });

    if let Some(output) = server_change {
        outputs.push(PsetOutput {
            asset_id: output.asset_id,
            amount: output.value,
            address: server_change_address,
        });
    }

    let ConstructedPset {
        blinded_pset,
        blinded_outputs,
    } = construct_pset(ConstructPsetArgs {
        policy_asset,
        offlines: Vec::new(),
        inputs,
        outputs,
        network_fee,
    })?;

    let mut server_pset = blinded_pset.clone();
    sideswap_common::pset_blind::remove_explicit_values(&mut server_pset);
    let server_pset = elements::encode::serialize(&server_pset);

    let req = server_api::Request::Sign(server_api::SignRequest {
        order_id,
        pset: base64::engine::general_purpose::STANDARD.encode(server_pset),
    });
    let resp = make_server_request(&AGENT, &url, req)?;
    let SignResponse {
        pset: server_signed_pset,
    } = match resp {
        server_api::Response::Sign(resp) => resp,
        _ => bail!("unexpected response {resp:?}"),
    };
    let server_signed_pset = elements::encode::deserialize::<PartiallySignedTransaction>(
        &base64::engine::general_purpose::STANDARD.decode(server_signed_pset)?,
    )?;

    let pset = copy_signatures(blinded_pset, server_signed_pset)?;

    Ok(CreatedPayjoin {
        pset,
        blinding_nonces: get_blinding_nonces(&blinded_outputs),
        asset_fee: server_fee,
        network_fee: network_fee,
    })
}

fn take_utxos<'a>(
    mut utxos: Vec<Utxo>,
    required: impl Iterator<Item = &'a utxo_select::Utxo>,
) -> Vec<PsetInput> {
    let mut selected = Vec::new();
    for required in required {
        let index = utxos
            .iter()
            .position(|utxo| utxo.asset_id == required.asset_id && utxo.value == required.value)
            .expect("must exists");
        let utxo = utxos.remove(index);

        let (asset_commitment, value_commitment) = if utxo.asset_bf
            == elements::confidential::AssetBlindingFactor::zero()
            || utxo.value_bf == elements::confidential::ValueBlindingFactor::zero()
        {
            (
                elements::confidential::Asset::Explicit(utxo.asset_id),
                elements::confidential::Value::Explicit(utxo.value),
            )
        } else {
            let gen = elements::secp256k1_zkp::Generator::new_blinded(
                SECP256K1,
                utxo.asset_id.into_tag(),
                utxo.asset_bf.into_inner(),
            );
            (
                elements::confidential::Asset::Confidential(gen),
                elements::confidential::Value::new_confidential(
                    SECP256K1,
                    utxo.value,
                    gen,
                    utxo.value_bf,
                ),
            )
        };

        let input = PsetInput {
            txid: utxo.txid,
            vout: utxo.vout,
            script_pub_key: utxo.script_pub_key,
            asset_commitment,
            value_commitment,
            tx_out_sec: TxOutSecrets {
                asset: utxo.asset_id,
                asset_bf: utxo.asset_bf,
                value: utxo.value,
                value_bf: utxo.value_bf,
            },
        };
        selected.push(input);
    }
    selected
}

fn copy_signatures(
    mut dst: PartiallySignedTransaction,
    src: PartiallySignedTransaction,
) -> Result<PartiallySignedTransaction, anyhow::Error> {
    ensure!(dst.inputs().len() == src.inputs().len());
    ensure!(dst.outputs().len() == src.outputs().len());
    for (dst, src) in dst.inputs_mut().iter_mut().zip(src.inputs().iter()) {
        if src.final_script_witness.is_some() {
            dst.final_script_sig = src.final_script_sig.clone();
            dst.final_script_witness = src.final_script_witness.clone();
        }
    }
    Ok(dst)
}

pub fn final_tx(
    pset_client: PartiallySignedTransaction,
    pset_server: PartiallySignedTransaction,
) -> Result<elements::Transaction, anyhow::Error> {
    let pset = copy_signatures(pset_client, pset_server)?;
    let tx = pset.extract_tx()?;
    Ok(tx)
}

fn make_server_request(
    agent: &ureq::Agent,
    url: &str,
    req: server_api::Request,
) -> Result<server_api::Response, anyhow::Error> {
    let res = agent.post(url).send_json(req);

    match res {
        Ok(resp) => {
            let resp = resp.into_json::<server_api::Response>()?;
            Ok(resp)
        }
        Err(ureq::Error::Transport(err)) => {
            bail!("unexpected HTTP transport error: {err}");
        }
        Err(ureq::Error::Status(400, resp)) => {
            let err = resp.into_json::<server_api::Error>()?.error;
            bail!("unexpected server error: {err}");
        }
        Err(ureq::Error::Status(status, resp)) => {
            let err = resp.into_string()?;
            bail!("unexpected HTTP status: {status}: {err}");
        }
    }
}
