use std::{collections::BTreeSet, str::FromStr, sync::Arc};

use anyhow::{anyhow, bail, ensure};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use elements::{Script, pset::PartiallySignedTransaction};
use lwk_wollet::WolletDescriptor;
use rand::{Rng, thread_rng};
use sideswap_api::connect_api::{self, InstallId};
use sideswap_common::{
    wallet_connect::{Effect, Input, WalletConnectCore},
    wallet_key::WalletKey,
    ws_client::{self, WsClient},
};
use sideswap_jade::{
    jade_mng::{self, AE_STUB_DATA},
    models::{OutputVariant, TrustedCommitment},
};

use crate::{
    ffi::proto::{self, Account},
    gdk_ses::{GdkSes, WalletInfo},
    utils::{encode_jade_tx, get_jade_asset_info, get_jade_network, unlock_hw},
};

use super::Data;

pub struct WalletConnect {
    client: WsClient,
    connect_core: WalletConnectCore,
}

pub fn new(data: &mut Data, descriptor: &WolletDescriptor) -> WalletConnect {
    let connect_server_url = sideswap_common::wallet_connect::get_connect_server_url(data.env);

    let msg_sender = data.msg_sender.clone();
    let event_cb = Box::new(move |event| {
        let _ = msg_sender.send(super::Message::WalletConnect(event));
    });

    let client = WsClient::new(
        connect_server_url.to_owned(),
        data.runtime.handle(),
        event_cb,
    );

    client.set_app_active(data.app_active);

    let master_blinding_key = match descriptor
        .ct_descriptor()
        .expect("must be a ct_descriptor")
        .key
    {
        elements_miniscript::confidential::Key::Slip77(master_blinding_key) => master_blinding_key,
        elements_miniscript::confidential::Key::View(_)
        | elements_miniscript::confidential::Key::Bare(_) => {
            panic!("expected slip77 descriptor")
        }
    };

    let wallet_key = WalletKey::new(master_blinding_key.as_bytes(), data.env.d().network);

    data.ui
        .send(proto::from::Msg::SessionList(proto::from::SessionList {
            sessions: Vec::new(),
        }));

    let install_id = match data.settings.install_id {
        Some(install_id) => install_id,
        None => {
            let install_id = InstallId(thread_rng().r#gen());
            data.settings.install_id = Some(install_id);
            data.save_settings();
            install_id
        }
    };

    let connect_core = WalletConnectCore::new(install_id, descriptor.to_string(), wallet_key);

    WalletConnect {
        client,
        connect_core,
    }
}

impl From<connect_api::Session> for proto::Session {
    fn from(value: connect_api::Session) -> Self {
        proto::Session {
            session_id: value.session_id,
            domain: value.domain,
            is_local: value.is_local,
        }
    }
}

fn get_signer_request_details(
    data: &mut Data,
    pset: &str,
) -> Result<proto::from::signer_request::Sign, anyhow::Error> {
    let wallet_data = data
        .wallet_data
        .as_mut()
        .ok_or_else(|| anyhow!("no wallet data"))?;

    let details = wallet_data
        .wallet_reg
        .default_account()
        .pset_details(&pset)?;

    data.add_missing_assets(details.balance.balances.keys(), true);

    Ok(proto::from::signer_request::Sign {
        balances: details
            .balance
            .balances
            .iter()
            .map(|(asset_id, amount)| proto::Balance {
                asset_id: asset_id.to_string(),
                amount: *amount,
            })
            .collect(),

        recipients: details
            .balance
            .recipients
            .iter()
            .filter_map(|recipient| {
                let address = recipient.address.as_ref()?.to_string();
                let amount = recipient.value? as i64;
                let asset_id = recipient.asset?.to_string();
                Some(proto::AddressAmount {
                    address,
                    amount,
                    asset_id,
                })
            })
            .collect(),
        network_fee: details.balance.fee,
    })
}

fn try_sign_pset(
    data: &mut Data,
    request_id: &str,
) -> Result<PartiallySignedTransaction, anyhow::Error> {
    let wallet_data = data
        .wallet_data
        .as_mut()
        .ok_or_else(|| anyhow!("no wallet_data"))?;

    let request = wallet_data
        .wallet_connect
        .connect_core
        .get_sign_request(request_id)
        .ok_or_else(|| anyhow!("request already removed"))?;

    let mut pset = PartiallySignedTransaction::from_str(&request.pset)?;

    let pset = match &wallet_data.wallet_reg.login_info().wallet_info {
        WalletInfo::Mnemonic(mnemonic) => {
            use lwk_common::Signer;
            let signer = lwk_signer::SwSigner::new(&mnemonic.to_string(), data.env.d().mainnet)
                .expect("signer creation failed");

            signer.sign(&mut pset)?;

            pset
        }

        WalletInfo::Jade(_jade, watch_only) => {
            let my_fingerprint = watch_only.master_xpub_fingerprint;

            try_sign_pset_jade(data, pset, my_fingerprint)?
        }
    };

    Ok(pset)
}

fn add_login_request(data: &mut Data, login_request: connect_api::LoginRequest) {
    let domain = login_request.domain.clone();

    data.ui.send(proto::from::Msg::SignerRequest(
        proto::from::SignerRequest {
            req_id: login_request.request_id,
            origin: domain,
            ttl_milliseconds: login_request.ttl.as_millis(),
            msg: Some(proto::from::signer_request::Msg::Connect(proto::Empty {})),
        },
    ));
}

fn remove_login_request(data: &mut Data, request_id: &String) {
    data.ui
        .send(proto::from::Msg::SignerCancel(proto::from::SignerCancel {
            req_id: request_id.clone(),
        }));
}

fn add_sign_request(data: &mut Data, sign_request: connect_api::SignRequest) {
    let res = get_signer_request_details(data, &sign_request.pset);

    match res {
        Ok(details) => {
            data.ui.send(proto::from::Msg::SignerRequest(
                proto::from::SignerRequest {
                    req_id: sign_request.request_id,
                    origin: sign_request.domain,
                    ttl_milliseconds: sign_request.ttl.as_millis(),
                    msg: Some(proto::from::signer_request::Msg::Sign(details)),
                },
            ));
        }

        Err(err) => {
            data.show_message(&format!(
                "invalid sign request from {domain}: {err}",
                domain = sign_request.domain
            ));
        }
    }
}

fn remove_sign_request(data: &mut Data, request_id: &String) {
    data.ui
        .send(proto::from::Msg::SignerCancel(proto::from::SignerCancel {
            req_id: request_id.clone(),
        }));
}

fn handle_core_effect(data: &mut Data, effect: Effect) {
    let wallet_data = match data.wallet_data.as_mut() {
        Some(wallet_data) => wallet_data,
        None => return,
    };

    match effect {
        Effect::Transport { command } => {
            wallet_data.wallet_connect.client.send_command(command);
        }
        Effect::AddLoginRequest { request } => {
            add_login_request(data, request);
        }
        Effect::RemoveLoginRequest { request_id } => {
            remove_login_request(data, &request_id);
        }
        Effect::AddSignRequest { request } => {
            add_sign_request(data, request);
        }
        Effect::RemoveSignRequest { request_id } => {
            remove_sign_request(data, &request_id);
        }

        Effect::SessionList { sessions } => {
            data.ui
                .send(proto::from::Msg::SessionList(proto::from::SessionList {
                    sessions: sessions.into_iter().map(Into::into).collect(),
                }));
        }
        Effect::SessionCreated { session } => {
            data.ui
                .send(proto::from::Msg::SessionAdded(proto::from::SessionAdded {
                    session: session.into(),
                }));
        }
        Effect::SessionRemoved { session_id } => {
            data.ui.send(proto::from::Msg::SessionRemoved(
                proto::from::SessionRemoved { session_id },
            ));
        }

        Effect::MinimizeMobileApp => {
            data.ui
                .send(proto::from::Msg::SignerReturn(proto::Empty {}));
        }
    }
}

fn handle_core_input(data: &mut Data, input: Input) {
    let wallet = match data.wallet_data.as_mut() {
        Some(wallet) => wallet,
        None => return,
    };

    let effects = wallet.wallet_connect.connect_core.handle(input);
    for effect in effects {
        handle_core_effect(data, effect);
    }
}

pub fn handle_app_state(data: &mut Data) {
    if let Some(wallet) = data.wallet_data.as_mut() {
        wallet.wallet_connect.client.set_app_active(data.app_active);
    }
}

pub fn handle_ws_event(data: &mut Data, event: ws_client::Event) {
    handle_core_input(data, Input::Transport { event });
}

pub fn set_fcm_token(data: &mut Data, token: String) {
    handle_core_input(data, Input::RegisterFcmToken { token });
}

pub fn new_app_link(data: &mut Data, resp: proto::to::AppLink) {
    if data.wallet_data.is_none() {
        data.show_message("Create or import a new wallet");
        return;
    }

    let res = sideswap_common::wallet_connect::parse_app_link(&resp.url);
    match res {
        Ok(app_link) => {
            handle_core_input(data, Input::AppLink { app_link });
        }
        Err(err) => {
            data.show_message(&format!("{err}: {url}", url = &resp.url));
        }
    }
}

pub fn ui_response(data: &mut Data, resp: proto::to::SignerResponse) {
    let wallet_data = match data.wallet_data.as_mut() {
        Some(wallet_data) => wallet_data,
        None => {
            log::debug!("no wallet_data, drop the UI response");
            return;
        }
    };

    if wallet_data
        .wallet_connect
        .connect_core
        .get_login_request(&resp.req_id)
        .is_some()
    {
        if resp.accept {
            handle_core_input(
                data,
                Input::LoginAccepted {
                    request_id: resp.req_id,
                },
            );
        } else {
            handle_core_input(
                data,
                Input::LoginRejected {
                    request_id: resp.req_id,
                },
            );
        }
    } else if wallet_data
        .wallet_connect
        .connect_core
        .get_sign_request(&resp.req_id)
        .is_some()
    {
        if resp.accept {
            let res = try_sign_pset(data, &resp.req_id);

            match res {
                Ok(signed_pset) => {
                    handle_core_input(
                        data,
                        Input::SignAccepted {
                            request_id: resp.req_id,
                            signed_pset: signed_pset.to_string(),
                        },
                    );
                }
                Err(err) => {
                    data.show_message(&format!("PSET sign failed: {err}"));
                }
            }
        } else {
            handle_core_input(
                data,
                Input::SignRejected {
                    request_id: resp.req_id,
                },
            );
        }
    }
}

// Copied from LWK
/// Create the same burn script that Elements Core wallet creates
pub fn burn_script() -> elements::Script {
    elements::script::Builder::new()
        .push_opcode(elements::opcodes::all::OP_RETURN)
        .into_script()
}

pub fn derivation_path_to_vec(path: &DerivationPath) -> Vec<u32> {
    path.into_iter().map(|e| (*e).into()).collect()
}

// Copied from LWK
// Get a script from witness script pubkey hash
fn script_code_wpkh(script: &Script) -> Script {
    assert!(script.is_v0_p2wpkh());
    // ugly segwit stuff
    let mut script_code = vec![0x76u8, 0xa9, 0x14];
    script_code.extend(&script.as_bytes()[2..]);
    script_code.push(0x88);
    script_code.push(0xac);
    Script::from(script_code)
}

pub fn try_sign_pset_jade(
    worker: &super::Data,
    mut pset: PartiallySignedTransaction,
    my_fingerprint: Fingerprint,
) -> Result<PartiallySignedTransaction, anyhow::Error> {
    let network = get_jade_network(worker.env);

    let tx = pset.extract_tx()?;

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

    let _status = jade.start_status(jade_mng::JadeStatus::SignTx(jade_mng::TxType::Normal));

    let mut trusted_commitments = Vec::new();
    let mut change = Vec::new();

    for (index, output) in pset.outputs().iter().enumerate() {
        let unblinded = output.script_pubkey.is_empty() || output.script_pubkey == burn_script();

        let trusted_commitment = if !unblinded {
            Some(TrustedCommitment {
                asset_id: output
                    .asset
                    .ok_or_else(|| anyhow!("no asset_id in output {index}"))?
                    .into(),
                value: output.amount.ok_or(anyhow!("no value in output {index}"))?,
                asset_generator: output
                    .asset_comm
                    .ok_or_else(|| anyhow!("no asset_comm in output {index}"))?,
                value_commitment: output
                    .amount_comm
                    .ok_or_else(|| anyhow!("no amount_comm in output {index}"))?,
                blinding_key: output
                    .blinding_key
                    .ok_or_else(|| anyhow!("no blinding_key in output {index}"))?
                    .inner
                    .into(),
                abf: None,
                vbf: None,
                asset_blind_proof: Some(
                    output
                        .blind_asset_proof
                        .as_ref()
                        .ok_or_else(|| anyhow!("no blind_asset_proof in output {index}"))?
                        .serialize()
                        .into(),
                ),
                value_blind_proof: Some(
                    output
                        .blind_value_proof
                        .as_ref()
                        .ok_or_else(|| anyhow!("no blind_value_proof in output {index}"))?
                        .serialize()
                        .into(),
                ),
            })
        } else {
            None
        };

        let own_output = output
            .bip32_derivation
            .values()
            .find(|(fingerprint, _derivation_path)| *fingerprint == my_fingerprint);

        let own_output = if let Some((_fingerprint, path)) = own_output {
            const CHANGE_CHAIN: ChildNumber = ChildNumber::Normal { index: 1 };
            let is_change = path.clone().into_iter().nth_back(1) == Some(&CHANGE_CHAIN);

            let variant = if output.script_pubkey.is_v0_p2wpkh() {
                OutputVariant::P2wpkh
            } else if output.script_pubkey.is_p2sh() {
                if let Some(redeem_script) = output.redeem_script.as_ref() {
                    if redeem_script.is_v0_p2wpkh() {
                        OutputVariant::P2wpkhP2sh
                    } else {
                        bail!("unsupported output redeem_script: {redeem_script}")
                    }
                } else {
                    bail!("no output redeem_script")
                }
            } else {
                bail!(
                    "unsupported output script_pubkey: {script_pubkey}",
                    script_pubkey = output.script_pubkey
                )
            };

            Some(sideswap_jade::models::Output {
                variant: Some(variant),
                path: derivation_path_to_vec(path),
                recovery_xpub: None,
                is_change,
            })
        } else {
            None
        };

        trusted_commitments.push(trusted_commitment);
        change.push(own_output);
    }

    let asset_ids = pset
        .inputs()
        .iter()
        .filter_map(|input| input.asset)
        .chain(pset.outputs().iter().filter_map(|output| output.asset))
        .collect::<BTreeSet<_>>();

    let num_inputs = tx.input.len() as u32;

    let sign_tx = sideswap_jade::models::ReqSignTx {
        network,
        use_ae_signatures: true,
        txn: encode_jade_tx(tx),
        num_inputs,
        trusted_commitments,
        change,
        asset_info: get_jade_asset_info(&worker.assets, asset_ids),
        additional_info: None,
    };

    let resp = jade.sign_liquid_tx(sign_tx)?;
    ensure!(resp, "sign_tx failed");

    for (index, input) in pset.inputs_mut().iter_mut().enumerate() {
        let own_input = input
            .bip32_derivation
            .values()
            .find(|(fingerprint, _derivation_path)| *fingerprint == my_fingerprint);

        let params = if let Some((_fingerprint, path)) = own_input {
            let txout = input
                .witness_utxo
                .as_ref()
                .ok_or_else(|| anyhow!("missing witness_utxo for input {index}"))?;

            let previous_output_script = &txout.script_pubkey;

            // Copied from LWK:
            let is_nested_wpkh = previous_output_script.is_p2sh()
                && input
                    .redeem_script
                    .as_ref()
                    .map(|x| x.is_v0_p2wpkh())
                    .unwrap_or(false);

            // Copied from LWK:
            let script = if previous_output_script.is_v0_p2wpkh() {
                script_code_wpkh(previous_output_script)
            } else if previous_output_script.is_v0_p2wsh() {
                input.witness_script.clone().ok_or_else(|| {
                    anyhow!(
                        "previous script pubkey is wsh but witness script is missing in input {index}"
                    )
                })?
            } else if is_nested_wpkh {
                script_code_wpkh(
                    input
                        .redeem_script
                        .as_ref()
                        .expect("redeem script non-empty checked earlier"),
                )
            } else {
                bail!("unsupported spending script pubkey: {previous_output_script}");
            };

            Some(sideswap_jade::models::ReqTxInput {
                is_witness: true,
                path: derivation_path_to_vec(path),
                script: script.as_bytes().to_vec().into(),
                sighash: None,
                asset_id: None,
                value: None,
                abf: None,
                vbf: None,
                value_commitment: txout
                    .value
                    .commitment()
                    .ok_or_else(|| anyhow!("the input {index} must be blinded"))?,
                asset_generator: None,
                ae_host_commitment: AE_STUB_DATA,
                ae_host_entropy: AE_STUB_DATA,
            })
        } else {
            None
        };

        let _resp = jade.tx_input(params)?;
    }

    for input in pset.inputs_mut().iter_mut() {
        let own_input = input
            .bip32_derivation
            .iter()
            .find(|(_public_key, (fingerprint, _derivation_path))| *fingerprint == my_fingerprint);

        match own_input {
            Some((public_key, _)) => {
                let signature = jade
                    .get_signature(Some(AE_STUB_DATA))?
                    .ok_or_else(|| anyhow!("unexpected get_signature response"))?;
                input.partial_sigs.insert(*public_key, signature);
            }
            None => {
                let _signature = jade.get_signature(None)?;
            }
        }
    }

    Ok(pset)
}

pub fn stop_session(data: &mut Data, resp: proto::to::StopSession) {
    handle_core_input(
        data,
        Input::StopSession {
            session_id: resp.session_id,
        },
    );
}
