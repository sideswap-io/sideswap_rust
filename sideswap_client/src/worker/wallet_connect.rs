use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, anyhow, bail, ensure};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use elements::{Script, pset::PartiallySignedTransaction};
use lwk_wollet::WolletDescriptor;
use sideswap_api::connect_api;
use sideswap_common::{
    wallet_key::WalletKey,
    ws_client::{self, WsClient},
};
use sideswap_jade::{
    jade_mng::{self, AE_STUB_DATA},
    models::{OutputVariant, TrustedCommitment},
};
use sideswap_types::env::Env;

use crate::{
    ffi::proto::{self, Account},
    gdk_ses::{GdkSes, WalletInfo},
    utils::{encode_jade_tx, get_jade_asset_info, get_jade_network, unlock_hw},
};

use super::Data;

pub struct WalletConnect {
    connected: bool,
    descriptor: WolletDescriptor,
    wallet_key: WalletKey,
    client: WsClient,

    last_ui_id: u32,

    /// Map ui id to request_id
    pending_login_request_ids: BTreeMap<u32, String>,

    /// Map ui id to request_id
    pending_sign_request_ids: BTreeMap<u32, String>,

    sessions: BTreeMap<String, connect_api::Session>,

    login_requests: BTreeMap<String, connect_api::LoginRequest>,

    sign_requests: BTreeMap<String, connect_api::SignRequest>,

    /// The list of user's action.
    /// Send it to the server if the upstream connection is up or after reconnect.
    /// The server will sort them out as needed.
    user_actions: BTreeMap<connect_api::ReqId, connect_api::UserAction>,

    mobile_requests: BTreeSet<String>,
}

pub fn new(data: &mut Data, descriptor: &WolletDescriptor) -> WalletConnect {
    let connect_server_url = match data.env {
        Env::Prod => "wss://api.sideswap.io/wallet-connect",
        Env::Testnet => "wss://api-testnet.sideswap.io/wallet-connect",
        Env::LocalLiquid => "ws://127.0.0.1:51225",
        Env::LocalTestnet => "ws://127.0.0.1:51235",
        Env::LocalRegtest => "ws://127.0.0.1:51245",
    };

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

    let master_blinding_key = match descriptor.as_ref().key {
        elements_miniscript::confidential::Key::Slip77(master_blinding_key) => master_blinding_key,
        elements_miniscript::confidential::Key::View(_)
        | elements_miniscript::confidential::Key::Bare(_) => {
            panic!("expected slip77 descriptor")
        }
    };

    let wallet_key = WalletKey::new(master_blinding_key.as_bytes(), data.env.d().network);

    WalletConnect {
        connected: false,
        descriptor: descriptor.clone(),
        wallet_key,
        client,
        last_ui_id: 0,
        pending_login_request_ids: BTreeMap::new(),
        pending_sign_request_ids: BTreeMap::new(),
        sessions: BTreeMap::new(),
        login_requests: BTreeMap::new(),
        sign_requests: BTreeMap::new(),
        user_actions: BTreeMap::new(),
        mobile_requests: BTreeSet::new(),
    }
}

fn add_user_action(data: &mut Data, action: connect_api::UserAction) {
    let wallet_data = match data.wallet_data.as_mut() {
        Some(wallet_data) => wallet_data,
        None => return,
    };

    let new_id = wallet_data
        .wallet_connect
        .user_actions
        .keys()
        .last()
        .copied()
        .unwrap_or_default()
        + 1;

    log::debug!("new user action, id: {new_id}");

    let old_value = wallet_data
        .wallet_connect
        .user_actions
        .insert(new_id, action.clone());
    assert!(old_value.is_none());

    if wallet_data.wallet_connect.connected {
        send_request(
            &wallet_data.wallet_connect,
            new_id,
            connect_api::Req::UserAction(connect_api::UserActionReq { action }),
        );
    }
}

fn add_session(data: &mut Data, session: connect_api::Session) {
    let wallet_data = match data.wallet_data.as_mut() {
        Some(wallet_data) => wallet_data,
        None => return,
    };

    let session_id = session.session_id.clone();

    wallet_data
        .wallet_connect
        .sessions
        .insert(session_id.clone(), session);
}

fn remove_session(data: &mut Data, session_id: &String) {
    let wallet_data = match data.wallet_data.as_mut() {
        Some(wallet_data) => wallet_data,
        None => return,
    };

    wallet_data.wallet_connect.sessions.remove(session_id);
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
        .sign_requests
        .get(request_id)
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
    let wallet_data = match data.wallet_data.as_mut() {
        Some(wallet_data) => wallet_data,
        None => return,
    };

    let domain = login_request.domain.clone();

    let old_sign_request = wallet_data
        .wallet_connect
        .login_requests
        .insert(login_request.request_id.clone(), login_request.clone());

    if old_sign_request.is_none() {
        wallet_data.wallet_connect.last_ui_id += 1;
        let ui_id = wallet_data.wallet_connect.last_ui_id;

        wallet_data
            .wallet_connect
            .pending_login_request_ids
            .insert(ui_id, login_request.request_id);

        data.ui.send(proto::from::Msg::SignerRequest(
            proto::from::SignerRequest {
                req_id: ui_id,
                origin: domain,
                ttl_milliseconds: Some(login_request.ttl.as_millis()),
                msg: Some(proto::from::signer_request::Msg::Connect(proto::Empty {})),
            },
        ));
    }
}

fn remove_login_request(data: &mut Data, request_id: &String) {
    let wallet_data = match data.wallet_data.as_mut() {
        Some(wallet_data) => wallet_data,
        None => return,
    };

    wallet_data.wallet_connect.sign_requests.remove(request_id);
}

fn add_sign_request(data: &mut Data, sign_request: connect_api::SignRequest) {
    let wallet_data = match data.wallet_data.as_mut() {
        Some(wallet_data) => wallet_data,
        None => return,
    };

    let old_sign_request = wallet_data
        .wallet_connect
        .sign_requests
        .insert(sign_request.request_id.clone(), sign_request.clone());

    if old_sign_request.is_none() {
        wallet_data.wallet_connect.last_ui_id += 1;
        let ui_id = wallet_data.wallet_connect.last_ui_id;

        let res = get_signer_request_details(data, &sign_request.pset);

        match res {
            Ok(details) => {
                let wallet_data = data.wallet_data.as_mut().expect("already checked");

                wallet_data
                    .wallet_connect
                    .pending_sign_request_ids
                    .insert(ui_id, sign_request.request_id);

                data.ui.send(proto::from::Msg::SignerRequest(
                    proto::from::SignerRequest {
                        req_id: ui_id,
                        origin: sign_request.domain,
                        ttl_milliseconds: Some(sign_request.ttl.as_millis()),
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
}

fn remove_sign_request(data: &mut Data, request_id: &String) {
    let wallet_data = match data.wallet_data.as_mut() {
        Some(wallet_data) => wallet_data,
        None => return,
    };

    wallet_data.wallet_connect.sign_requests.remove(request_id);
}

fn send_request(connect: &WalletConnect, id: connect_api::ReqId, req: connect_api::Req) {
    let data = serde_json::to_string(&connect_api::To::Req { id, req }).expect("must not fail");

    connect
        .client
        .send_command(ws_client::Command::Send { data: data.into() });
}

pub fn handle_msg(data: &mut Data, event: ws_client::Event) {
    let wallet = match data.wallet_data.as_mut() {
        Some(wallet) => wallet,
        None => return,
    };

    match event {
        ws_client::Event::Connected => {
            log::debug!("wallet connect server is connected");

            wallet
                .wallet_connect
                .client
                .send_command(ws_client::Command::ConnectAck);

            send_request(
                &wallet.wallet_connect,
                0,
                connect_api::Req::Challenge(connect_api::ChallengeReq {}),
            );
        }

        ws_client::Event::Recv { text } => {
            let res = serde_json::from_slice::<connect_api::From>(text.as_bytes());
            match res {
                Ok(from) => match from {
                    connect_api::From::Resp { id, resp } => match resp {
                        connect_api::Resp::Challenge(resp) => {
                            send_request(
                                &wallet.wallet_connect,
                                0,
                                connect_api::Req::Login(connect_api::LoginReq {
                                    public_key: wallet.wallet_connect.wallet_key.public_key(),
                                    signature: wallet
                                        .wallet_connect
                                        .wallet_key
                                        .sign_challenge(&resp.challenge),
                                }),
                            );
                        }
                        connect_api::Resp::Login(connect_api::LoginResp {
                            sessions,
                            sign_requests,
                        }) => {
                            log::debug!("login succeed");

                            wallet.wallet_connect.connected = true;

                            for (&req_id, action) in wallet.wallet_connect.user_actions.iter() {
                                send_request(
                                    &wallet.wallet_connect,
                                    req_id,
                                    connect_api::Req::UserAction(connect_api::UserActionReq {
                                        action: action.clone(),
                                    }),
                                );
                            }

                            let old_session_ids = wallet
                                .wallet_connect
                                .sessions
                                .keys()
                                .cloned()
                                .collect::<BTreeSet<_>>();

                            let new_session_ids = sessions
                                .iter()
                                .map(|req| req.session_id.clone())
                                .collect::<BTreeSet<_>>();

                            for session_id in old_session_ids.difference(&new_session_ids) {
                                remove_session(data, session_id);
                            }

                            for session in sessions {
                                add_session(data, session);
                            }

                            for sign_request in sign_requests {
                                add_sign_request(data, sign_request);
                            }
                        }

                        connect_api::Resp::UserAction(connect_api::UserActionResp {}) => {
                            let old_value = wallet.wallet_connect.user_actions.remove(&id);
                            match old_value {
                                Some(_) => {
                                    log::debug!("user action ack, id: {id}")
                                }
                                None => log::debug!("unknown user_action id: {id}"),
                            }
                        }
                    },

                    connect_api::From::Error { id: _, err: _ } => {
                        // FIXME: Handle this
                    }

                    connect_api::From::Notif { notif } => match notif {
                        connect_api::Notif::SessionCreated(notif) => {
                            add_session(data, notif.session);
                        }
                        connect_api::Notif::SessionRemoved(notif) => {
                            remove_session(data, &notif.session_id);
                        }
                        connect_api::Notif::LoginRequestCreated(notif) => {
                            add_login_request(data, notif.request);
                        }
                        connect_api::Notif::LoginRequestRemoved(notif) => {
                            remove_login_request(data, &notif.request_id);
                        }
                        connect_api::Notif::SignRequestCreated(notif) => {
                            add_sign_request(data, notif.request);
                        }
                        connect_api::Notif::SignRequestRemoved(notif) => {
                            remove_sign_request(data, &notif.request_id);
                        }
                    },
                },

                Err(err) => {
                    log::error!("parsing wallet connect message failed: {err}, msg: {text}");
                }
            }
        }

        ws_client::Event::Disconnected => {
            log::debug!("server is disconnected");
            wallet.wallet_connect.connected = false;
        }
    }
}

pub fn handle_app_state(data: &mut Data) {
    if let Some(wallet) = data.wallet_data.as_mut() {
        wallet.wallet_connect.client.set_app_active(data.app_active);
    }
}

fn try_process_app_link(data: &mut Data, resp: &proto::to::AppLink) -> Result<(), anyhow::Error> {
    let url = url::Url::parse(&resp.url)?;

    let host = url.host().ok_or_else(|| anyhow!("no host"))?;
    let domain = match host {
        url::Host::Domain(domain) => domain,
        url::Host::Ipv4(ipv4_addr) => bail!("ipv4 links are not supported: {ipv4_addr}"),
        url::Host::Ipv6(ipv6_addr) => bail!("ipv6 links are not supported: {ipv6_addr}"),
    };
    ensure!(url.port() == None);

    let params = url
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<String, String>>();

    let wallet_data = data
        .wallet_data
        .as_mut()
        .ok_or_else(|| anyhow!("no wallet_data"))?;

    let is_mobile = params
        .get("mobile")
        .map(|value| bool::from_str(value))
        .transpose()
        .context("invalid `mobile` query parameter value")?
        .unwrap_or_default();

    let request_id = params
        .get("request_id")
        .ok_or_else(|| anyhow!("invalid link: no request_id query parameter"))?
        .clone();

    if is_mobile {
        wallet_data
            .wallet_connect
            .mobile_requests
            .insert(request_id.clone());
    }

    match (url.scheme(), domain, url.path()) {
        ("https", "app.sideswap.io", "/login/") | ("liquidconnect", "login", "/") => {
            add_user_action(
                data,
                connect_api::UserAction::LinkLoginRequest { request_id },
            );

            Ok(())
        }

        ("https", "app.sideswap.io", "/sign/") | ("liquidconnect", "sign", "/") => {
            // Do nothing

            Ok(())
        }
        _ => bail!("unsupported URL: {url}", url = resp.url),
    }
}

pub fn new_app_link(data: &mut Data, resp: proto::to::AppLink) {
    if data.wallet_data.is_none() {
        data.show_message("Create or import a new wallet");
        return;
    }

    let res = try_process_app_link(data, &resp);

    if let Err(err) = res {
        data.show_message(&format!("{err}: {url}", url = &resp.url));
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

    if let Some(request_id) = wallet_data
        .wallet_connect
        .pending_login_request_ids
        .remove(&resp.req_id)
    {
        let is_mobile = wallet_data
            .wallet_connect
            .mobile_requests
            .contains(&request_id);

        if resp.accept {
            let descriptor = wallet_data.wallet_connect.descriptor.to_string();
            add_user_action(
                data,
                connect_api::UserAction::AcceptLoginRequest {
                    request_id,
                    descriptor,
                },
            );
        } else {
            add_user_action(
                data,
                connect_api::UserAction::CancelLoginRequest { request_id },
            );
        }

        if is_mobile {
            data.ui
                .send(proto::from::Msg::SignerReturn(proto::Empty {}));
        }
    } else if let Some(request_id) = wallet_data
        .wallet_connect
        .pending_sign_request_ids
        .remove(&resp.req_id)
    {
        let is_mobile = wallet_data
            .wallet_connect
            .mobile_requests
            .contains(&request_id);

        if resp.accept {
            let res = try_sign_pset(data, &request_id);

            match res {
                Ok(pset) => {
                    add_user_action(
                        data,
                        connect_api::UserAction::AcceptSignRequest {
                            request_id,
                            pset: pset.to_string(),
                        },
                    );

                    if is_mobile {
                        data.ui
                            .send(proto::from::Msg::SignerReturn(proto::Empty {}));
                    }
                }
                Err(err) => {
                    data.show_message(&format!("PSET sign failed: {err}"));
                }
            }
        } else {
            add_user_action(
                data,
                connect_api::UserAction::CancelSignRequest { request_id },
            );

            if is_mobile {
                data.ui
                    .send(proto::from::Msg::SignerReturn(proto::Empty {}));
            }
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
