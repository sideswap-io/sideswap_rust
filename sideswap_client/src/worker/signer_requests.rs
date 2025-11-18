use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, anyhow, bail, ensure};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use elements::{Script, pset::PartiallySignedTransaction};
use serde_bytes::ByteBuf;
use sideswap_common::channel_helpers::UncheckedOneshotSender;
use sideswap_jade::{
    jade_mng::{self, AE_STUB_DATA},
    models::{OutputVariant, TrustedCommitment},
};
use sideswap_types::{signer_backend_api, signer_local_api};
use url::Url;

use crate::{
    ffi::proto::{self, Account},
    gdk_ses::{GdkSes, WalletInfo},
    signer_server::{SignerError, WebRequest},
    utils::{get_jade_asset_info, get_jade_network, unlock_hw},
    worker::{Data, SignerReqId},
};

enum Request {
    Login {},
    Sign { pset: String },
}

#[derive(Clone)]
enum Response {
    Login { descriptor: String },
    Sign { pset: String },
}

enum Receiver {
    Web {
        res_sender: UncheckedOneshotSender<Result<signer_local_api::Resp, SignerError>>,
    },
    AppLink {
        code: String,
        upload_url: url::Url,
        return_url: Option<url::Url>,
    },
}

pub struct SignerRequests {
    requests: BTreeMap<SignerReqId, (Request, Receiver)>,
    last_signer_req_id: SignerReqId,
}

impl SignerRequests {
    pub fn new() -> Self {
        SignerRequests {
            requests: BTreeMap::new(),
            last_signer_req_id: 0,
        }
    }
}

fn try_send_new_request(
    data: &mut Data,
    origin: String,
    req: &Request,
) -> Result<SignerReqId, SignerError> {
    let wallet_data = data.wallet_data.as_mut().ok_or(SignerError::NoWalletData)?;

    wallet_data.signer_requests.last_signer_req_id += 1;
    let req_id = wallet_data.signer_requests.last_signer_req_id;

    let ui_req = match &req {
        Request::Login {} => proto::from::signer_request::Msg::Connect(proto::Empty {}),

        Request::Sign { pset } => {
            let details = wallet_data
                .wallet_reg
                .default_account()
                .pset_details(&pset)?;

            data.add_missing_assets(details.balance.balances.keys(), true);

            proto::from::signer_request::Msg::Sign(proto::from::signer_request::Sign {
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
    };

    data.ui.send(proto::from::Msg::SignerRequest(
        proto::from::SignerRequest {
            req_id,
            origin,
            msg: Some(ui_req),
        },
    ));

    Ok(req_id)
}

fn try_process_app_link(data: &mut Data, resp: &proto::to::AppLink) -> Result<(), anyhow::Error> {
    let url = url::Url::parse(&resp.url)?;

    anyhow::ensure!(url.scheme() == "https");
    ensure!(url.host() == Some(url::Host::Domain("app.sideswap.io")));
    ensure!(url.port() == None);

    let params = url
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<String, String>>();

    let upload_url = params
        .get("upload_url")
        .ok_or_else(|| anyhow!("no upload_url query parameter"))?
        .clone();

    let return_url = params
        .get("return_url")
        .map(|url| Url::parse(url))
        .transpose()
        .context("return_url")?;

    let upload_url = url::Url::parse(&upload_url).context("upload_url")?;
    let upload_url_domain = upload_url
        .domain()
        .ok_or_else(|| anyhow!("no domain in upload_url"))?;

    let allow_localhost = crate::signer_server::allow_localhost(data.env);

    ensure!(upload_url.scheme() == "https" || allow_localhost && upload_url_domain == "localhost");

    ensure!(
        data.settings
            .signer_whitelisted_domains
            .iter()
            .any(|domain| domain == upload_url_domain)
            || allow_localhost && upload_url_domain == "localhost",
        "upload_url is not allowed, please contact support"
    );

    if let Some(return_url) = &return_url {
        let return_url_domain = return_url
            .domain()
            .ok_or_else(|| anyhow!("no domain in return_url"))?;
        ensure!(
            return_url.scheme() == "https" || allow_localhost && return_url_domain == "localhost"
        );
        ensure!(return_url_domain == upload_url_domain);
    }

    let code = params
        .get("code")
        .ok_or_else(|| anyhow!("invalid link: no code query parameter"))?
        .clone();

    let request = match url.path() {
        "/login/" => {
            send_request_to_upload_url(
                &upload_url,
                signer_backend_api::Req::StartLogin(signer_backend_api::StartLoginReq {
                    code: code.clone(),
                }),
            )?;

            Request::Login {}
        }

        "/sign/" => {
            let resp = send_request_to_upload_url(
                &upload_url,
                signer_backend_api::Req::StartSign(signer_backend_api::StartSignReq {
                    code: code.clone(),
                }),
            )?;

            if let signer_backend_api::Resp::StartSign(signer_backend_api::StartSignResp { pset }) =
                resp
            {
                Request::Sign { pset }
            } else {
                bail!("unexpected response, expected GetPset")
            }
        }

        _ => bail!("unknown path: {path}", path = url.path()),
    };

    let req_id = try_send_new_request(data, upload_url.to_string(), &request)?;

    let wallet_data = data.wallet_data.as_mut().ok_or(SignerError::NoWalletData)?;

    let receiver = Receiver::AppLink {
        code,
        upload_url,
        return_url,
    };

    wallet_data
        .signer_requests
        .requests
        .insert(req_id, (request, receiver));

    Ok(())
}

pub fn new_web_request(data: &mut Data, req: WebRequest) {
    let request = match req.req {
        signer_local_api::Req::Login(_req) => Request::Login {},
        signer_local_api::Req::Sign(req) => Request::Sign { pset: req.pset },
    };

    let res = try_send_new_request(data, req.origin, &request);

    match res {
        Ok(req_id) => {
            let receiver = Receiver::Web {
                res_sender: req.res_sender,
            };
            let wallet_data = data.wallet_data.as_mut().expect("must exist");
            wallet_data
                .signer_requests
                .requests
                .insert(req_id, (request, receiver));
        }
        Err(err) => {
            req.res_sender.send(Err(err));
        }
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

fn handle_return_url(data: &mut Data, return_url: Option<url::Url>) {
    data.ui
        .send(proto::from::Msg::SignerReturn(proto::from::SignerReturn {
            return_url: return_url.as_ref().map(ToString::to_string),
        }));
}

pub fn ui_response(data: &mut Data, resp: proto::to::SignerResponse) {
    let wallet_data = match data.wallet_data.as_mut() {
        Some(wallet_data) => wallet_data,
        None => {
            log::warn!("no wallet_data, drop the UI response");
            return;
        }
    };

    let (request, receiver) = match wallet_data.signer_requests.requests.remove(&resp.req_id) {
        Some(req) => req,
        None => {
            log::error!("unknown signer request id");
            return;
        }
    };

    if !resp.accept {
        match receiver {
            Receiver::Web { res_sender } => res_sender.send(Err(SignerError::UserRejected)),
            Receiver::AppLink {
                code,
                upload_url,
                return_url,
            } => {
                let req = match request {
                    Request::Login {} => {
                        signer_backend_api::Req::RejectLogin(signer_backend_api::RejectLoginReq {
                            code,
                            reason: SignerError::UserRejected.to_string(),
                        })
                    }
                    Request::Sign { .. } => {
                        signer_backend_api::Req::RejectSign(signer_backend_api::RejectSignReq {
                            code,
                            reason: SignerError::UserRejected.to_string(),
                        })
                    }
                };
                let _res = send_request_to_upload_url(&upload_url, req);
                handle_return_url(data, return_url);
            }
        }
        return;
    }

    assert!(resp.accept);
    let res = process_accepted_signer_request(data, &request);

    match res {
        Ok(resp) => match receiver {
            Receiver::Web { res_sender } => {
                let resp = match resp {
                    Response::Login { descriptor } => {
                        signer_local_api::Resp::Login(signer_local_api::LoginResp { descriptor })
                    }
                    Response::Sign { pset } => {
                        signer_local_api::Resp::Sign(signer_local_api::SignResp { pset })
                    }
                };
                res_sender.send(Ok(resp));
            }

            Receiver::AppLink {
                code,
                upload_url,
                return_url,
            } => {
                let request =
                    match resp {
                        Response::Login { descriptor } => signer_backend_api::Req::AcceptLogin(
                            signer_backend_api::AcceptLoginReq { code, descriptor },
                        ),
                        Response::Sign { pset } => {
                            signer_backend_api::Req::AcceptSign(signer_backend_api::AcceptSignReq {
                                code,
                                pset,
                            })
                        }
                    };
                let _res = send_request_to_upload_url(&upload_url, request);
                handle_return_url(data, return_url);
            }
        },

        Err(err) => match receiver {
            Receiver::Web { res_sender } => res_sender.send(Err(err)),

            Receiver::AppLink {
                code,
                upload_url,
                return_url,
            } => {
                let req = match request {
                    Request::Login {} => {
                        signer_backend_api::Req::RejectLogin(signer_backend_api::RejectLoginReq {
                            code,
                            reason: err.to_string(),
                        })
                    }
                    Request::Sign { .. } => {
                        signer_backend_api::Req::RejectSign(signer_backend_api::RejectSignReq {
                            code,
                            reason: err.to_string(),
                        })
                    }
                };
                let _res = send_request_to_upload_url(&upload_url, req);
                handle_return_url(data, return_url);
            }
        },
    }
}

fn process_accepted_signer_request(
    data: &mut Data,
    req: &Request,
) -> Result<Response, SignerError> {
    let wallet_data = data.wallet_data.as_mut().ok_or(SignerError::NoWalletData)?;

    match req {
        Request::Login {} => {
            let descriptor = wallet_data
                .wallet_reg
                .default_account()
                .descriptor()
                .to_string();

            Ok(Response::Login { descriptor })
        }

        Request::Sign { pset } => {
            let mut pset = PartiallySignedTransaction::from_str(&pset)?;

            match &wallet_data.wallet_reg.login_info().wallet_info {
                WalletInfo::Mnemonic(mnemonic) => {
                    use lwk_common::Signer;
                    let signer =
                        lwk_signer::SwSigner::new(&mnemonic.to_string(), data.env.d().mainnet)
                            .expect("signer creation failed");

                    signer.sign(&mut pset)?;

                    Ok(Response::Sign {
                        pset: pset.to_string(),
                    })
                }

                WalletInfo::Jade(_jade, watch_only) => {
                    let my_fingerprint = watch_only.master_xpub_fingerprint;

                    let pset = try_sign_pset_jade(data, pset, my_fingerprint)
                        .map_err(SignerError::Jade)?;

                    Ok(Response::Sign {
                        pset: pset.to_string(),
                    })
                }
            }
        }
    }
}

fn send_request_to_upload_url(
    upload_url: &url::Url,
    req: signer_backend_api::Req,
) -> Result<signer_backend_api::Resp, anyhow::Error> {
    let resp = ureq::post(&upload_url.to_string())
        .timeout(Duration::from_secs(10))
        .send_json(req)
        .context("sending request failed")?;
    let status = resp.status();
    let resp = resp.into_string()?;
    ensure!(status == 200, "invalid http status: {status}: resp: {resp}");
    let resp = serde_json::from_str::<signer_backend_api::Resp>(&resp)?;
    Ok(resp)
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

    let sign_tx = sideswap_jade::models::ReqSignTx {
        network,
        use_ae_signatures: true,
        txn: ByteBuf::from(tx_bin),
        num_inputs: tx.input.len() as u32,
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
