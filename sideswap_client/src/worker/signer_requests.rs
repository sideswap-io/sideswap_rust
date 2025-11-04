use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, anyhow, bail, ensure};
use elements::pset::PartiallySignedTransaction;
use sideswap_common::channel_helpers::UncheckedOneshotSender;
use sideswap_jade::jade_mng;
use sideswap_types::{signer_backend_api, signer_local_api};

use crate::{
    ffi::proto,
    gdk_ses::{GdkSes, WalletInfo},
    signer_server::{SignerError, WebRequest},
    worker::{Data, SignerReqId},
};

enum Request {
    Login {},
    Sign {
        pset: String,
        blinding_nonces: Option<Vec<String>>,
    },
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
        upload_url: String,
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

        Request::Sign {
            pset,
            blinding_nonces: _,
        } => {
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
        .ok_or_else(|| anyhow!("invalid link: no upload_url query parameter"))?
        .clone();

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

            let (pset, blinding_nonces) =
                if let signer_backend_api::Resp::StartSign(signer_backend_api::StartSignResp {
                    pset,
                    blinding_nonces,
                }) = resp
                {
                    (pset, blinding_nonces)
                } else {
                    bail!("unexpected response, expected GetPset")
                };

            Request::Sign {
                pset,
                blinding_nonces,
            }
        }

        _ => bail!("unknown path: {path}", path = url.path()),
    };

    let req_id = try_send_new_request(data, upload_url.clone(), &request)?;

    let wallet_data = data.wallet_data.as_mut().ok_or(SignerError::NoWalletData)?;

    let receiver = Receiver::AppLink { code, upload_url };

    wallet_data
        .signer_requests
        .requests
        .insert(req_id, (request, receiver));

    Ok(())
}

pub fn new_web_request(data: &mut Data, req: WebRequest) {
    let request = match req.req {
        signer_local_api::Req::Login(_req) => Request::Login {},
        signer_local_api::Req::Sign(req) => Request::Sign {
            pset: req.pset,
            blinding_nonces: req.blinding_nonces,
        },
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
    let res = try_process_app_link(data, &resp);
    if let Err(err) = res {
        data.show_message(&format!("invalid url link: {url}: {err}", url = &resp.url));
    }
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
            Receiver::AppLink { code, upload_url } => {
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
            }
        }
        return;
    }

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

            Receiver::AppLink { code, upload_url } => {
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
            }
        },

        Err(err) => match receiver {
            Receiver::Web { res_sender } => res_sender.send(Err(err)),

            Receiver::AppLink { code, upload_url } => {
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

        Request::Sign {
            pset,
            blinding_nonces,
        } => {
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

                WalletInfo::Jade(_jade, _watch_only) => {
                    let pset = crate::worker::market_worker::try_sign_pset_jade(
                        data,
                        &[],
                        &[],
                        &[],
                        None,
                        pset,
                        BTreeSet::new(),
                        blinding_nonces.as_ref(),
                        jade_mng::TxType::Normal,
                    )
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
    upload_url: &str,
    req: signer_backend_api::Req,
) -> Result<signer_backend_api::Resp, anyhow::Error> {
    let resp = ureq::post(&upload_url)
        .timeout(Duration::from_secs(10))
        .send_json(req)
        .context("sending request failed")?;
    let status = resp.status();
    let resp = resp.into_string()?;
    ensure!(status == 200, "invalid http status: {status}: resp: {resp}");
    let resp = serde_json::from_str::<signer_backend_api::Resp>(&resp)?;
    Ok(resp)
}
