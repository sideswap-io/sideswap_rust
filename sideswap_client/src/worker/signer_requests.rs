use std::{collections::BTreeMap, str::FromStr, time::Duration};

use anyhow::{Context, anyhow, bail, ensure};
use elements::pset::PartiallySignedTransaction;
use sideswap_common::channel_helpers::UncheckedOneshotSender;
use sideswap_types::{abort, signer_api, signer_backend_api};

use crate::{
    ffi::proto,
    gdk_ses::{GdkSes, WalletInfo},
    signer_server::{self, SignerError, WebRequest},
    worker::{Data, SignerReqId},
};

enum Request {
    Connect {},
    Sign { pset: String },
}

#[derive(Clone)]
enum Response {
    Connect { descriptor: String },
    Sign { pset: String },
}

enum Receiver {
    Web {
        res_sender: UncheckedOneshotSender<Result<signer_api::Resp, SignerError>>,
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
        Request::Connect {} => proto::from::signer_request::Msg::Connect(proto::Empty {}),

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
        .ok_or_else(|| anyhow!("invalid link: no upload_url query parameter"))?
        .clone();

    let code = params
        .get("code")
        .ok_or_else(|| anyhow!("invalid link: no code query parameter"))?
        .clone();

    send_request_to_upload_url(
        &upload_url,
        signer_backend_api::Req::Started(signer_backend_api::StartedReq { code: code.clone() }),
    )?;

    let request = match url.path() {
        "/connect/" => Request::Connect {},

        "/sign/" => todo!(), // FIXME: Download the PSET from the upload_url

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
        signer_api::Req::Descriptor(_req) => Request::Connect {},
        signer_api::Req::Sign(req) => Request::Sign { pset: req.pset },
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
                let _res = send_request_to_upload_url(
                    &upload_url,
                    signer_backend_api::Req::Rejected(signer_backend_api::RejectedReq {
                        code,
                        reason: SignerError::UserRejected.to_string(),
                    }),
                );
            }
        }
        return;
    }

    let res = process_accepted_signer_request(data, request);

    match res {
        Ok(resp) => {
            match receiver {
                Receiver::Web { res_sender } => {
                    let resp = match resp {
                        Response::Connect { descriptor } => {
                            signer_api::Resp::Descriptor(signer_api::DescriptorResp { descriptor })
                        }
                        Response::Sign { pset } => {
                            signer_api::Resp::Sign(signer_api::SignResp { pset })
                        }
                    };
                    res_sender.send(Ok(resp));
                }

                Receiver::AppLink { code, upload_url } => {
                    let request =
                        match resp {
                            Response::Connect { descriptor } => signer_backend_api::Req::Connected(
                                signer_backend_api::ConnectedReq { code, descriptor },
                            ),
                            Response::Sign { pset } => {
                                signer_backend_api::Req::Signed(signer_backend_api::SignedReq {
                                    code,
                                    pset,
                                })
                            }
                        };
                    let _res = send_request_to_upload_url(&upload_url, request);
                }
            }
        }

        Err(err) => match receiver {
            Receiver::Web { res_sender } => res_sender.send(Err(err)),

            Receiver::AppLink { code, upload_url } => {
                let _res = send_request_to_upload_url(
                    &upload_url,
                    signer_backend_api::Req::Rejected(signer_backend_api::RejectedReq {
                        code,
                        reason: err.to_string(),
                    }),
                );
            }
        },
    }
}

fn process_accepted_signer_request(data: &mut Data, req: Request) -> Result<Response, SignerError> {
    let wallet_data = data.wallet_data.as_mut().ok_or(SignerError::NoWalletData)?;

    match req {
        Request::Connect {} => {
            let descriptor = wallet_data
                .wallet_reg
                .default_account()
                .descriptor()
                .to_string();

            Ok(Response::Connect { descriptor })
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

                WalletInfo::Jade(_jade, _watch_only) => {
                    // FIXME: Implement Jade
                    abort!(signer_server::SignerError::JadeNotImplemented);
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
