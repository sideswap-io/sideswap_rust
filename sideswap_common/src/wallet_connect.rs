use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use anyhow::{Context as _, anyhow, bail, ensure};
use sideswap_api::connect_api;
use sideswap_types::env::Env;

use crate::{wallet_key::WalletKey, ws_client};

pub enum LinkType {
    Login,
    Sign,
}

pub struct AppLink {
    pub link_type: LinkType,
    pub request_id: String,
    pub is_mobile: bool,
}

pub enum Input {
    Transport {
        event: ws_client::Event,
    },

    AppLink {
        app_link: AppLink,
    },

    LoginAccepted {
        request_id: String,
    },

    LoginRejected {
        request_id: String,
    },

    SignAccepted {
        request_id: String,
        signed_pset: String,
    },

    SignRejected {
        request_id: String,
    },

    RegisterFcmToken {
        token: String,
    },

    StopSession {
        session_id: String,
    },
}

pub enum Effect {
    Transport { command: ws_client::Command },

    AddLoginRequest { request: connect_api::LoginRequest },
    RemoveLoginRequest { request_id: String },

    AddSignRequest { request: connect_api::SignRequest },
    RemoveSignRequest { request_id: String },

    SessionList { sessions: Vec<connect_api::Session> },
    SessionCreated { session: connect_api::Session },
    SessionRemoved { session_id: String },

    MinimizeMobileApp,
}

pub struct WalletConnectCore {
    install_id: connect_api::InstallId,
    connected: bool,
    login_succeed: bool,

    descriptor: String,
    wallet_key: WalletKey,

    login_requests: BTreeMap<String, connect_api::LoginRequest>,
    sign_requests: BTreeMap<String, connect_api::SignRequest>,

    user_actions: BTreeMap<connect_api::ReqId, connect_api::UserAction>,
    next_action_id: connect_api::ReqId,

    mobile_requests: BTreeSet<String>,

    fcm_token: Option<String>,
}

pub fn get_connect_server_url(env: Env) -> &'static str {
    match env {
        Env::Prod => "wss://api.sideswap.io/wallet-connect",
        Env::Testnet => "wss://api-testnet.sideswap.io/wallet-connect",
        Env::LocalLiquid => "ws://127.0.0.1:51225",
        Env::LocalTestnet => "ws://127.0.0.1:51235",
        Env::LocalRegtest => "ws://127.0.0.1:51245",
    }
}

fn send(id: connect_api::ReqId, req: connect_api::Req) -> Effect {
    let to = connect_api::To::Req { id, req };
    let data = serde_json::to_string(&to).expect("must not fail");
    Effect::Transport {
        command: ws_client::Command::Send { data: data.into() },
    }
}

pub fn parse_app_link(url: &str) -> Result<AppLink, anyhow::Error> {
    let url = url::Url::parse(url)?;

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

    let link_type = match (url.scheme(), domain, url.path()) {
        ("https", "app.sideswap.io", "/login/") | ("liquidconnect", "login", "/") => {
            LinkType::Login
        }
        ("https", "app.sideswap.io", "/sign/") | ("liquidconnect", "sign", "/") => LinkType::Sign,
        _ => bail!("unsupported URL: {url}"),
    };

    Ok(AppLink {
        link_type,
        request_id,
        is_mobile,
    })
}

impl WalletConnectCore {
    pub fn new(
        install_id: connect_api::InstallId,
        descriptor: String,
        wallet_key: WalletKey,
    ) -> Self {
        Self {
            install_id,
            connected: false,
            login_succeed: false,
            descriptor,
            wallet_key,
            login_requests: BTreeMap::new(),
            sign_requests: BTreeMap::new(),
            user_actions: BTreeMap::new(),
            next_action_id: 0,
            mobile_requests: BTreeSet::new(),
            fcm_token: None,
        }
    }

    fn sync_sign_requests(
        &mut self,
        sign_requests: Vec<connect_api::SignRequest>,
        effects: &mut Vec<Effect>,
    ) {
        let old_request_ids = self.sign_requests.keys().cloned().collect::<BTreeSet<_>>();
        let new_request_ids = sign_requests
            .iter()
            .map(|req| req.request_id.clone())
            .collect::<BTreeSet<_>>();

        for req_id in old_request_ids.difference(&new_request_ids) {
            self.sign_requests.remove(req_id);
            effects.push(Effect::RemoveSignRequest {
                request_id: req_id.clone(),
            });
        }

        for sign_req in sign_requests {
            if !self.sign_requests.contains_key(&sign_req.request_id) {
                self.sign_requests
                    .insert(sign_req.request_id.clone(), sign_req.clone());
                effects.push(Effect::AddSignRequest { request: sign_req });
            }
        }
    }

    fn handle_response(
        &mut self,
        id: connect_api::ReqId,
        resp: connect_api::Resp,
        effects: &mut Vec<Effect>,
    ) {
        match resp {
            connect_api::Resp::Challenge(resp) => {
                effects.push(send(
                    0,
                    connect_api::Req::Login(connect_api::LoginReq {
                        public_key: self.wallet_key.public_key(),
                        signature: self.wallet_key.sign_challenge(&resp.challenge),
                        install_id: Some(self.install_id),
                    }),
                ));
            }

            connect_api::Resp::Login(connect_api::LoginResp {
                sessions,
                sign_requests,
            }) => {
                self.login_succeed = true;

                for (&req_id, action) in &self.user_actions {
                    effects.push(send(
                        req_id,
                        connect_api::Req::UserAction(connect_api::UserActionReq {
                            action: action.clone(),
                        }),
                    ));
                }

                self.sync_sign_requests(sign_requests, effects);
                effects.push(Effect::SessionList { sessions });
                self.send_fcm_token(effects);
            }

            connect_api::Resp::UserAction(_) => {
                self.user_actions.remove(&id);
            }

            connect_api::Resp::RegisterFcm(_) => {}
        }
    }

    fn handle_notification(&mut self, notif: connect_api::Notif, effects: &mut Vec<Effect>) {
        match notif {
            connect_api::Notif::SessionCreated(notif) => {
                effects.push(Effect::SessionCreated {
                    session: notif.session,
                });
            }

            connect_api::Notif::SessionRemoved(notif) => {
                effects.push(Effect::SessionRemoved {
                    session_id: notif.session_id,
                });
            }

            connect_api::Notif::LoginRequestCreated(notif) => {
                self.login_requests
                    .insert(notif.request.request_id.clone(), notif.request.clone());

                effects.push(Effect::AddLoginRequest {
                    request: notif.request,
                });
            }

            connect_api::Notif::LoginRequestRemoved(notif) => {
                self.login_requests.remove(&notif.request_id);
                effects.push(Effect::RemoveLoginRequest {
                    request_id: notif.request_id,
                });
            }

            connect_api::Notif::SignRequestCreated(notif) => {
                self.sign_requests
                    .insert(notif.request.request_id.clone(), notif.request.clone());

                effects.push(Effect::AddSignRequest {
                    request: notif.request,
                });
            }

            connect_api::Notif::SignRequestRemoved(n) => {
                self.sign_requests.remove(&n.request_id);
                effects.push(Effect::RemoveSignRequest {
                    request_id: n.request_id,
                });
            }
        }
    }

    fn add_user_action(&mut self, action: connect_api::UserAction, effects: &mut Vec<Effect>) {
        let id = self.next_action_id;
        self.next_action_id += 1;

        self.user_actions.insert(id, action.clone());

        if self.connected {
            effects.push(send(
                id,
                connect_api::Req::UserAction(connect_api::UserActionReq { action }),
            ));
        }
    }

    fn handle_server_message(&mut self, from: connect_api::From, effects: &mut Vec<Effect>) {
        match from {
            connect_api::From::Resp { id, resp } => {
                self.handle_response(id, resp, effects);
            }

            connect_api::From::Error { id, err } => {
                log::debug!("wallet-connect request failed: id={id}, err={err:?}");
            }

            connect_api::From::Notif { notif } => {
                self.handle_notification(notif, effects);
            }
        }
    }

    fn finish_request(&mut self, request_id: String, effects: &mut Vec<Effect>) {
        if self.mobile_requests.remove(&request_id) {
            effects.push(Effect::MinimizeMobileApp);
        }
    }

    fn send_fcm_token(&mut self, effects: &mut Vec<Effect>) {
        if let Some(token) = self.fcm_token.as_ref() {
            if self.connected && self.login_succeed {
                effects.push(send(
                    0,
                    connect_api::Req::RegisterFcm(connect_api::RegisterFcmReq {
                        token: token.clone(),
                    }),
                ));
            }
        }
    }

    pub fn handle(&mut self, input: Input) -> Vec<Effect> {
        let mut effects = Vec::new();

        match input {
            Input::Transport { event } => match event {
                ws_client::Event::Connected => {
                    self.connected = true;
                    effects.push(Effect::Transport {
                        command: ws_client::Command::ConnectAck,
                    });
                    effects.push(send(
                        0,
                        connect_api::Req::Challenge(connect_api::ChallengeReq {}),
                    ));
                }
                ws_client::Event::Recv { text } => {
                    let res = serde_json::from_str::<connect_api::From>(&text);
                    match res {
                        Ok(from) => {
                            self.handle_server_message(from, &mut effects);
                        }
                        Err(err) => {
                            log::error!("invalid server response: {err}");
                        }
                    }
                }
                ws_client::Event::Disconnected => {
                    self.connected = false;
                    self.login_succeed = false;
                }
            },

            Input::LoginAccepted { request_id } => {
                self.add_user_action(
                    connect_api::UserAction::AcceptLoginRequest {
                        request_id: request_id.clone(),
                        descriptor: self.descriptor.clone(),
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::LoginRejected { request_id } => {
                self.add_user_action(
                    connect_api::UserAction::CancelLoginRequest {
                        request_id: request_id.clone(),
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::SignAccepted {
                request_id,
                signed_pset,
            } => {
                self.add_user_action(
                    connect_api::UserAction::AcceptSignRequest {
                        request_id: request_id.clone(),
                        pset: signed_pset,
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::SignRejected { request_id } => {
                self.add_user_action(
                    connect_api::UserAction::CancelSignRequest {
                        request_id: request_id.clone(),
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::RegisterFcmToken { token } => {
                self.fcm_token = Some(token.clone());
                self.send_fcm_token(&mut effects);
            }

            Input::StopSession { session_id } => {
                self.add_user_action(
                    connect_api::UserAction::StopSession { session_id },
                    &mut effects,
                );
            }

            Input::AppLink {
                app_link:
                    AppLink {
                        link_type,
                        request_id,
                        is_mobile,
                    },
            } => {
                if is_mobile {
                    self.mobile_requests.insert(request_id.clone());
                }

                match link_type {
                    LinkType::Login => {
                        self.add_user_action(
                            connect_api::UserAction::LinkLoginRequest { request_id },
                            &mut effects,
                        );
                    }
                    LinkType::Sign => {
                        // Do nothing, handled via incoming sign requests
                    }
                }
            }
        }

        effects
    }
}
