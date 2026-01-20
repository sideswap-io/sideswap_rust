use lwk_wollet::WolletDescriptor;
use sideswap_api::connect_api;
use sideswap_common::{
    wallet_key::WalletKey,
    ws_client::{self, WsClient},
};
use sideswap_types::env::Env;

use super::Data;

pub struct WalletConnect {
    descriptor: WolletDescriptor,
    wallet_key: WalletKey,
    client: WsClient,
}

pub fn new(data: &mut Data, descriptor: &WolletDescriptor) -> WalletConnect {
    // FIXME: Use correct URLs
    let connect_server_url = match data.env {
        Env::Prod => "ws://127.0.0.1:51235",
        Env::Testnet => "ws://127.0.0.1:51235",
        Env::LocalLiquid => "ws://127.0.0.1:51235",
        Env::LocalTestnet => "ws://127.0.0.1:51235",
        Env::LocalRegtest => "ws://127.0.0.1:51235",
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
        descriptor: descriptor.clone(),
        wallet_key,
        client,
    }
}

fn send_request(connect: &WalletConnect, id: connect_api::ReqId, req: connect_api::Req) {
    let data = serde_json::to_string(&connect_api::To::Req { id, req }).expect("must not fail");

    connect
        .client
        .send_command(ws_client::Command::Send { data: data.into() });
}

fn handle_resp(connect: &WalletConnect, resp: connect_api::Resp) {
    match resp {
        connect_api::Resp::Challenge(resp) => {
            send_request(
                connect,
                0,
                connect_api::Req::Login(connect_api::LoginReq {
                    public_key: connect.wallet_key.public_key(),
                    signature: connect.wallet_key.sign_challenge(&resp.challenge),
                }),
            );
        }
        connect_api::Resp::Login(_resp) => {
            log::debug!("login succeed");
        }
    }
}

fn handle_from(connect: &WalletConnect, from: connect_api::From) {
    match from {
        connect_api::From::Resp { id, resp } => handle_resp(connect, resp),
        connect_api::From::Error { id, err } => {}
        connect_api::From::Notif { notif } => {}
    }
}

pub fn handle_msg(data: &mut Data, event: ws_client::Event) {
    if let Some(wallet) = data.wallet_data.as_mut() {
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
            ws_client::Event::Recv { data } => {
                let res = serde_json::from_slice::<connect_api::From>(data.as_bytes());
                match res {
                    Ok(from) => {
                        handle_from(&wallet.wallet_connect, from);
                    }
                    Err(err) => {
                        log::error!("parsing wallet connect message failed: {err}, msg: {data}");
                    }
                }
            }
            ws_client::Event::Disconnected => {
                log::debug!("wallet connect server is disconnected");
            }
        }
    }
}

pub fn handle_app_state(data: &mut Data) {
    if let Some(wallet) = data.wallet_data.as_mut() {
        wallet.wallet_connect.client.set_app_active(data.app_active);
    }
}
