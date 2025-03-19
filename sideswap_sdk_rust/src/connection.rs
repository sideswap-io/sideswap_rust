use std::sync::Mutex;

use sideswap_api::mkt;
use sideswap_common::{
    channel_helpers::UncheckedOneshotSender,
    env::Env,
    ws::{
        auto::{WrappedRequest, WrappedResponse},
        ws_req_sender::WsReqSender,
    },
};
use tokio::{
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
    task::JoinHandle,
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Backend error: {0}")]
    Backend(sideswap_api::Error),
    #[error("Channel closed")]
    ChannelClosed,
}

impl From<tokio::sync::oneshot::error::RecvError> for Error {
    fn from(_value: tokio::sync::oneshot::error::RecvError) -> Self {
        Error::ChannelClosed
    }
}

pub struct Params {
    pub env: Env,
    pub api_key: Option<String>,
    pub user_agent: String,
    pub version: String,
}

pub enum Event {
    Connected,
    Disconnected,
}

pub enum Command {
    State {
        active: bool,
    },
    StartSwap {
        res_sender: UncheckedOneshotSender<Result<String, Error>>,
    },
}

pub type EventCallback = Box<dyn FnMut(Event) + Send>;

pub struct Connection {
    command_sender: UnboundedSender<Command>,
    command_receiver: Mutex<Option<UnboundedReceiver<Command>>>,
}

impl Connection {
    pub fn new() -> Connection {
        let (command_sender, command_receiver) = unbounded_channel();

        Connection {
            command_sender,
            command_receiver: Mutex::new(Some(command_receiver)),
        }
    }

    pub fn start(
        &self,
        params: Params,
        runtime: &tokio::runtime::Handle,
        event_callback: EventCallback,
    ) {
        let command_receiver = self
            .command_receiver
            .lock()
            .expect("must not fail")
            .take()
            .expect("start can be called just once");

        runtime.spawn(run(params, command_receiver, event_callback));
    }

    pub fn state(&self, active: bool) {
        self.send_command(Command::State { active });
    }

    pub async fn start_swap(&self) -> Result<String, Error> {
        let (res_sender, res_receiver) = oneshot::channel();
        self.send_command(Command::StartSwap {
            res_sender: res_sender.into(),
        });
        let resp = res_receiver.await??;
        Ok(resp)
    }

    fn send_command(&self, command: Command) {
        self.command_sender
            .send(command)
            .expect("channel must be open");
    }
}

struct Data {
    params: Params,
    event_callback: EventCallback,
    ws: Option<Ws>,
}

struct Ws {
    req_sender: WsReqSender,
    handle: JoinHandle<()>,
}

async fn process_command(data: &mut Data, command: Command) {
    match command {
        Command::State { active } => {
            if active {
                start_ws(data);
            } else {
                stop_ws(data);
            }
        }
        Command::StartSwap { res_sender } => {
            res_sender.send(Ok("123".to_owned()));
        }
    }
}

fn send_event(data: &mut Data, event: Event) {
    (data.event_callback)(event);
}

fn start_ws(data: &mut Data) {
    if data.ws.is_none() {
        let server_url = data.params.env.base_server_ws_url();
        let (req_sender, req_receiver) = unbounded_channel::<WrappedRequest>();
        let (resp_sender, resp_receiver) = unbounded_channel::<WrappedResponse>();
        let handle = tokio::spawn(sideswap_common::ws::auto::run(
            server_url.clone(),
            req_receiver,
            resp_sender,
        ));
        let req_sender = WsReqSender::new(req_sender, resp_receiver);
        data.ws = Some(Ws { req_sender, handle });
    }
}

fn stop_ws(data: &mut Data) {
    if let Some(ws) = data.ws.as_ref() {
        let was_connected = ws.req_sender.connected();

        ws.handle.abort();
        data.ws = None;

        if was_connected {
            send_event(data, Event::Disconnected);
        }
    }
}

async fn ws_resp(data: &mut Data) -> WrappedResponse {
    match data.ws.as_mut() {
        Some(ws) => ws.req_sender.recv().await,
        None => std::future::pending().await,
    }
}

fn process_market_resp(data: &mut Data, resp: mkt::Response) {
    match resp {
        mkt::Response::ListMarkets(resp) => {}
        _ => {}
    }
}

fn process_ws_resp(data: &mut Data, resp: sideswap_api::Response) {
    match resp {
        sideswap_api::Response::Market(resp) => process_market_resp(data, resp),
        _ => {}
    }
}

fn process_market_notif(data: &mut Data, notif: mkt::Notification) {
    match notif {
        // mkt::Notification::MarketAdded(_notif) => {}
        // mkt::Notification::MarketRemoved(_notif) => {}
        _ => {}
    }
}

fn process_ws_notif(data: &mut Data, notif: sideswap_api::Notification) {
    match notif {
        sideswap_api::Notification::Market(notif) => process_market_notif(data, notif),
        _ => {}
    }
}

fn process_ws_event(data: &mut Data, event: WrappedResponse) {
    match event {
        WrappedResponse::Connected => {
            send_event(data, Event::Connected);

            let ws = data.ws.as_mut().expect("ws must be set");

            ws.req_sender
                .send_request(sideswap_api::Request::LoginClient(
                    sideswap_api::LoginClientRequest {
                        api_key: data.params.api_key.clone(),
                        cookie: None,
                        user_agent: data.params.user_agent.clone(),
                        version: data.params.version.clone(),
                    },
                ));

            ws.req_sender
                .send_request(sideswap_api::Request::Market(mkt::Request::ListMarkets(
                    mkt::ListMarketsRequest {},
                )));
        }

        WrappedResponse::Disconnected => {
            send_event(data, Event::Disconnected);
        }

        WrappedResponse::Response(resp) => match resp {
            sideswap_api::ResponseMessage::Response(_req_id, resp) => match resp {
                Ok(resp) => process_ws_resp(data, resp),
                Err(err) => {
                    log::error!("ws request failed: {}", err.message);
                }
            },
            sideswap_api::ResponseMessage::Notification(notif) => {
                process_ws_notif(data, notif);
            }
        },
    }
}

async fn run(
    params: Params,
    mut command_receiver: UnboundedReceiver<Command>,
    event_callback: EventCallback,
) {
    let mut data = Data {
        params,
        event_callback,
        ws: None,
    };

    start_ws(&mut data);

    loop {
        tokio::select! {
            command = command_receiver.recv() => {
                match command {
                    Some(command) => {
                        process_command(&mut data, command).await;
                    },
                    None => {
                        log::debug!("stop connection loop");
                        break;
                    },
                }
            },

            event = ws_resp(&mut data) => {
                process_ws_event(&mut data, event);
            },
        }
    }
}
