use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure};
use futures::{SinkExt, StreamExt};
use sideswap_types::retry_delay::RetryDelay;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time::interval,
};
use tokio_tungstenite::tungstenite::Message;
use tungstenite::Utf8Bytes;

#[derive(Debug)]
pub enum Command {
    ConnectAck,
    Send { data: Utf8Bytes },
}

#[derive(Debug)]
pub enum Event {
    Connected,
    Recv { text: Utf8Bytes },
    Disconnected,
}

pub struct WsClient {
    command_sender: mpsc::UnboundedSender<Command>,
    app_active_sender: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

pub type EventCb = Box<dyn Fn(Event) + Send + Sync>;

struct Data {
    url: String,
    command_receiver: mpsc::UnboundedReceiver<Command>,
    app_active_receiver: watch::Receiver<bool>,
    event_cb: EventCb,
}

struct ConnData {
    conn: Connection,
    last_received: Instant,
    app_active_ping_sent_at: Option<Instant>,
}

impl WsClient {
    pub fn new(url: String, runtime: &tokio::runtime::Handle, event_cb: EventCb) -> Self {
        let (command_sender, command_receiver) = mpsc::unbounded_channel::<Command>();
        let (app_active_sender, app_active_receiver) = watch::channel(true);

        let data = Data {
            url,
            command_receiver,
            app_active_receiver,
            event_cb,
        };

        let handle = runtime.spawn(run(data));

        Self {
            command_sender,
            app_active_sender,
            handle,
        }
    }

    pub fn send_command(&self, command: Command) {
        self.command_sender.send(command).expect("must be open");
    }

    /// This should be used in mobile apps only.
    /// Automatic reconnection is disabled if the app is inactive.
    /// A ping is sent to check the connection once the app resumes.
    pub fn set_app_active(&self, is_active: bool) {
        self.app_active_sender
            .send(is_active)
            .expect("must be open");
    }
}

impl Drop for WsClient {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

type Connection =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(data: &mut Data) -> Result<Connection, anyhow::Error> {
    let (conn, _resp) = tokio::time::timeout(
        Duration::from_secs(30),
        tokio_tungstenite::connect_async(&data.url),
    )
    .await??;
    Ok(conn)
}

async fn handle_command(conn: &mut ConnData, cmd: Command) -> Result<(), anyhow::Error> {
    match cmd {
        Command::Send { data } => {
            conn.conn.send(Message::Text(data)).await?;
        }
        Command::ConnectAck => {
            log::error!("unexpected ConnectAck, fix the code!");
        }
    }
    Ok(())
}

fn handle_recv_msg(
    conn: &mut ConnData,
    data: &mut Data,
    msg: Message,
) -> Result<(), anyhow::Error> {
    conn.last_received = Instant::now();

    match msg {
        Message::Text(text) => {
            (data.event_cb)(Event::Recv { text });
            Ok(())
        }
        Message::Binary(_bytes) => Err(anyhow!("unexpected binary message received")),
        Message::Ping(_bytes) => Ok(()),
        Message::Pong(_bytes) => {
            conn.app_active_ping_sent_at = None;
            Ok(())
        }
        Message::Close(close_frame) => Err(anyhow!("close frame received: {close_frame:?}")),
        Message::Frame(_frame) => {
            // Tungstenite handles frames internally
            Err(anyhow!("unexpected frame received"))
        }
    }
}

async fn handle_tick_interval(conn: &mut ConnData) -> Result<(), anyhow::Error> {
    if conn.last_received.elapsed() > Duration::from_secs(60) {
        conn.conn.send(Message::Ping(Default::default())).await?;
    }
    if let Some(reconnect_ping_sent_at) = conn.app_active_ping_sent_at {
        ensure!(
            reconnect_ping_sent_at.elapsed() < Duration::from_secs(15),
            "reconnect ping timeout"
        );
    }
    if conn.last_received.elapsed() > Duration::from_secs(90) {
        bail!("ping timeout");
    }
    Ok(())
}

async fn handle_app_active_changed(
    data: &mut Data,
    conn: &mut ConnData,
) -> Result<(), anyhow::Error> {
    let app_active = *data.app_active_receiver.borrow_and_update();
    if app_active {
        conn.conn.send(Message::Ping(Default::default())).await?;
        conn.app_active_ping_sent_at = Some(Instant::now());
    }
    Ok(())
}

async fn handle_connection(data: &mut Data, conn: Connection) -> Result<(), anyhow::Error> {
    let mut conn = ConnData {
        conn,
        last_received: Instant::now(),
        app_active_ping_sent_at: None,
    };

    let mut ping_interval = interval(Duration::from_secs(15));
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            res = conn.conn.next() => {
                match res {
                    Some(Ok(msg)) => handle_recv_msg(&mut conn, data, msg)?,
                    Some(Err(err)) => bail!("connection failed: {err}"),
                    None => break Ok(()),
                }
            },

            cmd = data.command_receiver.recv() => {
                match cmd {
                    Some(cmd) => handle_command(&mut conn, cmd).await?,
                    None => break Ok(()),
                }
            },

            _ = ping_interval.tick() => {
                handle_tick_interval(&mut conn).await?;
            },

            res = data.app_active_receiver.changed() => {
                match res {
                    Ok(()) => handle_app_active_changed(data, &mut conn).await?,
                    Err(_err) => break Ok(()),
                }
            },
        }
    }
}

async fn run(mut data: Data) {
    let mut reconnect_delay = RetryDelay::default();

    while !data.command_receiver.is_closed() {
        let app_active = *data.app_active_receiver.borrow_and_update();

        if !app_active {
            let res = data.app_active_receiver.changed().await;
            if res.is_err() {
                break;
            }
            continue;
        }

        log::debug!("start connection to {url}", url = data.url);
        let res = connect(&mut data).await;

        match res {
            Ok(conn) => {
                let connected_at = Instant::now();

                log::debug!("connected to {url}", url = data.url);
                (data.event_cb)(Event::Connected);

                // Wait until Command::ConnectAck is received to drop old messages
                loop {
                    let msg = data.command_receiver.recv().await;
                    match msg {
                        Some(msg) => match msg {
                            Command::ConnectAck => break,
                            Command::Send { data: _ } => {}
                        },
                        None => break,
                    }
                }

                let res = handle_connection(&mut data, conn).await;

                match res {
                    Ok(()) => log::debug!("connection closed normally"),
                    Err(err) => log::debug!("connection closed with error: {err}"),
                }

                if connected_at.elapsed() > Duration::from_secs(60) {
                    reconnect_delay.reset();
                }

                (data.event_cb)(Event::Disconnected);
            }

            Err(err) => {
                log::debug!("connection failed: {err}, url: {url}", url = data.url);
                tokio::time::sleep(reconnect_delay.next_delay()).await;
            }
        }
    }
}
