use std::sync::mpsc;

use axum::{extract::State, routing::get};
use sideswap_types::env::Env;

use crate::worker::Message;

pub struct WebServer {}

impl WebServer {
    pub fn new(env: Env, msg_sender: mpsc::Sender<Message>) -> Self {
        std::thread::spawn(move || {
            run(env, msg_sender);
        });

        Self {}
    }
}

async fn health(State(msg_sender): State<mpsc::Sender<Message>>) -> String {
    "NoError".to_owned()
}

pub async fn try_run(env: Env, msg_sender: mpsc::Sender<Message>) -> Result<(), anyhow::Error> {
    let enabled = match env {
        Env::Prod => false,
        Env::Testnet | Env::LocalLiquid | Env::LocalTestnet | Env::LocalRegtest => true,
    };
    if !enabled {
        // FIXME: Start the web server if the user allow it
        log::debug!("web server is not allowed");
        return Ok(());
    }

    let app = axum::Router::new()
        .route("/health", get(health))
        .with_state(msg_sender);

    let addr: std::net::SocketAddr = ([127, 0, 0, 3], env.d().wallet_port).into();

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}

pub fn run(env: Env, msg_sender: mpsc::Sender<Message>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("must not fail");

    let res = runtime.block_on(try_run(env, msg_sender));

    if let Err(err) = res {
        log::error!("web server failed: {err}");
    }
}
