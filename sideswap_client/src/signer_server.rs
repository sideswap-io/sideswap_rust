use std::sync::{Arc, mpsc};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{
        HeaderName, HeaderValue, Method, Request,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::IntoResponse,
    routing::post,
};
use sideswap_common::target_os::TargetOs;
use sideswap_types::{env::Env, retry_delay::RetryDelay};
use tokio::net::TcpSocket;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;

use crate::worker::Message;

pub struct SignerServer {
    cancel_token: CancellationToken,
}

pub struct Params {
    pub env: Env,
    pub msg_sender: mpsc::Sender<Message>,
    pub whitelisted_domains: Vec<String>,
}

pub struct WebRequest {
    pub app_link: String,
}

impl SignerServer {
    pub fn new(runtime: &tokio::runtime::Runtime, params: Params) -> Self {
        let cancel_token = CancellationToken::new();

        runtime.spawn(run(params, cancel_token.clone()));

        Self { cancel_token }
    }
}

impl Drop for SignerServer {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

async fn app_link(State(params): State<Arc<Params>>, app_link: String) {
    let _ = params
        .msg_sender
        .send(Message::SignerRequest(WebRequest { app_link }));
}

fn build_cors(allow_origin: tower_http::cors::AllowOrigin) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
}

async fn allow_private_network_header(req: Request<Body>, next: Next) -> impl IntoResponse {
    let mut res = next.run(req).await;
    // Chrome looks for this on the preflight response. Harmless on other responses.
    res.headers_mut().insert(
        HeaderName::from_static("access-control-allow-private-network"),
        HeaderValue::from_static("true"),
    );
    res
}

fn try_bind_socket(addr: std::net::SocketAddr) -> Result<tokio::net::TcpListener, anyhow::Error> {
    let sock = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    sock.set_reuseaddr(true)?;
    sock.bind(addr)?;

    let listener = sock.listen(128)?;

    Ok(listener)
}

async fn bind_socket_with_retry(addr: std::net::SocketAddr) -> tokio::net::TcpListener {
    let mut retry_delay = RetryDelay::default();

    loop {
        let res = try_bind_socket(addr);

        match res {
            Ok(listener) => return listener,

            Err(err) => {
                log::debug!("signer port bind failed: {err}");
                tokio::time::sleep(retry_delay.next_delay()).await;
            }
        }
    }
}

pub fn is_dev_env(env: Env) -> bool {
    match env {
        sideswap_types::env::Env::Prod => false,
        sideswap_types::env::Env::Testnet
        | sideswap_types::env::Env::LocalLiquid
        | sideswap_types::env::Env::LocalTestnet
        | sideswap_types::env::Env::LocalRegtest => true,
    }
}

pub async fn try_run(params: Params, cancel_token: CancellationToken) -> Result<(), anyhow::Error> {
    let env = params.env;

    let enabled = match TargetOs::get() {
        TargetOs::Linux | TargetOs::Windows | TargetOs::MacOs => true,
        TargetOs::Android | TargetOs::IOS => false,
    };

    if !enabled {
        log::debug!("web server is not allowed");
        return Ok(());
    }

    let is_dev_env = is_dev_env(env);

    let cors_origins = if !is_dev_env {
        tower_http::cors::AllowOrigin::list(
            params
                .whitelisted_domains
                .iter()
                .filter_map(|domain| HeaderValue::from_str(&format!("https://{domain}")).ok()),
        )
    } else {
        tower_http::cors::AllowOrigin::any()
    };

    let app = Router::new()
        .route("/app_link", post(app_link))
        .with_state(Arc::new(params))
        // Order: CORS first so it can short-circuit OPTIONS;
        // the PNA header still gets added after by the middleware.
        .layer(build_cors(cors_origins))
        .layer(middleware::from_fn(allow_private_network_header));

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], env.nd().wallet_port));

    let listener = tokio::select! {
        listener = bind_socket_with_retry(addr) => {
            listener
        },

        () = cancel_token.cancelled() => {
            return Ok(());
        },
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(cancel_token.cancelled_owned())
        .await?;

    Ok(())
}

pub async fn run(params: Params, cancel_token: CancellationToken) {
    let res = try_run(params, cancel_token).await;

    if let Err(err) = res {
        log::error!("web server failed: {err}");
    }
}
