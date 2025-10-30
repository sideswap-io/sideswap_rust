use std::sync::{Arc, mpsc};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{
        HeaderName, HeaderValue, Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::IntoResponse,
    routing::post,
};
use http::HeaderMap;
use sideswap_common::channel_helpers::UncheckedOneshotSender;
use sideswap_types::{env::Env, retry_delay::RetryDelay, signer_local_api};
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
}

pub struct WebRequest {
    pub origin: String,
    pub req: signer_local_api::Req,
    pub res_sender: UncheckedOneshotSender<Result<signer_local_api::Resp, SignerError>>,
}

impl SignerServer {
    pub fn new(params: Params) -> Self {
        let cancel_token = CancellationToken::new();

        let cancel_token_copy = cancel_token.clone();
        std::thread::spawn(move || {
            run(params, cancel_token_copy);
        });

        Self { cancel_token }
    }
}

impl Drop for SignerServer {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SignerError {
    #[error("user rejected")]
    UserRejected,
    #[error("jade is not implemented")]
    JadeNotImplemented,
    #[error("channel closed")]
    ChannelClosed,
    #[error("invalid PSET: {0}")]
    ParseError(#[from] elements::pset::ParseError),
    #[error("no wallet data")]
    NoWalletData,
    #[error("sign error: {0}")]
    Sign(#[from] lwk_signer::SignError),
    #[error("no origin header set")]
    NoOrigin,
    #[error("invalid header: {0}")]
    ToStrError(#[from] http::header::ToStrError),
    #[error("lwk: {0}")]
    Lwk(#[from] lwk_wollet::Error),
}

impl<T> From<std::sync::mpsc::SendError<T>> for SignerError {
    fn from(_value: std::sync::mpsc::SendError<T>) -> Self {
        SignerError::ChannelClosed
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for SignerError {
    fn from(_value: tokio::sync::oneshot::error::RecvError) -> Self {
        SignerError::ChannelClosed
    }
}

impl IntoResponse for SignerError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::BAD_REQUEST,
            Json(signer_local_api::Error {
                error: self.to_string(),
            }),
        )
            .into_response()
    }
}

async fn sign(
    headers: HeaderMap,
    State(params): State<Arc<Params>>,
    Json(req): Json<signer_local_api::Req>,
) -> Result<Json<signer_local_api::Resp>, SignerError> {
    let origin = headers
        .get(http::header::ORIGIN)
        .ok_or(SignerError::NoOrigin)?
        .to_str()?
        .to_owned();

    let (res_sender, res_receiver) = tokio::sync::oneshot::channel();
    params.msg_sender.send(Message::SignerRequest(WebRequest {
        origin,
        req,
        res_sender: res_sender.into(),
    }))?;
    let resp = res_receiver.await??;

    Ok(Json(resp))
}

fn build_cors() -> CorsLayer {
    // FIXME:
    let origins = [
        "http://localhost:8080",
        "https://sideswap.io",
        "https://testnet.sideswap.io",
        "https://swaption.io",
        "https://testnet.swaption.io",
    ];

    let origins = origins
        .into_iter()
        .map(|origin| origin.parse::<HeaderValue>().expect("must be valid"));

    CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::list(origins))
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

pub async fn try_run(params: Params, cancel_token: CancellationToken) -> Result<(), anyhow::Error> {
    let env = params.env;

    let enabled = true;
    if !enabled {
        // FIXME: Start the web server only if the user allows it
        log::debug!("web server is not allowed");
        return Ok(());
    }

    let app = Router::new()
        .route("/", post(sign))
        .with_state(Arc::new(params))
        // Order: CORS first so it can short-circuit OPTIONS;
        // the PNA header still gets added after by the middleware.
        .layer(build_cors())
        .layer(middleware::from_fn(allow_private_network_header));

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], env.d().wallet_port));

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

pub fn run(params: Params, cancel_token: CancellationToken) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("must not fail");

    let res = runtime.block_on(try_run(params, cancel_token));

    if let Err(err) = res {
        log::error!("web server failed: {err}");
    }
}
