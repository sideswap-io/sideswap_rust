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
use lwk_wollet::WolletDescriptor;
use sideswap_types::{env::Env, retry_delay::RetryDelay, signer_api};
use tokio::sync::Notify;
use tower_http::cors::CorsLayer;

use crate::worker::Message;

pub struct SignerServer {
    shutdown_notify: Arc<Notify>,
}

pub struct Params {
    pub env: Env,
    pub msg_sender: mpsc::Sender<Message>,
    pub descriptor: WolletDescriptor,
}

impl SignerServer {
    pub fn new(params: Params) -> Self {
        let shutdown_notify = Arc::new(Notify::new());

        let shutdown_notify_copy = Arc::clone(&shutdown_notify);

        std::thread::spawn(move || {
            run(params, shutdown_notify_copy);
        });

        Self { shutdown_notify }
    }
}

impl Drop for SignerServer {
    fn drop(&mut self) {
        self.shutdown_notify.notify_one();
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SignerError {
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
            Json(signer_api::Error {
                error: self.to_string(),
            }),
        )
            .into_response()
    }
}

async fn sign(
    State(params): State<Arc<Params>>,
    Json(req): Json<signer_api::Req>,
) -> Result<Json<signer_api::Resp>, SignerError> {
    match req {
        signer_api::Req::Descriptor(signer_api::DescriptorReq {}) => Ok(Json(
            signer_api::Resp::Descriptor(signer_api::DescriptorResp {
                descr: params.descriptor.to_string(),
            }),
        )),
        signer_api::Req::Sign(sign_req) => {
            let (res_sender, res_receiver) = tokio::sync::oneshot::channel();
            params
                .msg_sender
                .send(Message::SignPset(sign_req.pset, res_sender.into()))?;
            let pset = res_receiver.await??;
            Ok(Json(signer_api::Resp::Sign(signer_api::SignResp { pset })))
        }
    }
}

fn build_cors() -> CorsLayer {
    let origins = [
        "http://localhost:8080",
        "https://swaption.io",
        "https://testnet.swaption.io",
    ];

    let origins = origins
        .into_iter()
        .map(|origin| origin.parse::<HeaderValue>().expect("must be valid"));

    CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        // Add headers you actually need. This is a safe default:
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

pub async fn try_run(params: Params, shutdown_notify: Arc<Notify>) -> Result<(), anyhow::Error> {
    let env = params.env;

    let enabled = match env {
        Env::Prod => false,
        Env::Testnet | Env::LocalLiquid | Env::LocalTestnet | Env::LocalRegtest => true,
    };
    if !enabled {
        // FIXME: Start the web server if the user allow it
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

    let addr: std::net::SocketAddr = ([127, 0, 0, 3], env.d().wallet_port).into();

    let mut retry_delay = RetryDelay::default();

    let listener = loop {
        let res = tokio::select! {
            res = tokio::net::TcpListener::bind(addr) => {
                res
            },

            () = shutdown_notify.notified() => {
                return Ok(());
            },
        };

        match res {
            Ok(listener) => break listener,
            Err(err) => {
                log::error!("signer port bind failed: {err}");
                tokio::time::sleep(retry_delay.next_delay()).await;
            }
        }
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_notify.notified().await;
        })
        .await?;

    Ok(())
}

pub fn run(params: Params, shutdown_notify: Arc<Notify>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("must not fail");

    let res = runtime.block_on(try_run(params, shutdown_notify));

    if let Err(err) = res {
        log::error!("web server failed: {err}");
    }
}
