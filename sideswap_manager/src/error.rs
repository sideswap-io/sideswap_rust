use elements::AssetId;
use sideswap_common::{
    b64,
    dealer_ticker::{DealerTicker, InvalidTickerError},
    pset::swap_amount::SwapAmount,
    ws::ws_req_sender,
};
use sideswap_types::asset_precision::AssetPrecision;

use crate::api;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    InvalidTicker(#[from] InvalidTickerError),
    #[error("unknown ticker: {0}")]
    UnknownTicker(DealerTicker),
    #[error("channel closed, please report bug")]
    ChannelClosed,
    #[error("lwk error: {0}")]
    Lwk(#[from] sideswap_lwk::Error),
    #[error("wS error: {0}")]
    WsError(#[from] ws_req_sender::Error),
    #[error("invalid asset amount: {0} (asset_precison: {1})")]
    InvalidAssetAmount(f64, AssetPrecision),
    #[error("can't find market")]
    NoMarket,
    #[error(
        "not enough amount for asset {asset_id}, required: {required}, available: {available}"
    )]
    NotEnoughAmount {
        asset_id: AssetId,
        required: u64,
        available: u64,
    },
    #[error("quote error: {0}")]
    QuoteError(String),
    #[error("base64 error: {0}")]
    Base64(#[from] b64::Error),
    #[error("encode error: {0}")]
    EncodeError(#[from] elements::encode::Error),
    #[error("PSET error: {0}")]
    PsetError(#[from] elements::pset::Error),
    #[error("no UTXOs")]
    NoUtxos,
    #[error("quote expired")]
    QuoteExpired,
    #[error("no quote")]
    NoQuote,
    #[error("no stored tx with this txid, please try again")]
    NoCreatedTx,
    #[error("UTXO check failed: {0}, please retry")]
    UtxoCheckFailed(String),
    #[error("gap limit reached")]
    GapLimit,
    #[error("wrong swap amounts: {0}")]
    SwapAmount(#[from] sideswap_common::pset::swap_amount::Error),
    #[error("wrong swap amount: {actual:?}, expected: {expected:?}")]
    WrongSwapAmount {
        actual: SwapAmount,
        expected: SwapAmount,
    },
}

impl From<tokio::sync::oneshot::error::RecvError> for Error {
    fn from(_value: tokio::sync::oneshot::error::RecvError) -> Self {
        Error::ChannelClosed
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for Error {
    fn from(_value: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Error::ChannelClosed
    }
}

impl<T> From<std::sync::mpsc::SendError<T>> for Error {
    fn from(_value: std::sync::mpsc::SendError<T>) -> Self {
        Error::ChannelClosed
    }
}

impl Error {
    pub fn error_code(&self) -> api::ErrorCode {
        match self {
            Error::InvalidTicker(_)
            | Error::UnknownTicker(_)
            | Error::Lwk(_)
            | Error::InvalidAssetAmount(_, _)
            | Error::NoMarket
            | Error::NotEnoughAmount { .. }
            | Error::QuoteError(_)
            | Error::Base64(_)
            | Error::EncodeError(_)
            | Error::PsetError(_)
            | Error::QuoteExpired
            | Error::NoQuote
            | Error::NoCreatedTx
            | Error::GapLimit => api::ErrorCode::InvalidRequest,

            Error::ChannelClosed
            | Error::NoUtxos
            | Error::SwapAmount(_)
            | Error::WrongSwapAmount { .. } => api::ErrorCode::ServerError,

            Error::WsError(error) => match error {
                ws_req_sender::Error::Disconnected => api::ErrorCode::NetworkError,
                ws_req_sender::Error::BackendError(_, _error_code) => api::ErrorCode::ServerError,
                ws_req_sender::Error::Timeout(_elapsed) => api::ErrorCode::ServerError,
                ws_req_sender::Error::UnexpectedResponse => api::ErrorCode::ServerError,
            },

            Error::UtxoCheckFailed(_) => api::ErrorCode::UtxoCheckFailed,
        }
    }
}

impl From<Error> for api::Error {
    fn from(val: Error) -> Self {
        api::Error {
            text: val.to_string(),
            code: val.error_code(),
            details: None,
        }
    }
}
