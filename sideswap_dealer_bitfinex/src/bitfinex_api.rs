use log::debug;
use serde::Serialize;

use crate::BfSettings;

pub mod movements;
pub mod order_history;
pub mod submit;
pub mod transfer;
pub mod withdraw;

pub struct Bitfinex {
    settings: BfSettings,
}

pub trait ApiCall: Serialize {
    type Response;

    fn api_path() -> &'static str;

    fn parse(value: serde_json::Value) -> Result<Self::Response, anyhow::Error>;
}

fn get_string(list: &[serde_json::Value], index: usize) -> String {
    list.get(index)
        .and_then(|value| value.as_str())
        .map(|s| s.to_owned())
        .unwrap_or_default()
}

fn get_i64(list: &[serde_json::Value], index: usize) -> i64 {
    list.get(index)
        .and_then(|value| value.as_i64())
        .unwrap_or_default()
}

fn get_f64(list: &[serde_json::Value], index: usize) -> f64 {
    list.get(index)
        .and_then(|value| value.as_f64())
        .unwrap_or_default()
}

pub fn new_nonce() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros()
        .to_string()
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("transport error: {0:?}")]
    Transport(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(serde_json::Error),
    #[error("parse error: {0}")]
    Parse(anyhow::Error),
    #[error("bfx error: {msg}, code: {code}")]
    Bfx { code: String, msg: String },
}

impl Bitfinex {
    pub fn new(settings: BfSettings) -> Self {
        Self { settings }
    }

    pub async fn make_request<T: ApiCall>(&self, request: T) -> Result<T::Response, Error> {
        let body = serde_json::to_string(&request).expect("should not fail");
        let api_path = T::api_path();
        let nonce = new_nonce();
        let signature_payload = format!("/api/{api_path}{nonce}{body}");
        let key = ring::hmac::Key::new(
            ring::hmac::HMAC_SHA384,
            self.settings.bitfinex_secret.as_bytes(),
        );
        let tag = ring::hmac::sign(&key, signature_payload.as_bytes());
        let endpoint = format!("https://api.bitfinex.com/{api_path}");
        let signature = hex::encode(tag.as_ref());

        log::debug!("bf request: {body}, nonce: {nonce}, path: {api_path}");

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("http client construction failed");

        let resp = http_client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("bfx-nonce", &nonce)
            .header("bfx-apikey", &self.settings.bitfinex_key)
            .header("bfx-signature", &signature)
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        let resp = resp.text().await?;

        debug!("bfx response: {resp}, api_path: {api_path}, status: {status}");

        let resp = serde_json::from_str::<serde_json::Value>(&resp).map_err(Error::Json)?;

        if let Some(
            [serde_json::Value::String(err), serde_json::Value::Number(code), serde_json::Value::String(msg)],
        ) = resp.as_array().map(|a| a.as_slice())
        {
            if err == "error" {
                return Err(Error::Bfx {
                    code: code.as_str().to_owned(),
                    msg: msg.clone(),
                });
            }
        }

        let resp = T::parse(resp).map_err(Error::Parse)?;

        Ok(resp)
    }
}
