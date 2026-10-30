use std::time::Duration;

use serde::Deserialize;
use sideswap_common::{channel_helpers::UncheckedUnboundedSender, http_client::HttpClient};
use strum::IntoEnumIterator;

use crate::{BfxExchangePair, Msg};

/// External price source used to sanity check Bitfinex prices
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    strum_macros::Display,
    strum_macros::EnumIter,
)]
pub enum Source {
    Binance,
    Kraken,
}

struct Endpoint {
    url: &'static str,
    /// Set when the endpoint returns the inverted pair (for example USDT/EUR instead of EUR/USDT)
    invert: bool,
}

fn endpoint(source: Source, exchange_pair: BfxExchangePair) -> Endpoint {
    let (url, invert) = match (source, exchange_pair) {
        (Source::Binance, BfxExchangePair::BtcUsdt) => (
            "https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT",
            false,
        ),
        (Source::Binance, BfxExchangePair::BtcEur) => (
            "https://api.binance.com/api/v3/ticker/price?symbol=BTCEUR",
            false,
        ),
        (Source::Binance, BfxExchangePair::EurUsdt) => (
            "https://api.binance.com/api/v3/ticker/price?symbol=EURUSDT",
            false,
        ),
        (Source::Kraken, BfxExchangePair::BtcUsdt) => {
            ("https://api.kraken.com/0/public/Ticker?pair=XBTUSDT", false)
        }
        (Source::Kraken, BfxExchangePair::BtcEur) => {
            ("https://api.kraken.com/0/public/Ticker?pair=XBTEUR", false)
        }
        // Kraken has no EUR/USDT market, only USDT/EUR
        (Source::Kraken, BfxExchangePair::EurUsdt) => {
            ("https://api.kraken.com/0/public/Ticker?pair=USDTEUR", true)
        }
    };
    Endpoint { url, invert }
}

/// Binance: /api/v3/ticker/price?symbol=BTCUSDT
#[derive(Deserialize)]
struct BinanceTickerPrice {
    price: String,
}

/// Kraken: /0/public/Ticker?pair=XBTEUR
#[derive(Deserialize)]
struct KrakenTicker {
    error: Vec<String>,
    #[serde(default)]
    result: std::collections::BTreeMap<String, KrakenTickerPair>,
}

#[derive(Deserialize)]
struct KrakenTickerPair {
    /// Ask: [price, whole lot volume, lot volume]
    a: Vec<String>,
    /// Bid: [price, whole lot volume, lot volume]
    b: Vec<String>,
}

fn kraken_mid(resp: KrakenTicker) -> Result<f64, anyhow::Error> {
    anyhow::ensure!(
        resp.error.is_empty(),
        "kraken error: {}",
        resp.error.join(", ")
    );
    anyhow::ensure!(
        resp.result.len() == 1,
        "unexpected number of kraken pairs: {}",
        resp.result.len()
    );
    let pair = resp.result.into_values().next().expect("must not be empty");
    let ask = pair
        .a
        .first()
        .ok_or_else(|| anyhow::anyhow!("no kraken ask price"))?
        .parse::<f64>()?;
    let bid = pair
        .b
        .first()
        .ok_or_else(|| anyhow::anyhow!("no kraken bid price"))?
        .parse::<f64>()?;
    Ok((ask + bid) / 2.0)
}

fn finish_price(source: Source, endpoint: &Endpoint, price: f64) -> Result<f64, anyhow::Error> {
    anyhow::ensure!(
        price.is_finite() && price > 0.0,
        "invalid price from {source}: {price}"
    );
    Ok(if endpoint.invert { 1.0 / price } else { price })
}

async fn load_price(
    client: &HttpClient,
    source: Source,
    exchange_pair: BfxExchangePair,
) -> Result<f64, anyhow::Error> {
    let endpoint = endpoint(source, exchange_pair);
    let price = match source {
        Source::Binance => {
            let resp = client.get_json::<BinanceTickerPrice>(endpoint.url).await?;
            resp.price.parse::<f64>()?
        }
        Source::Kraken => {
            let resp = client.get_json::<KrakenTicker>(endpoint.url).await?;
            kraken_mid(resp)?
        }
    };
    finish_price(source, &endpoint, price)
}

pub async fn reload(msg_tx: UncheckedUnboundedSender<Msg>) {
    let client = HttpClient::new();
    loop {
        for source in Source::iter() {
            for exchange_pair in BfxExchangePair::iter() {
                let res = load_price(&client, source, exchange_pair).await;
                msg_tx.send(Msg::External(source, exchange_pair, res));
            }
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_binance() {
        let resp: BinanceTickerPrice =
            serde_json::from_str(r#"{"symbol":"BTCEUR","price":"68962.98000000"}"#).unwrap();
        let endpoint = endpoint(Source::Binance, BfxExchangePair::BtcEur);
        let price = finish_price(Source::Binance, &endpoint, resp.price.parse().unwrap()).unwrap();
        assert_eq!(price, 68962.98);
    }

    #[test]
    fn parse_kraken() {
        let resp: KrakenTicker = serde_json::from_str(
            r#"{"error":[],"result":{"XXBTZEUR":{"a":["70176.80000","1","1.000"],"b":["70176.60000","1","1.000"],"c":["70176.90000","0.02807192"],"v":["332.43287259","1045.70676860"],"p":["69098.01639","70676.19448"],"t":[1000,2000],"l":["68000.0","68000.0"],"h":["71000.0","71000.0"],"o":"69000.0"}}}"#,
        )
        .unwrap();
        let mid = kraken_mid(resp).unwrap();
        assert!((mid - 70176.7).abs() < 1e-6);
    }

    #[test]
    fn parse_kraken_inverted() {
        let resp: KrakenTicker = serde_json::from_str(
            r#"{"error":[],"result":{"USDTEUR":{"a":["0.89260000","386866","386866.000"],"b":["0.89250000","357342","357342.000"]}}}"#,
        )
        .unwrap();
        let endpoint = endpoint(Source::Kraken, BfxExchangePair::EurUsdt);
        let price = finish_price(Source::Kraken, &endpoint, kraken_mid(resp).unwrap()).unwrap();
        assert!((price - 1.0 / 0.89255).abs() < 1e-9);
    }

    #[test]
    fn parse_kraken_error() {
        let resp: KrakenTicker =
            serde_json::from_str(r#"{"error":["EQuery:Unknown asset pair"]}"#).unwrap();
        assert!(kraken_mid(resp).is_err());
    }
}
