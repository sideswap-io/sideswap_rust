use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::ensure;
use serde::Deserialize;
use sideswap_api::PricePair;
use sideswap_types::{asset_precision::asset_int_amount_, duration_sec::DurationSec, env::Env};

use crate::{
    dealer_ticker::{DealerTicker, TickerLoader},
    exchange_pair::ExchangePair,
    http_client::HttpClient,
    types::MAX_BTC_AMOUNT,
};

pub mod binance;
pub mod bitfinex;
pub mod bitpreco;
pub mod fixed;
pub mod sideswap;

#[derive(Debug, Copy, Clone, Deserialize)]
pub enum PriceSource {
    Binance,
    Bitfinex,
    BitPreco,
    SideSwap,
    Fixed,
}

pub type PriceCallback = Box<dyn FnMut(Option<PricePair>) -> () + Send>;

#[derive(Debug, Clone, Deserialize)]
pub struct Market {
    pub source: PriceSource,
    pub base: DealerTicker,
    pub quote: DealerTicker,
    pub ttl_seconds: DurationSec,

    pub fixed: Option<fixed::Params>,

    pub interest: Option<f64>,
    pub interest_ask: Option<f64>,
    pub interest_bid: Option<f64>,
    pub bid_amount: Option<f64>,
    pub ask_amount: Option<f64>,

    /// Orders for the members of private order books.
    /// They use the price source of the market with their own interest and amounts.
    #[serde(default)]
    pub private: Vec<PrivateOrders>,
}

/// Orders that are served only to the members of a private order book
#[derive(Debug, Clone, Deserialize)]
pub struct PrivateOrders {
    /// Name of the private order book
    pub book: String,
    /// The lowest tier of the members the orders are served to (all members if not set)
    pub tier: Option<u8>,

    pub interest: Option<f64>,
    pub interest_ask: Option<f64>,
    pub interest_bid: Option<f64>,
    /// Unlimited if not set, 0 for no orders on this side
    pub bid_amount: Option<f64>,
    pub ask_amount: Option<f64>,
}

impl PrivateOrders {
    /// The bid and ask interests
    pub fn interests(&self) -> (f64, f64) {
        let interest_bid = self
            .interest_bid
            .or(self.interest)
            .expect("interest_bid value of a private order book is empty");
        let interest_ask = self
            .interest_ask
            .or(self.interest)
            .expect("interest_ask value of a private order book is empty");
        (interest_bid, interest_ask)
    }
}

impl Market {
    pub fn exchange_pair(&self) -> ExchangePair {
        ExchangePair {
            base: self.base,
            quote: self.quote,
        }
    }

    pub fn bid_amount_f64(&self) -> f64 {
        self.bid_amount.unwrap_or(MAX_BTC_AMOUNT)
    }

    pub fn ask_amount_f64(&self) -> f64 {
        self.ask_amount.unwrap_or(MAX_BTC_AMOUNT)
    }

    pub fn bid_amount_sats(&self, ticker_loader: &TickerLoader) -> u64 {
        let base_precision = ticker_loader.precision(self.base);
        asset_int_amount_(self.bid_amount_f64(), base_precision)
    }

    pub fn ask_amount_sats(&self, ticker_loader: &TickerLoader) -> u64 {
        let base_precision = ticker_loader.precision(self.base);
        asset_int_amount_(self.ask_amount_f64(), base_precision)
    }
}

pub type Markets = Vec<Market>;

async fn get_price(
    env: Env,
    client: &HttpClient,
    market: &Market,
    ticker_loader: &TickerLoader,
) -> Result<PricePair, anyhow::Error> {
    let exchange_pair = market.exchange_pair();
    match market.source {
        PriceSource::Binance => binance::get_price(client, exchange_pair).await,
        PriceSource::Bitfinex => bitfinex::get_price(client, exchange_pair).await,
        PriceSource::BitPreco => bitpreco::get_price(client, exchange_pair).await,
        PriceSource::SideSwap => {
            sideswap::get_price(env, client, exchange_pair, ticker_loader).await
        }
        PriceSource::Fixed => {
            let params = market.fixed.as_ref().expect("fixed field must be set");
            fixed::get_price(client, exchange_pair, params).await
        }
    }
}

fn verify_price_pair(price_pair: PricePair) -> Result<PricePair, anyhow::Error> {
    ensure!(price_pair.ask.is_normal());
    ensure!(price_pair.bid.is_normal());
    ensure!(price_pair.bid > 0.0 && price_pair.ask > 0.0);
    ensure!(price_pair.bid <= price_pair.ask);
    Ok(price_pair)
}

async fn run(
    env: Env,
    market: Market,
    ticker_loader: Arc<TickerLoader>,
    mut callback: PriceCallback,
) {
    let client = HttpClient::new();
    let mut last_success = None;
    let exchange_pair = market.exchange_pair();

    loop {
        let res = get_price(env, &client, &market, &ticker_loader)
            .await
            .and_then(verify_price_pair);

        match res {
            Ok(price) => {
                log::debug!("price download succeed: {price:?}, exchange_pair: {exchange_pair}");

                last_success = Some(Instant::now());

                callback(Some(price));

                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            }

            Err(err) => {
                log::error!("price download failed: {err}, exchange_pair: {exchange_pair}");

                let expired = last_success
                    .map(|last_success| {
                        Instant::now().duration_since(last_success) > Duration::from_secs(600)
                    })
                    .unwrap_or(true);

                if expired {
                    callback(None);
                }

                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    }
}

pub fn start(env: Env, market: Market, ticker_loader: Arc<TickerLoader>, callback: PriceCallback) {
    tokio::spawn(run(env, market, ticker_loader, callback));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_orders_config() {
        // Without private order books
        let market: Market = serde_json::from_value(serde_json::json!({
            "source": "Binance",
            "base": "L-BTC",
            "quote": "USDt",
            "ttl_seconds": 3600,
            "interest": 1.01,
        }))
        .unwrap();
        assert!(market.private.is_empty());

        let market: Market = serde_json::from_value(serde_json::json!({
            "source": "Binance",
            "base": "L-BTC",
            "quote": "USDt",
            "ttl_seconds": 3600,
            "interest": 1.01,
            "private": [
                { "book": "example", "interest": 1.005, "bid_amount": 0.5 },
                { "book": "example", "tier": 1, "interest_bid": 1.002, "interest_ask": 1.003 },
            ],
        }))
        .unwrap();
        assert_eq!(market.private.len(), 2);

        assert_eq!(market.private[0].book, "example");
        assert_eq!(market.private[0].tier, None);
        assert_eq!(market.private[0].interests(), (1.005, 1.005));
        assert_eq!(market.private[0].bid_amount, Some(0.5));
        assert_eq!(market.private[0].ask_amount, None);

        assert_eq!(market.private[1].tier, Some(1));
        assert_eq!(market.private[1].interests(), (1.002, 1.003));
    }
}
