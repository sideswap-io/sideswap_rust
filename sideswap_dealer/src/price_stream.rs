use std::{collections::BTreeMap, sync::Arc};

use sideswap_api::{
    PricePair,
    mkt::{AssetPair, TradeDir},
};
use sideswap_common::{
    dealer_ticker::{DealerTicker, TickerLoader},
    exchange_pair::ExchangePair,
    price_stream,
    types::MAX_BTC_AMOUNT,
};
use sideswap_types::{asset_precision::asset_int_amount_, env::Env, normal_float::NormalFloat};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use crate::{
    dealer_rpc::{self, apply_interest_ask, apply_interest_bid},
    market,
};

enum Msg {
    Price {
        exchange_pair: ExchangePair,
        base_price: Option<PricePair>,
    },
}

pub struct Data {
    markets: price_stream::Markets,
    /// Prices of the price sources
    base_prices: BTreeMap<ExchangePair, PricePair>,
    /// Prices of the public orders
    submit_prices: BTreeMap<ExchangePair, PricePair>,
    msg_receiver: UnboundedReceiver<Msg>,
}

fn apply_interests(base_price: &PricePair, interest_bid: f64, interest_ask: f64) -> PricePair {
    PricePair {
        bid: apply_interest_bid(base_price.bid, interest_bid),
        ask: apply_interest_ask(base_price.ask, interest_ask),
    }
}

impl Data {
    pub fn new(env: Env, markets: price_stream::Markets, ticker_loader: Arc<TickerLoader>) -> Data {
        log::debug!("start price streams: {markets:?}");

        let (msg_sender, msg_receiver) = unbounded_channel::<Msg>();

        for market in markets.iter() {
            // Fail at start, not when the first price arrives
            for private in market.private.iter() {
                let (_interest_bid, _interest_ask) = private.interests();
            }

            let exchange_pair = market.exchange_pair();
            let msg_sender_copy = msg_sender.clone();
            let callback = Box::new(move |base_price| {
                let res = msg_sender_copy.send(Msg::Price {
                    exchange_pair,
                    base_price,
                });
                if let Err(err) = res {
                    log::error!("price channel closed: {err}");
                }
            });

            price_stream::start(env, market.clone(), Arc::clone(&ticker_loader), callback);
        }

        Data {
            markets,
            base_prices: BTreeMap::new(),
            submit_prices: BTreeMap::new(),
            msg_receiver,
        }
    }

    pub fn dealer_prices(&self) -> Vec<dealer_rpc::UpdatePrice> {
        let mut updates = Vec::new();

        for market in self.markets.iter() {
            if market.base == DealerTicker::LBTC {
                let exchange_pair = market.exchange_pair();
                let submit_price = self.submit_prices.get(&exchange_pair);
                let price = submit_price.map(|price| dealer_rpc::DealerPrice {
                    submit_price: *price,
                    limit_btc_dealer_send: market.ask_amount_f64(),
                    limit_btc_dealer_recv: market.bid_amount_f64(),
                    balancing: false,
                });
                updates.push(dealer_rpc::UpdatePrice {
                    ticker: market.quote,
                    price,
                });
            }
        }

        updates
    }

    pub fn market_prices(&self, ticker_loader: &TickerLoader) -> Vec<market::AutomaticOrder> {
        let mut orders = Vec::new();

        for market in self.markets.iter() {
            let exchange_pair = market.exchange_pair();
            let submit_price = self.submit_prices.get(&exchange_pair);
            if let Some(submit_price) = submit_price {
                let asset_pair = AssetPair {
                    base: *ticker_loader.asset_id(market.base),
                    quote: *ticker_loader.asset_id(market.quote),
                };

                {
                    let bid_amount = market.bid_amount_sats(ticker_loader);
                    if bid_amount > 0 {
                        orders.push(market::AutomaticOrder {
                            asset_pair,
                            trade_dir: TradeDir::Buy,
                            base_amount: bid_amount,
                            price: NormalFloat::new(submit_price.bid).expect("must be valid"),
                            ttl: market.ttl_seconds.duration().into(),
                            book: None,
                            tier: None,
                        });
                    }
                }

                {
                    let ask_amount = market.ask_amount_sats(ticker_loader);
                    if ask_amount > 0 {
                        orders.push(market::AutomaticOrder {
                            asset_pair,
                            trade_dir: TradeDir::Sell,
                            base_amount: ask_amount,
                            price: NormalFloat::new(submit_price.ask).expect("must be valid"),
                            ttl: market.ttl_seconds.duration().into(),
                            book: None,
                            tier: None,
                        });
                    }
                }
            }

            // Orders for the members of the private order books:
            // the same price source with the interest and the amounts of the book and tier
            if let Some(base_price) = self.base_prices.get(&exchange_pair) {
                let asset_pair = AssetPair {
                    base: *ticker_loader.asset_id(market.base),
                    quote: *ticker_loader.asset_id(market.quote),
                };
                let base_precision = ticker_loader.precision(market.base);

                for private in market.private.iter() {
                    let (interest_bid, interest_ask) = private.interests();
                    let price = apply_interests(base_price, interest_bid, interest_ask);

                    for (trade_dir, amount, price) in [
                        (TradeDir::Buy, private.bid_amount, price.bid),
                        (TradeDir::Sell, private.ask_amount, price.ask),
                    ] {
                        let base_amount =
                            asset_int_amount_(amount.unwrap_or(MAX_BTC_AMOUNT), base_precision);
                        if base_amount > 0 {
                            orders.push(market::AutomaticOrder {
                                asset_pair,
                                trade_dir,
                                base_amount,
                                price: NormalFloat::new(price).expect("must be valid"),
                                ttl: market.ttl_seconds.duration().into(),
                                book: Some(private.book.clone()),
                                tier: private.tier,
                            });
                        }
                    }
                }
            }
        }

        orders
    }

    fn process_msg(&mut self, msg: Msg) {
        match msg {
            Msg::Price {
                exchange_pair,
                base_price,
            } => {
                let market = self
                    .markets
                    .iter()
                    .find(|market| {
                        market.base == exchange_pair.base && market.quote == exchange_pair.quote
                    })
                    .expect("must be known market");

                match base_price {
                    Some(base_price) => {
                        let interest_bid = market
                            .interest_bid
                            .or(market.interest)
                            .expect("interest_bid value is empty");

                        let interest_ask = market
                            .interest_ask
                            .or(market.interest)
                            .expect("interest_ask value is empty");

                        self.submit_prices.insert(
                            exchange_pair,
                            apply_interests(&base_price, interest_bid, interest_ask),
                        );
                        self.base_prices.insert(exchange_pair, base_price);
                    }
                    None => {
                        self.submit_prices.remove(&exchange_pair);
                        self.base_prices.remove(&exchange_pair);
                    }
                }
            }
        }
    }

    // Cancel-safe.
    pub async fn run(&mut self) {
        // Prevent busy loop if config is empty
        if self.markets.is_empty() {
            std::future::pending::<()>().await;
        }

        // Must be cancel-safe!
        loop {
            let msg = self
                .msg_receiver
                .recv()
                .await
                .expect("channel must be open");

            self.process_msg(msg);
        }
    }
}
