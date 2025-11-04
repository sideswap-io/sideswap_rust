use serde::Deserialize;
use sideswap_api::PricePair;

use crate::{dealer_ticker::DealerTicker, exchange_pair::ExchangePair, http_client::HttpClient};

#[derive(Debug, Clone, Deserialize)]
pub enum PriceIn {
    USDt,
    EUR,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Params {
    pub price_in: PriceIn,
    pub bid: f64,
    pub ask: f64,
}

pub async fn get_price(
    client: &HttpClient,
    exchange_pair: ExchangePair,
    params: &Params,
) -> Result<PricePair, anyhow::Error> {
    assert!(params.bid <= params.ask);

    match exchange_pair.quote {
        DealerTicker::LBTC => {
            let price_in_ticker = match params.price_in {
                PriceIn::USDt => DealerTicker::USDT,
                PriceIn::EUR => DealerTicker::EURX,
            };

            let bitcoin_price = super::bitfinex::get_price(
                client,
                ExchangePair {
                    base: DealerTicker::LBTC,
                    quote: price_in_ticker,
                },
            )
            .await?;

            let bitcoin_price = (bitcoin_price.ask + bitcoin_price.bid) / 2.0;

            Ok(PricePair {
                bid: params.bid / bitcoin_price,
                ask: params.ask / bitcoin_price,
            })
        }

        DealerTicker::USDT => match params.price_in {
            PriceIn::USDt => Ok(PricePair {
                bid: params.bid,
                ask: params.ask,
            }),

            PriceIn::EUR => {
                let eur_price = super::bitfinex::get_price(
                    client,
                    ExchangePair {
                        base: DealerTicker::EURX,
                        quote: DealerTicker::USDT,
                    },
                )
                .await?;

                let eur_price = (eur_price.ask + eur_price.bid) / 2.0;

                Ok(PricePair {
                    bid: params.bid * eur_price,
                    ask: params.ask * eur_price,
                })
            }
        },

        _ => panic!("unsupported exchange_pair: {exchange_pair:?}"),
    }
}
