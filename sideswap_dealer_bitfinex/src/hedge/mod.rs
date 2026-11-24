//! Hedging of the swaps on the exchange.
//!
//! A swap is final once the dealer signs it, but the exchange balance changes only when
//! the hedge order is executed. What is still to be traded is kept here in the meantime:
//! - the published order sizes are the exchange balances without it (`Hedge::reserved`),
//!   so the same balance is not offered twice;
//! - a hedge order is cut to what the exchange has (`Hedge::next_order`), the rest stays
//!   owed and is traded when the balance allows it.
//!
//! All amounts are base amounts of the pair as the exchange sees them:
//! negative to sell, positive to buy.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use sideswap_api::mkt::{AssetPair, TradeDir};
use sideswap_dealer::market::SwapInfo;

use crate::{BfxExchangePair, ExchangeTicker};

/// How long a signed swap is kept when the server does not report it
pub const SIGNED_SWAP_TTL: Duration = Duration::from_secs(60);

/// How long the execution of an accepted hedge order is waited for
pub const ORDER_TTL: Duration = Duration::from_secs(30);

/// Pause after a failed hedge order of the pair
pub const RETRY_DELAY: Duration = Duration::from_secs(60);

/// A market buy can cost more than the best ask
const BUY_PRICE_MARGIN: f64 = 1.01;

/// What a trade takes from the exchange balance
#[derive(Debug, Clone, Copy, PartialEq)]
struct Need {
    ticker: ExchangeTicker,
    amount: f64,
}

/// A sell takes the base currency, a buy pays with the quote currency
/// (nothing is counted for a buy while the price is unknown)
fn need(pair: BfxExchangePair, amount: f64, ask: Option<f64>) -> Need {
    if amount < 0.0 {
        Need {
            ticker: pair.base_exchange(),
            amount: -amount,
        }
    } else {
        Need {
            ticker: pair.quote_exchange(),
            amount: amount * ask.unwrap_or_default(),
        }
    }
}

fn round(amount: f64) -> f64 {
    (amount * 1e8).round() / 1e8
}

struct SignedSwap {
    swap: SwapInfo,
    pair: BfxExchangePair,
    amount: f64,
    signed_at: Instant,
}

struct Order {
    pair: BfxExchangePair,
    amount: f64,
    need: Need,
    submitted_at: Instant,
    /// Set when the exchange has taken the order
    accepted_at: Option<Instant>,
}

#[derive(Debug, PartialEq)]
pub struct NewOrder {
    pub cid: i64,
    pub amount: f64,
}

#[derive(Default)]
pub struct Expired {
    /// Signed swaps that the server never reported
    pub swaps: Vec<SwapInfo>,
    /// Client ids of the accepted orders with no execution report
    pub orders: Vec<i64>,
}

#[derive(Default)]
pub struct Hedge {
    /// Swaps that are signed and not reported by the server yet
    signed: Vec<SignedSwap>,
    /// Amounts of the reported swaps that are in no hedge order yet
    owed: BTreeMap<BfxExchangePair, f64>,
    /// Hedge orders that are sent and not executed yet
    orders: BTreeMap<i64, Order>,
    /// No new hedge orders of the pair before this time
    retry_at: BTreeMap<BfxExchangePair, Instant>,
}

impl Hedge {
    /// How much of the exchange currency all pending trades will take
    pub fn reserved(
        &self,
        ticker: ExchangeTicker,
        ask: impl Fn(BfxExchangePair) -> Option<f64>,
    ) -> f64 {
        let signed = self
            .signed
            .iter()
            .map(|signed| need(signed.pair, signed.amount, ask(signed.pair)));
        let owed = self
            .owed
            .iter()
            .map(|(pair, amount)| need(*pair, *amount, ask(*pair)));
        let orders = self.orders.values().map(|order| order.need);
        let total = signed
            .chain(owed)
            .chain(orders)
            .filter(|need| need.ticker == ticker)
            .map(|need| need.amount)
            .sum();
        round(total)
    }

    /// Amount of the reported swaps that is in no hedge order
    pub fn unhedged(&self, pair: BfxExchangePair) -> f64 {
        self.owed.get(&pair).copied().unwrap_or_default()
    }

    /// The dealer is about to sign the swap
    pub fn swap_signed(
        &mut self,
        swap: SwapInfo,
        pair: BfxExchangePair,
        amount: f64,
        now: Instant,
    ) {
        self.signed.push(SignedSwap {
            swap,
            pair,
            amount,
            signed_at: now,
        });
    }

    /// The server reported the signed swap (`add_swap` is to follow).
    /// Returns false if no such swap was signed.
    pub fn swap_reported(
        &mut self,
        asset_pair: AssetPair,
        trade_dir: TradeDir,
        base_amount: u64,
    ) -> bool {
        let index = self.signed.iter().position(|signed| {
            signed.swap.asset_pair == asset_pair
                && signed.swap.trade_dir == trade_dir
                && signed.swap.base_amount == base_amount
        });
        match index {
            Some(index) => {
                self.signed.remove(index);
                true
            }
            None => false,
        }
    }

    /// A swap is made and `amount` must be traded on the exchange
    pub fn add_swap(&mut self, pair: BfxExchangePair, amount: f64) {
        let owed = self.owed.entry(pair).or_default();
        *owed = round(*owed + amount);
    }

    /// Make a hedge order for as much of the owed amount as the exchange balance allows.
    /// `cid` is the wanted client id, the returned one is free.
    pub fn next_order(
        &mut self,
        pair: BfxExchangePair,
        balance: impl Fn(ExchangeTicker) -> f64,
        ask: Option<f64>,
        mut cid: i64,
        now: Instant,
    ) -> Option<NewOrder> {
        if self
            .retry_at
            .get(&pair)
            .is_some_and(|retry_at| now < *retry_at)
        {
            return None;
        }

        let owed = self.unhedged(pair);
        let ticker = need(pair, owed, ask).ticker;
        let in_orders = self
            .orders
            .values()
            .filter(|order| order.need.ticker == ticker)
            .map(|order| order.need.amount)
            .sum::<f64>();
        let free = f64::max(balance(ticker) - in_orders, 0.0);

        let amount = if owed < 0.0 {
            -f64::min(-owed, free)
        } else {
            f64::min(owed, free / (ask? * BUY_PRICE_MARGIN))
        };
        let amount = round(amount);
        if amount.abs() < pair.min_bfx_amount() {
            return None;
        }

        while self.orders.contains_key(&cid) {
            cid += 1;
        }
        self.owed.insert(pair, round(owed - amount));
        self.orders.insert(
            cid,
            Order {
                pair,
                amount,
                need: need(pair, amount, ask),
                submitted_at: now,
                accepted_at: None,
            },
        );
        Some(NewOrder { cid, amount })
    }

    /// The exchange has taken the order, its execution report is to follow
    pub fn order_accepted(&mut self, cid: i64, now: Instant) {
        if let Some(order) = self.orders.get_mut(&cid) {
            order.accepted_at = Some(now);
        }
    }

    /// The order was not placed: its amount is owed again and is retried after a pause
    pub fn order_failed(&mut self, cid: i64, now: Instant) {
        if let Some(order) = self.orders.remove(&cid) {
            self.add_swap(order.pair, order.amount);
            self.retry_at.insert(order.pair, now + RETRY_DELAY);
        }
    }

    /// The order is executed (the exchange balance shows it already).
    /// Returns the submit time of a known order.
    pub fn order_done(&mut self, cid: i64) -> Option<Instant> {
        self.orders.remove(&cid).map(|order| order.submitted_at)
    }

    /// Drop what nothing has released in time.
    /// An accepted order is not owed again: it may have been executed.
    pub fn expire(&mut self, now: Instant) -> Expired {
        let mut expired = Expired::default();

        self.signed.retain(|signed| {
            let keep = now.duration_since(signed.signed_at) <= SIGNED_SWAP_TTL;
            if !keep {
                expired.swaps.push(signed.swap);
            }
            keep
        });

        self.orders.retain(|cid, order| {
            let keep = order
                .accepted_at
                .is_none_or(|accepted_at| now.duration_since(accepted_at) <= ORDER_TTL);
            if !keep {
                expired.orders.push(*cid);
            }
            keep
        });

        expired
    }
}

#[cfg(test)]
mod tests;
