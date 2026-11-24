use super::*;

use BfxExchangePair::{BtcEur, BtcUsdt, EurUsdt};
use ExchangeTicker::{BTC, EUR, USDt};

const ASK: f64 = 60_000.0;

fn ask(_pair: BfxExchangePair) -> Option<f64> {
    Some(ASK)
}

fn no_price(_pair: BfxExchangePair) -> Option<f64> {
    None
}

/// The same balance of every exchange currency
fn balance(amount: f64) -> impl Fn(ExchangeTicker) -> f64 {
    move |_ticker| amount
}

fn swap(trade_dir: TradeDir, base_amount: f64) -> SwapInfo {
    let asset = |byte| elements::AssetId::from_byte_array([byte; 32]);
    SwapInfo {
        asset_pair: AssetPair {
            base: asset(1),
            quote: asset(2),
        },
        trade_dir,
        base_amount: (base_amount * 1e8).round() as u64,
        quote_amount: (base_amount * ASK * 1e8).round() as u64,
    }
}

fn order(cid: i64, amount: f64) -> Option<NewOrder> {
    Some(NewOrder { cid, amount })
}

#[test]
fn sell_takes_base_and_buy_takes_quote() {
    let mut hedge = Hedge::default();

    hedge.add_swap(BtcUsdt, -1.5);
    assert_eq!(hedge.reserved(BTC, ask), 1.5);
    assert_eq!(hedge.reserved(USDt, ask), 0.0);

    // An EURx swap sells from the same BTC balance
    hedge.add_swap(BtcEur, -0.5);
    assert_eq!(hedge.reserved(BTC, ask), 2.0);

    hedge.add_swap(EurUsdt, 100.0);
    assert_eq!(hedge.reserved(USDt, ask), 100.0 * ASK);
    assert_eq!(hedge.reserved(EUR, ask), 0.0);

    // Without a price the cost of a buy is unknown
    assert_eq!(hedge.reserved(USDt, no_price), 0.0);
    assert_eq!(hedge.reserved(BTC, no_price), 2.0);
}

/// 2026-11-23 13:56:10: the order of 1.35947116 BTC lost 0.04263907 on the server when the first
/// swap was matched. The exchange balance was the same until the hedge order was executed,
/// so the dealer put the full size back and two more swaps took all of it.
#[test]
fn signed_swap_lowers_the_published_size() {
    let now = Instant::now();
    let mut hedge = Hedge::default();
    let size = |hedge: &Hedge, balance: f64| round(balance * 0.99 - hedge.reserved(BTC, ask));

    assert_eq!(size(&hedge, 1.37320319), 1.35947116);

    // From the signature the size is what the server has left of the order
    let swap_1 = swap(TradeDir::Buy, 0.04263907);
    hedge.swap_signed(swap_1, BtcUsdt, -0.04263907, now);
    assert_eq!(size(&hedge, 1.37320319), 1.31683209);

    // ... while the swap is reported and its hedge order is sent
    assert!(hedge.swap_reported(swap_1.asset_pair, swap_1.trade_dir, swap_1.base_amount));
    hedge.add_swap(BtcUsdt, -0.04263907);
    assert_eq!(size(&hedge, 1.37320319), 1.31683209);
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(1.37320319), ask(BtcUsdt), 1, now),
        order(1, -0.04263907)
    );
    assert_eq!(size(&hedge, 1.37320319), 1.31683209);

    // ... and until the order is executed
    hedge.order_done(1);
    assert_eq!(hedge.reserved(BTC, ask), 0.0);
    assert_eq!(size(&hedge, 1.33056412), 1.31725848);
}

/// The third swap of the incident: 1.19435184 BTC to sell with 1.1654448 on the exchange
#[test]
fn order_is_cut_to_the_balance_and_the_rest_follows() {
    let now = Instant::now();
    let mut hedge = Hedge::default();

    hedge.add_swap(BtcUsdt, -1.19435184);
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(1.1654448), ask(BtcUsdt), 1, now),
        order(1, -1.1654448)
    );
    assert_eq!(hedge.unhedged(BtcUsdt), -0.02890704);

    // Nothing more to sell, also not what the running order will take
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(1.1654448), ask(BtcUsdt), 2, now),
        None
    );
    hedge.order_done(1);
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(0.0), ask(BtcUsdt), 2, now),
        None
    );

    // The balancing transfer has arrived
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(0.18873635), ask(BtcUsdt), 2, now),
        order(2, -0.02890704)
    );
    assert_eq!(hedge.unhedged(BtcUsdt), 0.0);
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(0.18873635), ask(BtcUsdt), 3, now),
        None
    );
}

#[test]
fn buy_is_cut_to_the_quote_balance() {
    let now = Instant::now();
    let mut hedge = Hedge::default();
    hedge.add_swap(BtcUsdt, 1.0);

    // The price is needed to know what the balance buys
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(30_300.0), None, 1, now),
        None
    );

    // 1% is left for a price above the best ask
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(30_300.0), ask(BtcUsdt), 1, now),
        order(1, 0.5)
    );
    assert_eq!(hedge.unhedged(BtcUsdt), 0.5);
    assert_eq!(hedge.reserved(USDt, ask), 60_000.0);

    hedge.order_done(1);
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(100_000.0), ask(BtcUsdt), 2, now),
        order(2, 0.5)
    );
}

#[test]
fn small_amounts_add_up() {
    let now = Instant::now();
    let mut hedge = Hedge::default();

    hedge.add_swap(BtcUsdt, -0.00003);
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(1.0), ask(BtcUsdt), 1, now),
        None
    );
    assert_eq!(hedge.unhedged(BtcUsdt), -0.00003);

    hedge.add_swap(BtcUsdt, -0.00002);
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(1.0), ask(BtcUsdt), 1, now),
        order(1, -0.00005)
    );
}

#[test]
fn opposite_swaps_cancel_out() {
    let now = Instant::now();
    let mut hedge = Hedge::default();

    hedge.add_swap(BtcUsdt, -0.5);
    hedge.add_swap(BtcUsdt, 0.5);
    assert_eq!(hedge.unhedged(BtcUsdt), 0.0);
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(100_000.0), ask(BtcUsdt), 1, now),
        None
    );
}

#[test]
fn orders_of_one_millisecond_get_own_ids() {
    let now = Instant::now();
    let mut hedge = Hedge::default();

    hedge.add_swap(BtcUsdt, -0.1);
    hedge.add_swap(BtcEur, -0.2);
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(1.0), ask(BtcUsdt), 7, now),
        order(7, -0.1)
    );
    // The running order of the other pair takes from the same BTC balance
    assert_eq!(
        hedge.next_order(BtcEur, balance(0.25), ask(BtcEur), 7, now),
        order(8, -0.15)
    );
    assert_eq!(hedge.reserved(BTC, ask), 0.3);
}

#[test]
fn failed_order_is_retried_after_a_pause() {
    let now = Instant::now();
    let mut hedge = Hedge::default();

    hedge.add_swap(BtcUsdt, -0.5);
    hedge.add_swap(BtcEur, -0.1);
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(1.0), ask(BtcUsdt), 1, now),
        order(1, -0.5)
    );
    hedge.order_failed(1, now);
    assert_eq!(hedge.unhedged(BtcUsdt), -0.5);
    assert_eq!(hedge.reserved(BTC, ask), 0.6);

    assert_eq!(
        hedge.next_order(BtcUsdt, balance(1.0), ask(BtcUsdt), 2, now),
        None
    );
    // Other pairs are not paused
    assert_eq!(
        hedge.next_order(BtcEur, balance(1.0), ask(BtcEur), 2, now),
        order(2, -0.1)
    );
    assert_eq!(
        hedge.next_order(BtcUsdt, balance(1.0), ask(BtcUsdt), 3, now + RETRY_DELAY),
        order(3, -0.5)
    );

    // A late failure report of an executed order changes nothing
    hedge.order_done(3);
    hedge.order_failed(3, now);
    assert_eq!(hedge.unhedged(BtcUsdt), 0.0);
}

#[test]
fn swap_reported_releases_one_matching_swap() {
    let now = Instant::now();
    let mut hedge = Hedge::default();
    let swap = swap(TradeDir::Buy, 0.5);
    hedge.swap_signed(swap, BtcUsdt, -0.5, now);
    hedge.swap_signed(swap, BtcUsdt, -0.5, now);

    // Another direction or amount is another swap (an instant swap, for one)
    assert!(!hedge.swap_reported(swap.asset_pair, TradeDir::Sell, swap.base_amount));
    assert!(!hedge.swap_reported(swap.asset_pair, swap.trade_dir, swap.base_amount + 1));
    assert_eq!(hedge.reserved(BTC, ask), 1.0);

    assert!(hedge.swap_reported(swap.asset_pair, swap.trade_dir, swap.base_amount));
    assert_eq!(hedge.reserved(BTC, ask), 0.5);
    assert!(hedge.swap_reported(swap.asset_pair, swap.trade_dir, swap.base_amount));
    assert!(!hedge.swap_reported(swap.asset_pair, swap.trade_dir, swap.base_amount));
    assert_eq!(hedge.reserved(BTC, ask), 0.0);
}

#[test]
fn stale_entries_expire() {
    let now = Instant::now();
    let mut hedge = Hedge::default();
    let swap = swap(TradeDir::Buy, 0.5);
    hedge.swap_signed(swap, BtcUsdt, -0.5, now);
    hedge.add_swap(BtcUsdt, -0.2);
    hedge.add_swap(BtcEur, -0.1);
    hedge.next_order(BtcUsdt, balance(1.0), ask(BtcUsdt), 1, now);
    hedge.next_order(BtcEur, balance(1.0), ask(BtcEur), 2, now);
    hedge.order_accepted(1, now);

    let expired = hedge.expire(now + ORDER_TTL);
    assert!(expired.swaps.is_empty() && expired.orders.is_empty());

    // The accepted order may have been executed, it is not owed again.
    // The other one waits for the answer of the exchange.
    let later = now + SIGNED_SWAP_TTL + Duration::from_secs(1);
    let expired = hedge.expire(later);
    assert_eq!(expired.swaps, [swap]);
    assert_eq!(expired.orders, [1]);
    assert_eq!(hedge.unhedged(BtcUsdt), 0.0);
    assert_eq!(hedge.reserved(BTC, ask), 0.1);

    hedge.order_failed(2, later);
    assert_eq!(hedge.unhedged(BtcEur), -0.1);
}
