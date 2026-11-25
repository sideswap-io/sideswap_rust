use sideswap_types::{asset_precision::AssetPrecision, normal_float::NormalFloat};

use super::verify_maker_swap_amounts;

const BTC: AssetPrecision = AssetPrecision::BITCOIN_PRECISION;

fn verify(base_amount: u64, quote_amount: u64, price: f64) -> Result<(), anyhow::Error> {
    verify_maker_swap_amounts(
        base_amount,
        quote_amount,
        NormalFloat::new(price).unwrap(),
        BTC,
        BTC,
    )
}

#[test]
fn exact_amounts_are_accepted() {
    verify(100_000_000, 6_950_000_000_000, 69_500.0).unwrap();
    verify(1, 69_500, 69_500.0).unwrap();
}

#[test]
fn base_amount_rounded_to_whole_satoshi_is_accepted() {
    // 2 USDt at 69505.45 is 2877.47 sat, which the server rounds to 2877.
    // That moves the quote amount by 1.7e-4 of the expected one.
    let price = 69_505.45;
    let quote_amount = 200_000_000;
    let diff = 1.0 - 2877.0 * price / quote_amount as f64;
    assert!(diff > 0.0001, "{diff}");

    verify(2877, quote_amount, price).unwrap();
    // Truncated or rounded up by the server
    verify(2878, quote_amount, price).unwrap();
}

#[test]
fn quote_amount_rounded_to_whole_satoshi_is_accepted() {
    // 3 sat at 0.5 is 1.5 sat
    verify(3, 1, 0.5).unwrap();
    verify(3, 2, 0.5).unwrap();
}

#[test]
fn small_amounts_off_by_more_than_rounding_are_rejected() {
    let price = 69_505.45;
    let quote_amount = 200_000_000;

    // 2 USDt is 2877.47 sat
    verify(2876, quote_amount, price).unwrap_err();
    verify(2879, quote_amount, price).unwrap_err();
}

#[test]
fn big_amounts_within_relative_tolerance_are_accepted() {
    let price = 69_500.0;
    let base_amount = 100_000_000;
    let expected_quote_amount = 6_950_000_000_000_u64;

    verify(
        base_amount,
        expected_quote_amount + expected_quote_amount / 20_000,
        price,
    )
    .unwrap();
    verify(
        base_amount,
        expected_quote_amount - expected_quote_amount / 20_000,
        price,
    )
    .unwrap();
}

#[test]
fn big_amounts_outside_relative_tolerance_are_rejected() {
    let price = 69_500.0;
    let base_amount = 100_000_000;
    let expected_quote_amount = 6_950_000_000_000_u64;

    verify(
        base_amount,
        expected_quote_amount + expected_quote_amount / 5_000,
        price,
    )
    .unwrap_err();
    verify(
        base_amount,
        expected_quote_amount - expected_quote_amount / 5_000,
        price,
    )
    .unwrap_err();
}

#[test]
fn asset_precisions_are_applied() {
    let quote_precision = AssetPrecision::new(2).unwrap();
    let price = NormalFloat::new(50_000.0).unwrap();
    let verify = |base_amount, quote_amount| {
        verify_maker_swap_amounts(base_amount, quote_amount, price, BTC, quote_precision)
    };

    // 1 L-BTC for 50000.00
    verify(100_000_000, 5_000_000).unwrap();
    // 0.5 L-BTC is not worth 50000.00
    verify(50_000_000, 5_000_000).unwrap_err();
    // One unit of the quote asset is 2000 sat here
    verify(100_000, 5_001).unwrap();
    verify(100_000, 5_002).unwrap_err();
}

#[test]
fn empty_amounts_and_negative_price_are_rejected() {
    verify(0, 1, 1.0).unwrap_err();
    // One satoshi for nothing is within one unit of the price
    verify(1, 0, 1.0).unwrap_err();
    verify(1, 1, -1.0).unwrap_err();
}
