//! Peg-in and peg-out payout amount formulas and their inverses.
//!
//! All amounts are in satoshi. The fee parameters come from the
//! `PegInFixedFee`, `PegInFeeRate`, `PegOutFeeRate` and `PegOutFixedFeeVsize`
//! subscribed values.
//!
//! The inverse ("send amount") functions are exact: feeding their result back
//! into the corresponding payout function returns the requested receive amount.
//! This holds because the forward formula rounds `send * (1 - fee_rate)` to the
//! nearest satoshi, and the rounding error of the inverse quotient (at most 0.5)
//! is scaled down by `(1 - fee_rate) < 1`, so it can never flip the forward
//! rounding.

use sideswap_types::fee_rate::FeeRateSats;

/// Peg-in fees (`PegInFixedFee` and `PegInFeeRate`)
#[derive(Debug, Copy, Clone)]
pub struct PegInFees {
    /// Fixed fee in sats
    pub fixed_fee: u64,
    /// Fee rate as a fraction, for example 0.001 for 0.1%
    pub fee_rate: f64,
}

/// Peg-out fees (`PegOutFeeRate` and `PegOutFixedFeeVsize`)
#[derive(Debug, Copy, Clone)]
pub struct PegOutFees {
    /// Fee rate as a fraction, for example 0.001 for 0.1%
    pub fee_rate: f64,
    /// Virtual size of the bitcoin payout transaction
    pub vsize: usize,
}

/// Peg-in payout amount for the `bitcoin_amount` sent:
/// `round((bitcoin_amount - fixed_fee) * (1 - fee_rate))`.
///
/// Returns `None` if the sent amount does not cover the fixed fee.
pub fn peg_in_payout_amount(fees: PegInFees, bitcoin_amount: u64) -> Option<u64> {
    let amount = bitcoin_amount.checked_sub(fees.fixed_fee)?;
    Some((amount as f64 * (1.0 - fees.fee_rate)).round() as u64)
}

/// How much bitcoin to send to receive `recv_amount` L-BTC:
/// `fixed_fee + round(recv_amount / (1 - fee_rate))`.
pub fn peg_in_send_amount(fees: PegInFees, recv_amount: u64) -> u64 {
    fees.fixed_fee + (recv_amount as f64 / (1.0 - fees.fee_rate)).round() as u64
}

/// Bitcoin network fee deducted from peg-out payouts:
/// `ceil(bitcoin_fee_rate * vsize)`.
pub fn peg_out_network_fee(fees: PegOutFees, bitcoin_fee_rate: FeeRateSats) -> u64 {
    bitcoin_fee_rate.vsize_to_fee(fees.vsize)
}

/// Peg-out payout amount before the bitcoin network fee is deducted:
/// `round(liquid_bitcoin_amount * (1 - fee_rate))`.
pub fn peg_out_output_amount(fee_rate: f64, liquid_bitcoin_amount: u64) -> u64 {
    (liquid_bitcoin_amount as f64 * (1.0 - fee_rate)).round() as u64
}

/// Peg-out payout amount for the `liquid_bitcoin_amount` sent:
/// `round(liquid_bitcoin_amount * (1 - fee_rate)) - ceil(bitcoin_fee_rate * vsize)`.
///
/// Returns `None` if the sent amount does not cover the bitcoin network fee.
pub fn peg_out_payout_amount(
    fees: PegOutFees,
    bitcoin_fee_rate: FeeRateSats,
    liquid_bitcoin_amount: u64,
) -> Option<u64> {
    peg_out_output_amount(fees.fee_rate, liquid_bitcoin_amount)
        .checked_sub(peg_out_network_fee(fees, bitcoin_fee_rate))
}

/// How much L-BTC to send to receive `recv_amount` bitcoin:
/// `round((recv_amount + ceil(bitcoin_fee_rate * vsize)) / (1 - fee_rate))`.
pub fn peg_out_send_amount(
    fees: PegOutFees,
    bitcoin_fee_rate: FeeRateSats,
    recv_amount: u64,
) -> u64 {
    let amount = recv_amount + peg_out_network_fee(fees, bitcoin_fee_rate);
    (amount as f64 / (1.0 - fees.fee_rate)).round() as u64
}

#[cfg(test)]
mod tests;
