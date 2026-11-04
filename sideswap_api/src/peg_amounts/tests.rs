use super::*;

const PEG_IN_FEES: PegInFees = PegInFees {
    fixed_fee: 300,
    fee_rate: 0.001,
};

const PEG_OUT_FEES: PegOutFees = PegOutFees {
    fee_rate: 0.001,
    vsize: 141,
};

#[test]
fn peg_in_forward() {
    // (100_000 - 300) * 0.999 = 99_600.3
    assert_eq!(peg_in_payout_amount(PEG_IN_FEES, 100_000), Some(99_600));
    // (1_000_000 - 300) * 0.999 = 998_700.3
    assert_eq!(peg_in_payout_amount(PEG_IN_FEES, 1_000_000), Some(998_700));
    assert_eq!(peg_in_payout_amount(PEG_IN_FEES, 300), Some(0));
    assert_eq!(peg_in_payout_amount(PEG_IN_FEES, 299), None);
}

#[test]
fn peg_in_backward() {
    // 300 + round(99_600 / 0.999) = 300 + round(99_699.7)
    assert_eq!(peg_in_send_amount(PEG_IN_FEES, 99_600), 100_000);
    assert_eq!(peg_in_send_amount(PEG_IN_FEES, 998_700), 1_000_000);
}

#[test]
fn peg_in_round_trip() {
    for fee_rate in [0.0, 0.001, 0.0015, 0.01, 0.1] {
        let fees = PegInFees {
            fixed_fee: 300,
            fee_rate,
        };
        for recv_amount in (1_000..=100_000).chain([1_000_000, 123_456_789, 2_100_000_000]) {
            let send_amount = peg_in_send_amount(fees, recv_amount);
            assert_eq!(
                peg_in_payout_amount(fees, send_amount),
                Some(recv_amount),
                "fee_rate: {fee_rate}, recv_amount: {recv_amount}, send_amount: {send_amount}"
            );
        }
    }
}

#[test]
fn peg_out_network_fee_rounds_up() {
    assert_eq!(
        peg_out_network_fee(PEG_OUT_FEES, FeeRateSats::from_raw(10.0)),
        1410
    );
    // 141 * 1.5 = 211.5
    assert_eq!(
        peg_out_network_fee(PEG_OUT_FEES, FeeRateSats::from_raw(1.5)),
        212
    );
}

#[test]
fn peg_out_forward() {
    let fee_rate = FeeRateSats::from_raw(10.0);
    // 1_000_000 * 0.999 - 1410
    assert_eq!(
        peg_out_payout_amount(PEG_OUT_FEES, fee_rate, 1_000_000),
        Some(997_590)
    );
    // 123_456 * 0.999 = 123_332.544
    assert_eq!(
        peg_out_payout_amount(PEG_OUT_FEES, fee_rate, 123_456),
        Some(123_333 - 1410)
    );
    assert_eq!(peg_out_payout_amount(PEG_OUT_FEES, fee_rate, 1_000), None);
}

#[test]
fn peg_out_backward() {
    let fee_rate = FeeRateSats::from_raw(10.0);
    assert_eq!(
        peg_out_send_amount(PEG_OUT_FEES, fee_rate, 997_590),
        1_000_000
    );
}

#[test]
fn peg_out_round_trip() {
    for fee_rate in [0.0, 0.001, 0.0015, 0.01, 0.1] {
        let fees = PegOutFees {
            fee_rate,
            vsize: 141,
        };
        for bitcoin_fee_rate in [1.0, 1.5, 10.0, 123.45] {
            let bitcoin_fee_rate = FeeRateSats::from_raw(bitcoin_fee_rate);
            for recv_amount in (1_000..=100_000).chain([1_000_000, 123_456_789, 2_100_000_000]) {
                let send_amount = peg_out_send_amount(fees, bitcoin_fee_rate, recv_amount);
                assert_eq!(
                    peg_out_payout_amount(fees, bitcoin_fee_rate, send_amount),
                    Some(recv_amount),
                    "fee_rate: {fee_rate}, bitcoin_fee_rate: {bitcoin_fee_rate:?}, recv_amount: {recv_amount}, send_amount: {send_amount}"
                );
            }
        }
    }
}
