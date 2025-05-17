use std::{
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};

use anyhow::ensure;
use rand::{seq::SliceRandom, thread_rng, Rng};

use crate::network::Network;

use super::*;

fn random_value(max: u64, power: f64, rng: &mut rand::prelude::ThreadRng) -> u64 {
    let x = rng.gen::<f64>(); // uniform in [0, 1)
    let value = (x.powf(power) * max as f64).round() as u64;
    let value = u64::max(1, value);
    value
}

fn select_slow(
    Args {
        policy_asset,
        utxos,
        recipients,
        deduct_fee,
        force_change_wallets,
        use_all_utxos,
    }: Args,
) -> Result<Res, Error> {
    let mut res: Result<Res, Error> = Err(Error::InsufficientFunds);

    let utxos = {
        let mut utxos = utxos;
        utxos.sort();
        utxos
    };

    let change_wallets = change_wallets(&utxos, force_change_wallets);
    let change_wallet = *change_wallets
        .get(&policy_asset)
        .ok_or(Error::InsufficientFunds)?;

    let recipient_totals = recipient_totals(&recipients)?;
    let bitcoin_target = recipient_totals
        .get(&policy_asset)
        .copied()
        .unwrap_or_default();

    let max_bit_mask = (1 << utxos.len()) - 1;

    let base_weight = tx_weight(
        [].into_iter(),
        recipients.iter().map(|recipient| &recipient.address),
        [].into_iter(),
    );

    for with_change in [false, true] {
        let start_index = if use_all_utxos { max_bit_mask } else { 1 };

        for bit_mask in start_index..=max_bit_mask {
            let mut selected_total = 0;
            let mut selected_weight = 0;

            for index in 0..utxos.len() {
                let is_selected = bit_mask & (1 << index) != 0;
                let utxo = &utxos[index];
                if is_selected {
                    selected_total += utxo.value;
                    selected_weight += utxo.wallet.input_weight();
                }
            }

            if selected_total < bitcoin_target {
                continue;
            }

            let total_weight = base_weight
                + selected_weight
                + with_change
                    .then(|| change_wallet.output_weight())
                    .unwrap_or_default();

            let min_fee = weight_to_fee(total_weight, DEFAULT_FEE_RATE);

            if selected_total < min_fee {
                continue;
            }

            let actual_fee = if with_change {
                min_fee
            } else {
                if deduct_fee.is_some() {
                    min_fee
                } else {
                    selected_total - bitcoin_target
                }
            };

            if actual_fee < min_fee {
                continue;
            }

            if let Some(deduct_fee) = deduct_fee {
                if recipients[deduct_fee].amount <= actual_fee {
                    continue;
                }
            }

            let is_better = res
                .as_ref()
                .map(|old| old.network_fee > actual_fee)
                .unwrap_or(true);

            if is_better {
                let selected_utxos = utxos
                    .iter()
                    .enumerate()
                    .filter_map(|(index, utxo)| {
                        let is_selected = bit_mask & (1 << index) != 0;
                        is_selected.then(|| utxo.clone())
                    })
                    .collect::<Vec<_>>();

                let change_amount = if !with_change {
                    0
                } else if deduct_fee.is_some() {
                    selected_total - bitcoin_target
                } else {
                    if selected_total < bitcoin_target + actual_fee {
                        continue;
                    }
                    selected_total - bitcoin_target - actual_fee
                };

                let change = if with_change {
                    if change_amount == 0 {
                        continue;
                    }
                    vec![Change {
                        wallet: change_wallet,
                        asset_id: policy_asset,
                        value: change_amount,
                    }]
                } else {
                    vec![]
                };

                let mut updated_recipients = recipients.clone();

                if let Some(deduct_fee) = deduct_fee {
                    updated_recipients[deduct_fee].amount = selected_total
                        - change_amount
                        - actual_fee
                        - (bitcoin_target - recipients[deduct_fee].amount);
                    if updated_recipients[deduct_fee].amount > recipients[deduct_fee].amount {
                        continue;
                    }
                }

                res = Ok(Res {
                    inputs: selected_utxos,
                    updated_recipients,
                    change,
                    network_fee: actual_fee,
                });
            }
        }
    }

    res
}

fn validate(args: &Args, res: &Res) -> Result<(), anyhow::Error> {
    ensure!(!res.inputs.is_empty());

    let all_utxos = args.utxos.iter().collect::<BTreeSet<_>>();
    ensure!(all_utxos.len() == args.utxos.len());
    let all_inputs = res.inputs.iter().collect::<BTreeSet<_>>();
    ensure!(all_inputs.len() == res.inputs.len());

    ensure!(all_inputs.difference(&all_utxos).count() == 0);

    if args.use_all_utxos {
        ensure!(args.utxos.len() == res.inputs.len());
    }

    if let Some(deduct_fee) = args.deduct_fee {
        let orig_output = args.recipients[deduct_fee].amount;
        let updated_output = res.updated_recipients[deduct_fee].amount;
        ensure!(updated_output <= orig_output);
        ensure!(orig_output <= updated_output + res.network_fee);
    } else {
        ensure!(res.updated_recipients == args.recipients);
    }

    let tx_weight = tx_weight(
        res.inputs.iter().map(|utxo| utxo.wallet),
        res.updated_recipients
            .iter()
            .map(|recipient| &recipient.address),
        res.change.iter().map(|change| change.wallet),
    );

    let min_network_fee = weight_to_fee(tx_weight, DEFAULT_FEE_RATE);
    ensure!(res.network_fee >= min_network_fee);
    ensure!(res.network_fee < min_network_fee + 10);
    // If there is change, then the network fee must be minimal
    ensure!(res.network_fee == min_network_fee || res.change.is_empty());
    // When deducting the fee we can deduct the minimum amount
    ensure!(res.network_fee == min_network_fee || args.deduct_fee.is_none());

    let input_amount = res.inputs.iter().map(|utxo| utxo.value).sum::<u64>();
    let output_amount = res
        .updated_recipients
        .iter()
        .map(|recipient| recipient.amount)
        .chain(res.change.iter().map(|change| change.value))
        .sum::<u64>()
        + res.network_fee;
    ensure!(input_amount == output_amount);
    Ok(())
}

#[test]
fn randomized() {
    let network = Network::Regtest;
    let policy_asset = network.d().policy_asset;
    let all_wallets = [WalletType::Native, WalletType::Nested, WalletType::AMP];
    let txid = elements::Txid::from_str(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();

    let without_change_normal = AtomicUsize::default();
    let without_change_slow = AtomicUsize::default();

    let test_count = 100000;

    use rayon::prelude::*;

    (0..test_count).into_par_iter().map(|_| {

        let mut rng = thread_rng();
        let utxo_count = rng.gen_range(1..10);

        let utxos = (0..utxo_count)
            .into_iter()
            .map(|vout| {
                let wallet = *all_wallets.choose(&mut rng).unwrap();
                let value = random_value(10000, 0.5, &mut rng);

                Utxo {
                    wallet,
                    txid,
                    vout,
                    asset_id: policy_asset,
                    value,
                }
            })
            .collect::<Vec<_>>();

        let recipient_count = rng.gen_range(0..4);

        let recipients = (0..recipient_count)
            .into_iter()
            .map(|_index| {
                let wallet = *all_wallets.choose(&mut rng).unwrap();
                let amount = random_value(10000, 0.5, &mut rng);

                Recipient {
                    address: RecipientAddress::Unknown(wallet),
                    asset_id: policy_asset,
                    amount,
                }
            })
            .collect::<Vec<_>>();

        let deduct_fee = rng.gen_bool(0.1) && recipient_count != 0;

        let deduct_fee = deduct_fee.then(|| rng.gen_range(0..recipient_count) as usize);

        let use_all_utxos = rng.gen_bool(0.05);

        let args = Args {
            policy_asset,
            utxos,
            recipients,
            deduct_fee,
            force_change_wallets: ChangeWallets::new(),
            use_all_utxos,
        };

        let res_normal = select(args.clone());

        let res_slow = select_slow(args.clone());

        match (res_normal, res_slow) {
            (Ok(selected_normal), Ok(selected_slow)) => {
                assert!(selected_slow.network_fee <= selected_normal.network_fee);
                validate(&args, &selected_normal).unwrap_or_else(|err| {
                    panic!("failed validation for selected_normal: {err}, args: {args:#?}, res: {selected_normal:#?}")
                });
                validate(&args, &selected_slow).unwrap_or_else(|err| {
                    panic!("failed validation for selected_slow: {err}, args: {args:#?}, res: {selected_slow:#?}")
                });
                if selected_normal.change.is_empty() {
                    without_change_normal.fetch_add(1, Ordering::Relaxed);
                }
                if selected_slow.change.is_empty() {
                    without_change_slow.fetch_add(1, Ordering::Relaxed);
                }
            }
            (Ok(selected_normal), Err(err_test)) => {
                panic!(
                    "args: {args:#?}, err_test: {err_test}, selected_normal: {selected_normal:#?}"
                )
            }
            (Err(err_normal), Ok(selected_test)) => {
                // Workaround for some corner case
                if !err_normal
                    .to_string()
                    .contains("can't deduct fee because the recipient amount is too small")
                {
                    panic!(
                        "args: {args:#?}, err_normal: {err_normal}, selected_test: {selected_test:#?}"
                    )
                }
            }
            (Err(_), Err(_)) => {}
        }
    }).count();

    let without_change_normal_rate =
        without_change_normal.load(Ordering::Relaxed) as f64 / test_count as f64;
    assert!(without_change_normal_rate >= 0.005);
    let without_change_slow_rate =
        without_change_slow.load(Ordering::Relaxed) as f64 / test_count as f64;
    assert!(without_change_slow_rate >= 0.005);
}

#[test]
fn no_policy_asset_crash() {
    let network = Network::Regtest;

    let policy_asset = network.d().policy_asset;
    let send_asset = network.d().known_assets.USDt;
    let txid = elements::Txid::from_str(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();

    select(Args {
        policy_asset,
        utxos: vec![Utxo {
            wallet: WalletType::AMP,
            txid,
            vout: 0,
            asset_id: send_asset,
            value: 100000000,
        }],
        recipients: vec![Recipient {
            address: RecipientAddress::Unknown(WalletType::Nested),
            asset_id: send_asset,
            amount: 10000,
        }],
        deduct_fee: None,
        force_change_wallets: BTreeMap::new(),
        use_all_utxos: false,
    })
    .unwrap_err();
}
