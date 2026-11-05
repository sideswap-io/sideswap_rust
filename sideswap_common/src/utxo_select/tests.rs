use std::{
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};

use anyhow::ensure;
use rand::{Rng, seq::SliceRandom, thread_rng};
use sideswap_types::network::Network;

use super::*;

fn random_value(max: u64, power: f64, rng: &mut rand::prelude::ThreadRng) -> u64 {
    let x = rng.r#gen::<f64>(); // uniform in [0, 1)
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
    let all_wallets = [
        WalletType::Native,
        WalletType::Nested,
        WalletType::AMP2,
        WalletType::AMP,
    ];
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

fn utxo(wallet: WalletType, asset_id: AssetId, vout: u32, value: u64) -> Utxo {
    let txid = elements::Txid::from_str(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    Utxo {
        wallet,
        asset_id,
        value,
        txid,
        vout,
    }
}

fn regtest_assets() -> (AssetId, AssetId) {
    let network = Network::Regtest;
    (network.d().policy_asset, network.d().known_assets.USDt)
}

/// A signed input of the wallet with the signature sizes `WalletType::input_weight` assumes
fn signed_input(wallet: WalletType) -> elements::TxIn {
    // A DER signature with the sighash byte: 71 + 1 bytes, or 70 + 1 bytes with a grinded R
    let sig = vec![0u8; 72];
    let grinded_sig = vec![0u8; 71];
    let pubkey = vec![0u8; 33];
    // OP_2 <33 bytes> <33 bytes> OP_2 OP_CHECKMULTISIG
    let multisig_script = vec![0u8; 71];
    // The script_sig of a nested input pushes the redeem script: OP_0 <witness program>
    let nested_script_sig = |program_len: usize| {
        elements::script::Builder::new()
            .push_slice(&vec![0u8; 2 + program_len])
            .into_script()
    };

    let (script_sig, script_witness) = match wallet {
        WalletType::Native => (elements::Script::new(), vec![sig, pubkey]),
        WalletType::Nested => (nested_script_sig(20), vec![sig, pubkey]),
        // The user and the AMP2 server signatures, both maximal
        WalletType::AMP2 => (
            elements::Script::new(),
            vec![vec![], sig.clone(), sig, multisig_script],
        ),
        // The Green server grinds its signature
        WalletType::AMP => (
            nested_script_sig(32),
            vec![vec![], grinded_sig, sig, multisig_script],
        ),
    };

    elements::TxIn {
        previous_output: elements::OutPoint::default(),
        is_pegin: false,
        script_sig,
        sequence: elements::Sequence::MAX,
        asset_issuance: elements::AssetIssuance::default(),
        witness: elements::TxInWitness {
            amount_rangeproof: None,
            inflation_keys_rangeproof: None,
            script_witness,
            pegin_witness: Vec::new(),
        },
    }
}

/// The fee rate applies to the discounted weight, where every output weighs as an explicit one
fn explicit_output(asset_id: AssetId, script_pubkey_len: usize) -> elements::TxOut {
    elements::TxOut {
        asset: elements::confidential::Asset::Explicit(asset_id),
        value: elements::confidential::Value::Explicit(1),
        nonce: elements::confidential::Nonce::Null,
        script_pubkey: elements::Script::from(vec![0u8; script_pubkey_len]),
        witness: elements::TxOutWitness::default(),
    }
}

fn discount_weight(inputs: Vec<elements::TxIn>, outputs: Vec<elements::TxOut>) -> usize {
    elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
    .discount_weight()
}

/// The weight constants match the serialized transactions
#[test]
fn weights() {
    let (policy_asset, _usdt) = regtest_assets();
    let all_wallets = [
        WalletType::Native,
        WalletType::Nested,
        WalletType::AMP2,
        WalletType::AMP,
    ];

    // The smallest transaction: one input and the fee output (explicit, with an empty script)
    let fee_output = || explicit_output(policy_asset, 0);
    let base = discount_weight(vec![signed_input(WalletType::Native)], vec![fee_output()]);
    assert_eq!(base, WEIGHT_TX_FIXED + WalletType::Native.input_weight());

    for wallet in all_wallets {
        let with_input = discount_weight(
            vec![signed_input(WalletType::Native), signed_input(wallet)],
            vec![fee_output()],
        );
        assert_eq!(with_input - base, wallet.input_weight(), "{wallet:?} input");

        let with_output = discount_weight(
            vec![signed_input(WalletType::Native)],
            vec![
                fee_output(),
                explicit_output(policy_asset, wallet.script_pubkey_len()),
            ],
        );
        assert_eq!(
            with_output - base,
            wallet.output_weight(),
            "{wallet:?} output"
        );
    }

    // The wallets are sorted by their input weight
    assert!(
        all_wallets
            .windows(2)
            .all(|pair| { pair[0] < pair[1] && pair[0].input_weight() < pair[1].input_weight() })
    );
}

#[test]
fn change_wallet_priority() {
    let (policy_asset, usdt) = regtest_assets();

    let wallets = change_wallets(
        &[
            utxo(WalletType::AMP, usdt, 0, 1),
            utxo(WalletType::AMP2, usdt, 1, 1),
            utxo(WalletType::AMP2, policy_asset, 2, 1),
            utxo(WalletType::Nested, policy_asset, 3, 1),
        ],
        ChangeWallets::new(),
    );
    assert_eq!(wallets[&usdt], WalletType::AMP2);
    assert_eq!(wallets[&policy_asset], WalletType::Nested);

    // AMP2 only keeps all the change in the AMP2 wallet
    let wallets = change_wallets(
        &[
            utxo(WalletType::AMP2, usdt, 0, 1),
            utxo(WalletType::AMP2, policy_asset, 1, 1),
        ],
        ChangeWallets::new(),
    );
    assert_eq!(wallets[&usdt], WalletType::AMP2);
    assert_eq!(wallets[&policy_asset], WalletType::AMP2);

    // Unless the caller forces another wallet
    let wallets = change_wallets(
        &[utxo(WalletType::AMP2, usdt, 0, 1)],
        ChangeWallets::from([(usdt, WalletType::AMP)]),
    );
    assert_eq!(wallets[&usdt], WalletType::AMP);
}

fn change_of(res: &Res, asset_id: AssetId) -> &Change {
    res.change
        .iter()
        .find(|change| change.asset_id == asset_id)
        .expect("must have change")
}

#[test]
fn amp2_asset_change_stays_in_amp2() {
    let (policy_asset, usdt) = regtest_assets();

    let args = Args {
        policy_asset,
        utxos: vec![
            utxo(WalletType::AMP2, usdt, 0, 100_000),
            utxo(WalletType::AMP2, policy_asset, 1, 50_000),
        ],
        recipients: vec![Recipient {
            address: RecipientAddress::Unknown(WalletType::AMP2),
            asset_id: usdt,
            amount: 30_000,
        }],
        deduct_fee: None,
        force_change_wallets: ChangeWallets::new(),
        use_all_utxos: false,
    };

    let res = select(args.clone()).unwrap();
    validate(&args, &res).unwrap();

    assert_eq!(res.inputs.len(), 2);
    assert_eq!(res.change.len(), 2);

    let usdt_change = change_of(&res, usdt);
    assert_eq!(usdt_change.wallet, WalletType::AMP2);
    assert_eq!(usdt_change.value, 70_000);

    let lbtc_change = change_of(&res, policy_asset);
    assert_eq!(lbtc_change.wallet, WalletType::AMP2);
    assert_eq!(lbtc_change.value + res.network_fee, 50_000);

    // Two AMP2 inputs, the recipient output and two change outputs, all P2WSH
    let weight = WEIGHT_TX_FIXED
        + 2 * WalletType::AMP2.input_weight()
        + 3 * WalletType::AMP2.output_weight();
    assert_eq!(res.network_fee, weight_to_fee(weight, DEFAULT_FEE_RATE));
}

#[test]
fn amp2_asset_with_fee_from_native_wallet() {
    let (policy_asset, usdt) = regtest_assets();

    let args = Args {
        policy_asset,
        utxos: vec![
            utxo(WalletType::AMP2, usdt, 0, 100_000),
            utxo(WalletType::Native, policy_asset, 1, 50_000),
        ],
        recipients: vec![Recipient {
            address: RecipientAddress::Unknown(WalletType::AMP2),
            asset_id: usdt,
            amount: 30_000,
        }],
        deduct_fee: None,
        force_change_wallets: ChangeWallets::new(),
        use_all_utxos: false,
    };

    let res = select(args.clone()).unwrap();
    validate(&args, &res).unwrap();

    assert_eq!(change_of(&res, usdt).wallet, WalletType::AMP2);
    assert_eq!(change_of(&res, policy_asset).wallet, WalletType::Native);

    let weight = WEIGHT_TX_FIXED
        + WalletType::AMP2.input_weight()
        + WalletType::Native.input_weight()
        + 2 * WalletType::AMP2.output_weight()
        + WalletType::Native.output_weight();
    assert_eq!(res.network_fee, weight_to_fee(weight, DEFAULT_FEE_RATE));
}

#[test]
fn amp2_lbtc_without_change() {
    let (policy_asset, _usdt) = regtest_assets();

    // One AMP2 input and one native SegWit output, nothing else
    let fee = weight_to_fee(
        WEIGHT_TX_FIXED + WalletType::AMP2.input_weight() + WalletType::Native.output_weight(),
        DEFAULT_FEE_RATE,
    );
    let amount = 10_000;

    let args = Args {
        policy_asset,
        utxos: vec![
            utxo(WalletType::AMP2, policy_asset, 0, amount + fee),
            utxo(WalletType::AMP2, policy_asset, 1, 100_000),
        ],
        recipients: vec![Recipient {
            address: RecipientAddress::Unknown(WalletType::Native),
            asset_id: policy_asset,
            amount,
        }],
        deduct_fee: None,
        force_change_wallets: ChangeWallets::new(),
        use_all_utxos: false,
    };

    let res = select(args.clone()).unwrap();
    validate(&args, &res).unwrap();

    assert_eq!(
        res.inputs,
        vec![utxo(WalletType::AMP2, policy_asset, 0, amount + fee)]
    );
    assert!(res.change.is_empty());
    assert_eq!(res.network_fee, fee);
}

#[test]
fn amp2_send_all_lbtc_deducting_fee() {
    let (policy_asset, _usdt) = regtest_assets();

    let args = Args {
        policy_asset,
        utxos: vec![
            utxo(WalletType::AMP2, policy_asset, 0, 10_000),
            utxo(WalletType::AMP2, policy_asset, 1, 20_000),
        ],
        recipients: vec![Recipient {
            address: RecipientAddress::Unknown(WalletType::Native),
            asset_id: policy_asset,
            amount: 30_000,
        }],
        deduct_fee: Some(0),
        force_change_wallets: ChangeWallets::new(),
        use_all_utxos: false,
    };

    let res = select(args.clone()).unwrap();
    validate(&args, &res).unwrap();

    assert_eq!(res.inputs.len(), 2);
    assert!(res.change.is_empty());
    let fee = weight_to_fee(
        WEIGHT_TX_FIXED + 2 * WalletType::AMP2.input_weight() + WalletType::Native.output_weight(),
        DEFAULT_FEE_RATE,
    );
    assert_eq!(res.network_fee, fee);
    assert_eq!(res.updated_recipients[0].amount, 30_000 - fee);
}

#[test]
fn amp2_use_all_utxos() {
    let (policy_asset, usdt) = regtest_assets();

    let args = Args {
        policy_asset,
        utxos: vec![
            utxo(WalletType::AMP2, usdt, 0, 100_000),
            utxo(WalletType::AMP2, usdt, 1, 5_000),
            utxo(WalletType::AMP2, policy_asset, 2, 50_000),
            utxo(WalletType::AMP2, policy_asset, 3, 1_000),
        ],
        recipients: vec![Recipient {
            address: RecipientAddress::Unknown(WalletType::Native),
            asset_id: usdt,
            amount: 30_000,
        }],
        deduct_fee: None,
        force_change_wallets: ChangeWallets::new(),
        use_all_utxos: true,
    };

    let res = select(args.clone()).unwrap();
    validate(&args, &res).unwrap();

    assert_eq!(res.inputs.len(), 4);
    let usdt_change = change_of(&res, usdt);
    assert_eq!(usdt_change.wallet, WalletType::AMP2);
    assert_eq!(usdt_change.value, 75_000);
    let lbtc_change = change_of(&res, policy_asset);
    assert_eq!(lbtc_change.wallet, WalletType::AMP2);
    assert_eq!(lbtc_change.value + res.network_fee, 51_000);
}

#[test]
fn amp2_not_enough_lbtc_for_fee() {
    let (policy_asset, usdt) = regtest_assets();

    let err = select(Args {
        policy_asset,
        utxos: vec![
            utxo(WalletType::AMP2, usdt, 0, 100_000),
            utxo(WalletType::AMP2, policy_asset, 1, 10),
        ],
        recipients: vec![Recipient {
            address: RecipientAddress::Unknown(WalletType::AMP2),
            asset_id: usdt,
            amount: 30_000,
        }],
        deduct_fee: None,
        force_change_wallets: ChangeWallets::new(),
        use_all_utxos: false,
    })
    .unwrap_err();
    assert!(matches!(err, Error::InsufficientFunds), "{err}");
}
