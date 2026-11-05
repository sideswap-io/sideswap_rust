use std::{collections::BTreeMap, str::FromStr};

use sideswap_types::network::Network;

use crate::utxo_select::WalletType;

use super::*;

#[test]
fn deduct_fee() {
    let network = Network::Regtest;

    let policy_asset = network.d().policy_asset;
    let fee_asset = network.d().known_assets.USDt;
    let txid = elements::Txid::from_str(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();

    let res = select(Args {
        policy_asset,
        fee_asset,
        utxos: vec![Utxo {
            wallet: WalletType::Nested,
            txid,
            vout: 0,
            asset_id: fee_asset,
            value: 10000000,
        }],
        recipients: vec![Recipient {
            address: RecipientAddress::Unknown(WalletType::Nested),
            asset_id: fee_asset,
            amount: 10000000,
        }],
        server_utxos: vec![Utxo {
            wallet: WalletType::Native,
            txid,
            vout: 1,
            asset_id: policy_asset,
            value: 10000,
        }],
        price: 12345.56,
        fixed_fee: 234567,
        deduct_fee: Some(0),
        force_change_wallets: BTreeMap::new(),
        use_all_utxos: false,
    })
    .unwrap();

    assert!(res.server_fee > 0);
}

#[test]
fn amp2_utxos() {
    let network = Network::Regtest;

    let policy_asset = network.d().policy_asset;
    let fee_asset = network.d().known_assets.USDt;
    let txid = elements::Txid::from_str(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();

    let res = select(Args {
        policy_asset,
        fee_asset,
        utxos: vec![Utxo {
            wallet: WalletType::AMP2,
            txid,
            vout: 0,
            asset_id: fee_asset,
            value: 10000000,
        }],
        recipients: vec![Recipient {
            address: RecipientAddress::Unknown(WalletType::AMP2),
            asset_id: fee_asset,
            amount: 1000000,
        }],
        server_utxos: vec![Utxo {
            wallet: WalletType::Native,
            txid,
            vout: 1,
            asset_id: policy_asset,
            value: 10000,
        }],
        price: 12345.56,
        fixed_fee: 234567,
        deduct_fee: None,
        force_change_wallets: BTreeMap::new(),
        use_all_utxos: false,
    })
    .unwrap();

    assert_eq!(res.inputs.len(), 1);
    assert_eq!(res.inputs[0].wallet, WalletType::AMP2);
    // The fee asset change stays in the AMP2 wallet
    assert_eq!(res.change.len(), 1);
    assert_eq!(res.change[0].wallet, WalletType::AMP2);
    assert_eq!(res.change[0].asset_id, fee_asset);

    // The user AMP2 input and the server input, the recipient and the server outputs,
    // the user and the server change outputs
    let weight = tx_weight(
        [WalletType::AMP2, WalletType::Native].into_iter(),
        [
            &RecipientAddress::Unknown(WalletType::AMP2),
            &RecipientAddress::Unknown(WalletType::Native),
        ]
        .into_iter(),
        [WalletType::AMP2, WalletType::Native].into_iter(),
    );
    assert_eq!(res.network_fee, weight_to_fee(weight, DEFAULT_FEE_RATE));
    assert_eq!(
        res.server_fee,
        (res.network_fee as f64 * 12345.56) as u64 + 234567
    );
}
