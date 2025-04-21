use std::{collections::BTreeMap, str::FromStr};

use crate::{network::Network, utxo_select::WalletType};

use super::*;

#[test]
fn deduct_fee() {
    let network = Network::Regtest;

    let policy_asset = network.d().policy_asset.asset_id();
    let fee_asset = network.d().known_assets.USDt.asset_id();
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
