use std::str::FromStr;

use crate::network::Network;

use super::*;

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
