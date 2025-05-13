use elements::Script;

use crate::network::Network;

use super::*;

#[test]
fn roundtrip() {
    let network = Network::Regtest;

    let price = 102515.0 / 1.05;

    let event = ClientEvent::AddOrder {
        asset_pair: AssetPair {
            base: network.d().policy_asset,
            quote: network.d().known_assets.USDt,
        },
        base_amount: 1,
        price: Some(NormalFloat::new(price).unwrap()),
        price_tracking: None,
        min_price: None,
        max_price: None,
        trade_dir: TradeDir::Sell,
        ttl: None,
        receive_address: Address::p2wsh(&Script::new(), None, network.d().elements_params),
        change_address: Address::p2wsh(&Script::new(), None, network.d().elements_params),
        private: false,
        client_order_id: None,
    };

    let event_json_1 = serde_json::to_string(&event).unwrap();
    let event_2 = serde_json::from_str::<ClientEvent>(&event_json_1).unwrap();
    let event_json_2 = serde_json::to_string(&event_2).unwrap();
    assert_eq!(event_json_1, event_json_2);
}
