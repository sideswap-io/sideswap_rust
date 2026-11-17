use elements::Script;
use sideswap_types::network::Network;

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

#[test]
fn trusted_replay_matches_verified_replay() {
    let env = Env::LocalRegtest;
    let network = Network::Regtest;
    let secret_key = secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
    let public_key = secret_key.public_key(secp256k1::SECP256K1);
    let order_id = OrdId::new(42);

    let client_events = [
        ClientEvent::AddOrder {
            asset_pair: AssetPair {
                base: network.d().policy_asset,
                quote: network.d().known_assets.USDt,
            },
            base_amount: 1000,
            price: Some(NormalFloat::new(100000.0).unwrap()),
            price_tracking: None,
            min_price: None,
            max_price: None,
            trade_dir: TradeDir::Sell,
            ttl: None,
            receive_address: Address::p2wsh(&Script::new(), None, network.d().elements_params),
            change_address: Address::p2wsh(&Script::new(), None, network.d().elements_params),
            private: false,
            client_order_id: None,
        },
        ClientEvent::EditOrder {
            order_id,
            base_amount: Some(500),
            price: None,
            price_tracking: None,
            min_price: None,
            max_price: None,
            receive_address: None,
            change_address: None,
        },
        ClientEvent::Ack { nonce: 1 },
    ];

    // Build a signed event chain the same way the client does
    let mut signer = EventProofs::new(env, public_key);
    let mut events = Vec::new();
    for (index, event) in client_events.into_iter().enumerate() {
        let signature = signer.sign_client_event(event.clone(), &secret_key);
        let event = mkt::EventWithSignature::Client { event, signature };
        signer.add_event(event.clone()).unwrap();
        events.push(event);
        if index == 0 {
            let event = mkt::EventWithSignature::Server {
                event: ServerEvent::OrderCreated {
                    order_id,
                    created_at: TimestampMs::from_millis(1),
                },
            };
            signer.add_event(event.clone()).unwrap();
            events.push(event);
        }
    }

    let mut verified = EventProofs::new(env, public_key);
    let mut trusted = EventProofs::new(env, public_key);
    for event in events {
        verified.add_event(event.clone()).unwrap();
        trusted.add_event_trusted(event).unwrap();
    }

    assert_eq!(
        serde_json::to_string(&verified).unwrap(),
        serde_json::to_string(&trusted).unwrap(),
    );
    assert_eq!(trusted.get_active_orders()[&order_id].base_amount, 500);

    // A new event signed by the client must still verify against the state restored without checks
    let next = ClientEvent::Ack { nonce: 2 };
    let signature = signer.sign_client_event(next.clone(), &secret_key);
    trusted.add_client_event(next, &signature).unwrap();
}
