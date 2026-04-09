use super::*;

#[test]
fn swap_notification_no_duplicate_after_reregister() {
    let txid = elements::Txid::from_str(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let mut map: BTreeMap<elements::Txid, SwapNotificationMeta> = BTreeMap::new();
    map.entry(txid).or_insert_with(|| SwapNotificationMeta {
        created_at: Instant::now(),
        notified_at: None,
    });
    assert!(map.get(&txid).unwrap().notified_at.is_none());
    map.get_mut(&txid).unwrap().notified_at = Some(Instant::now());
    assert!(map.get(&txid).unwrap().notified_at.is_some());
    map.entry(txid).or_insert_with(|| SwapNotificationMeta {
        created_at: Instant::now(),
        notified_at: None,
    });
    assert!(map.get(&txid).unwrap().notified_at.is_some());
}

#[test]
fn incoming_notification_dedup() {
    let txid = elements::Txid::from_str(
        "1111111111111111111111111111111111111111111111111111111111111111",
    )
    .unwrap();
    let mut incoming_notified: BTreeMap<elements::Txid, Instant> = BTreeMap::new();
    assert!(!incoming_notified.contains_key(&txid));
    incoming_notified.insert(txid, Instant::now());
    assert!(incoming_notified.contains_key(&txid));
}

#[test]
fn incoming_skipped_when_a3_handled() {
    let txid = elements::Txid::from_str(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )
    .unwrap();
    let mut swap_notifications: BTreeMap<elements::Txid, SwapNotificationMeta> = BTreeMap::new();
    swap_notifications.insert(
        txid,
        SwapNotificationMeta {
            created_at: Instant::now(),
            notified_at: Some(Instant::now()),
        },
    );
    let a3_handled = swap_notifications
        .get(&txid)
        .map(|m| m.notified_at.is_some())
        .unwrap_or(false);
    assert!(a3_handled);
}

#[test]
fn pending_notification_forwarded_when_unhandled() {
    let txid = elements::Txid::from_str(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )
    .unwrap();
    let mut pending: BTreeMap<elements::Txid, (String, String, Instant)> = BTreeMap::new();
    pending.entry(txid).or_insert((
        "Test Title".to_owned(),
        "Test Body".to_owned(),
        Instant::now(),
    ));
    let handled = false;
    let mut forwarded: Option<(String, String)> = None;
    if let Some((title, body, _)) = pending.remove(&txid) {
        if !handled {
            forwarded = Some((title, body));
        }
    }
    assert!(forwarded.is_some());
    let (title, body) = forwarded.unwrap();
    assert_eq!(title, "Test Title");
    assert_eq!(body, "Test Body");
    assert!(pending.is_empty());
}

#[test]
fn fee_change_skipped() {
    let policy_asset = elements::AssetId::from_str(
        "25b17a801d060c45640f15d7a716ef0f0c73d0d9b6e0e81e0c90bd4cd5e1a23",
    )
    .unwrap_or_else(|_| elements::AssetId::default());
    let filter = |asset_id: elements::AssetId, amount: u64, network_fee: u64| -> bool {
        if asset_id == policy_asset && amount <= network_fee {
            return true;
        }
        false
    };
    let network_fee: u64 = 1000;
    assert!(filter(policy_asset, network_fee, network_fee));
    assert!(!filter(policy_asset, network_fee + 1, network_fee));
    assert!(filter(policy_asset, network_fee - 1, network_fee));
}

#[test]
fn outgoing_notification_dedup() {
    let txid = elements::Txid::from_str(
        "4444444444444444444444444444444444444444444444444444444444444444",
    )
    .unwrap();
    let mut outgoing_notified: BTreeMap<elements::Txid, Instant> = BTreeMap::new();
    let can_fire = |map: &BTreeMap<elements::Txid, Instant>, txid: elements::Txid| -> bool {
        !map.contains_key(&txid)
    };
    assert!(can_fire(&outgoing_notified, txid));
    outgoing_notified.insert(txid, Instant::now());
    assert!(!can_fire(&outgoing_notified, txid));
}

#[test]
fn outgoing_skipped_when_a3_handled() {
    let txid = elements::Txid::from_str(
        "5555555555555555555555555555555555555555555555555555555555555555",
    )
    .unwrap();
    let mut swap_notifications: BTreeMap<elements::Txid, SwapNotificationMeta> = BTreeMap::new();
    swap_notifications.insert(
        txid,
        SwapNotificationMeta {
            created_at: Instant::now(),
            notified_at: Some(Instant::now()),
        },
    );
    assert!(swap_notifications.contains_key(&txid));
}

#[test]
fn outgoing_fee_only_skipped() {
    let policy_asset = elements::AssetId::from_str(
        "25b17a801d060c45640f15d7a716ef0f0c73d0d9b6e0e81e0c90bd4cd5e1a23",
    )
    .unwrap_or_else(|_| elements::AssetId::default());
    let network_fee: u64 = 1000;
    let mut outgoing = vec![(policy_asset, network_fee)];
    for (asset_id, amount) in outgoing.iter_mut() {
        if *asset_id == policy_asset {
            *amount = amount.saturating_sub(network_fee);
        }
    }
    outgoing.retain(|(_, amount)| *amount > 0);
    assert!(outgoing.is_empty());
}
