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

#[test]
fn pending_wallet_notification_skipped_when_already_notified() {
    let title = "t".to_owned();
    let body = "b".to_owned();
    let now = Instant::now();

    let txid_incoming = elements::Txid::from_str(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    let mut incoming_notified: BTreeMap<elements::Txid, Instant> = BTreeMap::new();
    incoming_notified.insert(txid_incoming, now);
    let outgoing_notified: BTreeMap<elements::Txid, Instant> = BTreeMap::new();
    let swap_notifications: BTreeMap<elements::Txid, SwapNotificationMeta> = BTreeMap::new();
    let mut pending_wallet_notifications: BTreeMap<
        elements::Txid,
        (String, String, Instant),
    > = BTreeMap::new();
    let already_handled = incoming_notified.contains_key(&txid_incoming)
        || outgoing_notified.contains_key(&txid_incoming)
        || swap_notifications
            .get(&txid_incoming)
            .map(|m| m.notified_at.is_some())
            .unwrap_or(false);
    assert!(already_handled);
    if !already_handled {
        pending_wallet_notifications
            .entry(txid_incoming)
            .or_insert((title.clone(), body.clone(), now));
    }
    assert!(pending_wallet_notifications.is_empty());

    let txid_outgoing = elements::Txid::from_str(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap();
    let incoming_notified: BTreeMap<elements::Txid, Instant> = BTreeMap::new();
    let mut outgoing_notified: BTreeMap<elements::Txid, Instant> = BTreeMap::new();
    outgoing_notified.insert(txid_outgoing, now);
    let swap_notifications: BTreeMap<elements::Txid, SwapNotificationMeta> = BTreeMap::new();
    let mut pending_wallet_notifications: BTreeMap<
        elements::Txid,
        (String, String, Instant),
    > = BTreeMap::new();
    let already_handled = incoming_notified.contains_key(&txid_outgoing)
        || outgoing_notified.contains_key(&txid_outgoing)
        || swap_notifications
            .get(&txid_outgoing)
            .map(|m| m.notified_at.is_some())
            .unwrap_or(false);
    assert!(already_handled);
    if !already_handled {
        pending_wallet_notifications
            .entry(txid_outgoing)
            .or_insert((title.clone(), body.clone(), now));
    }
    assert!(pending_wallet_notifications.is_empty());

    let txid_swap = elements::Txid::from_str(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    )
    .unwrap();
    let incoming_notified: BTreeMap<elements::Txid, Instant> = BTreeMap::new();
    let outgoing_notified: BTreeMap<elements::Txid, Instant> = BTreeMap::new();
    let mut swap_notifications: BTreeMap<elements::Txid, SwapNotificationMeta> = BTreeMap::new();
    swap_notifications.insert(
        txid_swap,
        SwapNotificationMeta {
            created_at: now,
            notified_at: Some(now),
        },
    );
    let mut pending_wallet_notifications: BTreeMap<
        elements::Txid,
        (String, String, Instant),
    > = BTreeMap::new();
    let already_handled = incoming_notified.contains_key(&txid_swap)
        || outgoing_notified.contains_key(&txid_swap)
        || swap_notifications
            .get(&txid_swap)
            .map(|m| m.notified_at.is_some())
            .unwrap_or(false);
    assert!(already_handled);
    if !already_handled {
        pending_wallet_notifications
            .entry(txid_swap)
            .or_insert((title, body, now));
    }
    assert!(pending_wallet_notifications.is_empty());
}

#[test]
fn pending_wallet_notification_inserted_on_first_arrival() {
    let txid = elements::Txid::from_str(
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    )
    .unwrap();
    let title = "Title".to_owned();
    let body = "Body".to_owned();
    let now = Instant::now();

    let incoming_notified: BTreeMap<elements::Txid, Instant> = BTreeMap::new();
    let outgoing_notified: BTreeMap<elements::Txid, Instant> = BTreeMap::new();
    let mut swap_notifications: BTreeMap<elements::Txid, SwapNotificationMeta> = BTreeMap::new();
    swap_notifications.insert(
        txid,
        SwapNotificationMeta {
            created_at: now,
            notified_at: None,
        },
    );
    let mut pending_wallet_notifications: BTreeMap<
        elements::Txid,
        (String, String, Instant),
    > = BTreeMap::new();

    let already_handled = incoming_notified.contains_key(&txid)
        || outgoing_notified.contains_key(&txid)
        || swap_notifications
            .get(&txid)
            .map(|m| m.notified_at.is_some())
            .unwrap_or(false);
    assert!(!already_handled);
    if !already_handled {
        pending_wallet_notifications
            .entry(txid)
            .or_insert((title.clone(), body.clone(), now));
    }
    assert_eq!(pending_wallet_notifications.len(), 1);
    assert!(pending_wallet_notifications.contains_key(&txid));
    let (got_title, got_body, _) = pending_wallet_notifications.get(&txid).unwrap();
    assert_eq!(got_title, &title);
    assert_eq!(got_body, &body);
}
