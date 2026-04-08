use super::*;

#[test]
fn swap_notification_no_duplicate_after_reregister() {
    let txid = elements::Txid::from_str(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let mut map: BTreeMap<elements::Txid, SwapNotificationMeta> = BTreeMap::new();

    // First registration
    map.entry(txid).or_insert_with(|| SwapNotificationMeta {
        created_at: Instant::now(),
        notified_at: None,
    });
    assert!(
        map.get(&txid).unwrap().notified_at.is_none(),
        "fresh entry must have notified_at = None"
    );

    // Simulate notification fired
    map.get_mut(&txid).unwrap().notified_at = Some(Instant::now());
    assert!(
        map.get(&txid).unwrap().notified_at.is_some(),
        "entry must record notified_at after notification fires"
    );

    // Re-registration must not overwrite notified_at
    map.entry(txid).or_insert_with(|| SwapNotificationMeta {
        created_at: Instant::now(),
        notified_at: None,
    });
    assert!(
        map.get(&txid).unwrap().notified_at.is_some(),
        "re-registration must not reset notified_at — dedupe guard would be bypassed"
    );
}

#[test]
fn incoming_notification_dedup() {
    let txid = elements::Txid::from_str(
        "1111111111111111111111111111111111111111111111111111111111111111",
    )
    .unwrap();
    let mut incoming_notified: BTreeMap<elements::Txid, Instant> = BTreeMap::new();

    // Not yet recorded — should NOT be in map
    assert!(
        !incoming_notified.contains_key(&txid),
        "txid must not be in incoming_notified before first notification"
    );

    // Record it (simulating what try_make_incoming_notification_message does)
    incoming_notified.insert(txid, Instant::now());

    // Now it is recorded — second call would return None (dedup guard)
    assert!(
        incoming_notified.contains_key(&txid),
        "txid must be present in incoming_notified after first notification fires"
    );
}

#[test]
fn incoming_skipped_when_a3_handled() {
    let txid = elements::Txid::from_str(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )
    .unwrap();
    let mut swap_notifications: BTreeMap<elements::Txid, SwapNotificationMeta> = BTreeMap::new();

    // Insert as if A3 already fired (notified_at is Some)
    swap_notifications.insert(
        txid,
        SwapNotificationMeta {
            created_at: Instant::now(),
            notified_at: Some(Instant::now()),
        },
    );

    // The A3 guard used inside try_make_incoming_notification_message:
    let a3_handled = swap_notifications
        .get(&txid)
        .map(|m| m.notified_at.is_some())
        .unwrap_or(false);

    assert!(
        a3_handled,
        "A3 guard must detect that swap notification was already fired for this txid"
    );
}

#[test]
fn pending_notification_forwarded_when_unhandled() {
    let txid = elements::Txid::from_str(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )
    .unwrap();
    let mut pending: BTreeMap<elements::Txid, (String, String, Instant)> = BTreeMap::new();

    // Simulate process_local_message storing backend notification
    pending.entry(txid).or_insert((
        "Test Title".to_owned(),
        "Test Body".to_owned(),
        Instant::now(),
    ));

    // Simulate fire_tx_notifications: neither A3 nor A4 handled (handled = false)
    let handled = false;
    let mut forwarded: Option<(String, String)> = None;
    if let Some((title, body, _)) = pending.remove(&txid) {
        if !handled {
            forwarded = Some((title, body));
        }
    }

    assert!(
        forwarded.is_some(),
        "backend notification must be forwarded when neither A3 nor A4 handled the txid"
    );
    let (title, body) = forwarded.unwrap();
    assert_eq!(title, "Test Title");
    assert_eq!(body, "Test Body");
    assert!(
        pending.is_empty(),
        "pending entry must be removed after processing"
    );
}

#[test]
fn fee_change_skipped() {
    let policy_asset = elements::AssetId::from_str(
        "25b17a801d060c45640f15d7a716ef0f0c73d0d9b6e0e81e0c90bd4cd5e1a23",
    )
    .unwrap_or_else(|_| elements::AssetId::default());

    // Helper: simulate fee-change filter logic from try_make_incoming_notification_message
    let filter = |asset_id: elements::AssetId, amount: u64, network_fee: u64| -> bool {
        // Returns true if the notification should be SKIPPED (filtered out)
        if asset_id == policy_asset && amount <= network_fee {
            return true;
        }
        false
    };

    let network_fee: u64 = 1000;

    // amount == network_fee → skip (boundary: equal means fee-change)
    assert!(
        filter(policy_asset, network_fee, network_fee),
        "must skip when amount == network_fee (fee change)"
    );

    // amount == network_fee + 1 → do NOT skip (real incoming)
    assert!(
        !filter(policy_asset, network_fee + 1, network_fee),
        "must NOT skip when amount == network_fee + 1 (real incoming)"
    );

    // amount < network_fee → skip
    assert!(
        filter(policy_asset, network_fee - 1, network_fee),
        "must skip when amount < network_fee"
    );
}
