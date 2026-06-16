use rand::Rng;

use super::*;

#[test]
fn basic() {
    let value = serde_json::from_str::<UnsignedBtcAmount>("1.00000123").unwrap();
    assert_eq!(value.0, 100000123);

    let value = serde_json::from_str::<UnsignedBtcAmount>("1").unwrap();
    assert_eq!(value.0, 100000000);

    serde_json::from_str::<UnsignedBtcAmount>("-1.0").unwrap_err();

    let value = serde_json::to_string(&UnsignedBtcAmount(1)).unwrap();
    assert_eq!(value, "0.00000001");

    let value = serde_json::to_string(&UnsignedBtcAmount(1000)).unwrap();
    assert_eq!(value, "0.00001");

    let value = serde_json::to_string(&UnsignedBtcAmount(u64::MAX)).unwrap();
    assert_eq!(value, "184467440737.09551615");

    let value = serde_json::to_string(&UnsignedBtcAmount(u64::MAX - 1)).unwrap();
    assert_eq!(value, "184467440737.09551614");
}

#[test]
fn basic_signed() {
    let value = serde_json::from_str::<SignedBtcAmount>("1.00000123").unwrap();
    assert_eq!(value.0, 100000123);

    let value = serde_json::from_str::<SignedBtcAmount>("1").unwrap();
    assert_eq!(value.0, 100000000);

    let value = serde_json::from_str::<SignedBtcAmount>("-1.0").unwrap();
    assert_eq!(value.0, -100000000);

    let value = serde_json::to_string(&SignedBtcAmount(1)).unwrap();
    assert_eq!(value, "0.00000001");

    let value = serde_json::to_string(&SignedBtcAmount(1000)).unwrap();
    assert_eq!(value, "0.00001");

    let value = serde_json::to_string(&SignedBtcAmount(i64::MAX)).unwrap();
    assert_eq!(value, "92233720368.54775807");

    let value = serde_json::to_string(&SignedBtcAmount(i64::MIN)).unwrap();
    assert_eq!(value, "-92233720368.54775808");
}

#[test]
fn roundtrip() {
    let mut rng = rand::thread_rng();
    for _ in 0..100 {
        let sats = rng.r#gen::<u64>();

        let str = serde_json::to_string(&UnsignedBtcAmount(sats)).unwrap();

        let parsed = serde_json::from_str::<UnsignedBtcAmount>(&str).unwrap();

        assert_eq!(parsed.0, sats);
    }
}

#[test]
fn roundtrip_signed() {
    let mut rng = rand::thread_rng();
    for _ in 0..100 {
        let sats = rng.r#gen::<i64>();

        let str = serde_json::to_string(&SignedBtcAmount(sats)).unwrap();

        let parsed = serde_json::from_str::<SignedBtcAmount>(&str).unwrap();

        assert_eq!(parsed.0, sats);
    }
}
