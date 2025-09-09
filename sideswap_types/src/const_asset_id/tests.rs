use std::str::FromStr;

#[test]
fn basic() {
    let asset_id = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";
    let a = crate::const_asset_id::const_asset_id(asset_id);
    let b = elements::AssetId::from_str(asset_id).unwrap();
    assert_eq!(a, b);
}
