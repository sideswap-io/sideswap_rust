use super::*;

#[tokio::test]
async fn basic() {
    for source in [Source::Blockstream, Source::Github] {
        for network in [Network::Liquid, Network::LiquidTestnet] {
            let path = format!("/tmp/sideswap/{source:?}");
            let gdk_registry = GdkRegistryCache::new(network, &path, source).await;
            let all_assets = gdk_registry.get_all_assets();
            for asset_id in all_assets.keys() {
                gdk_registry.get_asset(asset_id).unwrap();
            }
        }
    }
}
