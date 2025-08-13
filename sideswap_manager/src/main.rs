use std::{path::PathBuf, sync::Arc};

use serde::Deserialize;
use sideswap_common::dealer_ticker::{TickerLoader, WhitelistedAssets};

mod api;
mod db;
mod error;
mod models;
mod worker;
mod ws_server;

#[derive(Debug, Deserialize)]
struct Settings {
    env: sideswap_common::env::Env,
    work_dir: PathBuf,

    mnemonic: bip39::Mnemonic,
    script_variant: sideswap_lwk::ScriptVariant,
    ws_server: ws_server::Config,
    whitelisted_assets: Option<WhitelistedAssets>,
    affiliate_api_key: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    assert!(
        args.len() == 2,
        "Specify a single argument for the path to the config file"
    );
    let config_path = &args[1];

    let mut conf = config::Config::new();
    conf.merge(config::File::with_name(config_path))
        .expect("can't load config");
    conf.merge(config::Environment::with_prefix("app").separator("_"))
        .expect("reading env failed");
    let settings: Settings = conf.try_into().expect("invalid config");

    assert!(
        !settings.work_dir.starts_with("/tmp"),
        "invalid work_dir value: {:?}\nplease do not keep work dir in /tmp, the contents must be preserved",
        settings.work_dir,
    );

    sideswap_dealer::logs::init(&settings.work_dir);

    sideswap_common::panic_handler::install_panic_handler();

    let db_file = settings.work_dir.join("db.sqlite");
    let db = db::Db::open_file(db_file).await;

    let ticker_loader = Arc::new(
        TickerLoader::load(
            &settings.work_dir,
            settings.whitelisted_assets.as_ref(),
            settings.env.d().network,
        )
        .await
        .expect("must not fail"),
    );

    let (command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();

    ws_server::start(settings.ws_server.clone(), command_sender);

    worker::run(settings, command_receiver, ticker_loader, db).await;
}
