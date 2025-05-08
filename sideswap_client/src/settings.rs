use std::collections::BTreeMap;

use bitcoin::bip32::{self, Fingerprint};
use elements_miniscript::slip77::MasterBlindingKey;
use serde::{Deserialize, Serialize};
use sideswap_api::{OrderId, SessionId};
use sideswap_types::str_encoded::StrEncoded;

use crate::models;

#[derive(Eq, PartialEq, Serialize, Deserialize, Copy, Clone)]
pub enum PegDir {
    In,
    Out,
}

#[derive(Serialize, Deserialize)]
pub struct Peg {
    pub order_id: OrderId,
    pub dir: PegDir,
}

#[derive(Serialize, Deserialize, Default)]
pub struct SettingsPersistent {}

#[derive(Serialize, Deserialize, Clone)]
pub struct WatchOnly {
    pub master_blinding_key: StrEncoded<MasterBlindingKey>,
    pub native_xpub: bip32::Xpub,
    pub nested_xpub: bip32::Xpub,
    pub amp_user_xpub: bip32::Xpub,
    pub master_xpub_fingerprint: Fingerprint,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RegInfo {
    pub watch_only: Option<WatchOnly>,
    pub amp_service_xpub: String,
    pub amp_user_path: Vec<u32>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub enum AddressWallet {
    NativeReceive,
    NativeChange,
    NestedReceive,
    NestedChange,
    Amp,
}

#[derive(Serialize, Deserialize)]
pub struct AddressCacheEntry {
    pub address: models::AddressInfo,
    pub address_wallet: AddressWallet,
}

// Everything will be deleted after importing a new wallet!
#[derive(Serialize, Deserialize, Default)]
pub struct Settings {
    pub pegs: Option<Vec<Peg>>,

    pub device_key: Option<String>,

    pub market_token: Option<String>,

    #[serde(default, rename = "single_sig_registered")]
    pub nested_registered: [u32; 2],

    #[serde(default, rename = "single_sig_registered_native")]
    pub native_registered: [u32; 2],

    #[serde(default, rename = "multi_sig_registered")]
    pub amp_registered: u32,

    pub session_id: Option<SessionId>,

    // Random key used with assets_registry to encrypt data on disk
    pub master_pub_key: Option<bip32::Xpub>,

    pub reg_info: Option<RegInfo>,

    pub event_proofs: Option<serde_json::Value>,

    #[serde(default)]
    pub address_cache: Vec<AddressCacheEntry>,

    pub min_order_amounts: Option<sideswap_api::mkt::MinOrderAmounts>,

    #[serde(default)]
    pub tx_memos: BTreeMap<elements::Txid, String>,
}

const SETTINGS_NAME: &str = "settings.json";
const SETTINGS_NAME_TMP: &str = "settings.json.tmp";

pub fn save_settings(
    settings: &Settings,
    data_dir: &std::path::PathBuf,
) -> Result<(), anyhow::Error> {
    let data = serde_json::to_string(&settings)?;
    let file_path = data_dir.join(SETTINGS_NAME);
    let file_path_tmp = std::path::Path::new(&data_dir).join(SETTINGS_NAME_TMP);
    std::fs::write(&file_path_tmp, data)?;
    std::fs::rename(&file_path_tmp, file_path)?;
    Ok(())
}

pub fn load_settings(data_dir: &std::path::PathBuf) -> Result<Settings, anyhow::Error> {
    let file_path = data_dir.join(SETTINGS_NAME);
    let data = std::fs::read(file_path)?;
    let settings = serde_json::from_slice::<Settings>(&data)?;
    Ok(settings)
}

pub fn prune(_settings: &mut Settings) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_load() {
        assert!(serde_json::from_str::<Settings>("{}").is_ok());
    }
}
