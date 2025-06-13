use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use crate::{ffi::proto, models, settings::WatchOnly};
use bitcoin::bip32;
use elements_miniscript::slip77::MasterBlindingKey;
use sideswap_common::env::Env;
use sideswap_jade::{jade_mng, models::JadeNetwork};
use sideswap_types::proxy_address::ProxyAddress;

#[derive(Clone)]
pub struct JadeData {
    pub env: Env,
    pub jade: Arc<jade_mng::ManagedJade>,
}

#[derive(Clone)]
pub enum WalletInfo {
    Mnemonic(bip39::Mnemonic),
    Jade(JadeData, WatchOnly),
}

impl WalletInfo {
    pub fn master_blinding_key(&self) -> MasterBlindingKey {
        match &self {
            WalletInfo::Mnemonic(mnemonic) => {
                let seed = mnemonic.to_seed("");
                MasterBlindingKey::from_seed(&seed)
            }
            WalletInfo::Jade(_jade_data, watch_only) => watch_only.master_blinding_key.into_inner(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElectrumServer {
    SideSwap,
    SideSwapCn,
    Blockstream,
    Custom {
        host: String,
        port: u16,
        use_tls: bool,
    },
}

impl Default for ElectrumServer {
    fn default() -> Self {
        Self::SideSwap
    }
}

#[derive(Clone)]
pub struct LoginInfo {
    pub account: proto::Account,
    pub env: Env,
    pub cache_dir: PathBuf,
    pub wallet_info: WalletInfo,
    pub electrum_server: ElectrumServer,
    pub proxy: Option<ProxyAddress>,
}

pub enum WalletNotif {
    Transaction(elements::Txid),
    Block,
    LwkSynced,
    LwkFailed { error_msg: String },
    AmpConnected { subaccount: u32, gaid: String },
    AmpDisconnected,
    AmpFailed { error_msg: String },
    AmpBalanceUpdated,
}

pub type NotifCallback = Box<dyn Fn(proto::Account, WalletNotif) + Send + Sync>;

impl JadeData {
    pub fn resolve_xpub(
        &self,
        network: JadeNetwork,
        path: &[u32],
    ) -> Result<bip32::Xpub, anyhow::Error> {
        let xpub = self.jade.resolve_xpub(network, path)?;
        let xpub = bip32::Xpub::from_str(&xpub)?;
        Ok(xpub)
    }

    pub fn master_blinding_key(&self) -> Result<MasterBlindingKey, anyhow::Error> {
        let master_blinding_key = self.jade.master_blinding_key()?;
        let master_blinding_key = <[u8; 32]>::try_from(master_blinding_key).expect("must not fail");
        Ok(MasterBlindingKey::from(master_blinding_key))
    }
}

impl WalletInfo {
    pub fn mnemonic(&self) -> Option<&bip39::Mnemonic> {
        match self {
            WalletInfo::Mnemonic(mnemonic) => Some(mnemonic),
            WalletInfo::Jade(_, _) => None,
        }
    }

    pub fn hw_data(&self) -> Option<&JadeData> {
        match self {
            WalletInfo::Jade(hw_data, _) => Some(hw_data),
            WalletInfo::Mnemonic(_) => None,
        }
    }
}

#[derive(Copy, Clone)]
pub enum GetTransactionsOpt {
    PendingOnly,
    All,
}

#[derive(Clone)]
pub struct TransactionList {
    pub tip_height: u32,
    pub list: Vec<models::Transaction>,
}

pub struct AddressList {
    pub list: Vec<models::AddressInfo>,
}

pub trait GdkSes: Send + Sync {
    fn login_info(&self) -> &LoginInfo;

    fn get_transactions(&self, opts: GetTransactionsOpt) -> Result<TransactionList, anyhow::Error>;

    fn broadcast_tx(&self, tx: &str) -> Result<(), anyhow::Error>;

    fn get_utxos(&self) -> Result<models::UtxoList, anyhow::Error>;
}
