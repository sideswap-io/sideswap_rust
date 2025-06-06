use crate::be::BEBlockHeader;
use crate::{be::BEBlockHash, model::Settings, model::TransactionType, State};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type NativeType =
    (extern "C" fn(*const libc::c_void, *const libc::c_char), *const libc::c_void);

#[derive(Clone)]
pub struct NativeNotif {
    pub callback: Option<std::sync::Arc<dyn Fn(Notification) + Send + Sync>>,

    /// With testing feature notifications are simply pushed in the following vec so assertions
    /// could check over it, it's a mutex so that methods signatures doesn't need to be mut
    #[cfg(feature = "testing")]
    pub testing: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
}

#[derive(Serialize, Deserialize)]
pub struct Notification {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkNotification>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TransactionNotification>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<BlockNotification>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subaccount: Option<SubaccountNotification>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<Settings>,

    pub event: Kind,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Network,
    Transaction,
    Block,
    Subaccount,
    Settings,
}

#[derive(Serialize, Deserialize)]
pub struct NetworkNotification {
    pub current_state: State,
    pub next_state: State,
    pub wait_ms: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TransactionNotification {
    /// The wallet subaccounts the transaction affects.
    pub subaccounts: Vec<u32>,

    /// The txid of the transaction.
    #[serde(rename = "txhash")]
    pub txid: bitcoin::Txid,

    /// The net amount of the transaction, always positive.
    ///
    /// None if Liquid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub satoshi: Option<u64>,

    /// Transaction type.
    ///
    /// None if Liquid.
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<TransactionType>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BlockNotification {
    /// The height of the block.
    pub block_height: u32,

    /// The hash of the block.
    pub block_hash: bitcoin::BlockHash,

    /// The hash of the block prior to this block
    pub previous_hash: bitcoin::BlockHash,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SubaccountEventType {
    New,
    Synced,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SubaccountNotification {
    /// The subaccount numbers.
    pub accounts: Vec<u32>,

    /// The type of subaccount event occurred.
    pub event_type: SubaccountEventType,
}

impl Notification {
    pub fn new_network(current: State, next: State) -> Self {
        Notification {
            network: Some(NetworkNotification {
                current_state: current,
                next_state: next,
                wait_ms: 0,
            }),
            transaction: None,
            block: None,
            subaccount: None,
            settings: None,
            event: Kind::Network,
        }
    }

    pub fn new_transaction(ntf: &TransactionNotification) -> Self {
        Notification {
            network: None,
            transaction: Some(ntf.clone()),
            block: None,
            subaccount: None,
            settings: None,
            event: Kind::Transaction,
        }
    }

    pub fn new_block_from_hashes(height: u32, hash: &BEBlockHash, prev_hash: &BEBlockHash) -> Self {
        Notification {
            network: None,
            transaction: None,
            block: Some(BlockNotification {
                block_height: height,
                block_hash: hash.into_bitcoin(),
                previous_hash: prev_hash.into_bitcoin(),
            }),
            subaccount: None,
            settings: None,
            event: Kind::Block,
        }
    }

    pub fn new_block_from_header(height: u32, header: &BEBlockHeader) -> Self {
        Notification {
            network: None,
            transaction: None,
            block: Some(BlockNotification {
                block_height: height,
                block_hash: header.block_hash().into_bitcoin(),
                previous_hash: header.prev_block_hash().into_bitcoin(),
            }),
            subaccount: None,
            settings: None,
            event: Kind::Block,
        }
    }

    pub fn subaccounts(accounts: Vec<u32>, event_type: SubaccountEventType) -> Self {
        Notification {
            network: None,
            transaction: None,
            block: None,
            subaccount: Some(SubaccountNotification {
                accounts,
                event_type,
            }),
            settings: None,
            event: Kind::Subaccount,
        }
    }
}

impl NativeNotif {
    #[cfg(not(feature = "testing"))]
    pub fn new() -> Self {
        NativeNotif {
            callback: None,
        }
    }

    // TODO once every notification is a struct, accept a `Notification` here
    fn notify(&self, data: Notification) {
        // info!("push notification: {:?}", data);
        if let Some(callback) = self.callback.as_ref() {
            callback(data);
        } else {
            if !cfg!(feature = "testing") {
                warn!("no registered handler to receive notification");
            }
        }
    }

    pub fn set_native(&mut self, _native_type: NativeType) {}

    pub fn block_from_hashes(&self, height: u32, hash: &BEBlockHash, prev_hash: &BEBlockHash) {
        self.notify(Notification::new_block_from_hashes(height, hash, prev_hash));
    }

    pub fn block_from_header(&self, height: u32, header: &BEBlockHeader) {
        self.notify(Notification::new_block_from_header(height, &header));
    }

    pub fn settings(&self, settings: &Settings) {
        self.notify(Notification {
            network: None,
            transaction: None,
            block: None,
            subaccount: None,
            settings: Some(settings.clone()),
            event: Kind::Settings,
        });
    }

    pub fn updated_txs(&self, ntf: &TransactionNotification) {
        self.notify(Notification::new_transaction(ntf));
    }

    pub fn network(&self, current: State, desired: State) {
        self.notify(Notification::new_network(current, desired));
    }

    pub fn subaccount_new(&self, pointer: u32) {
        self.notify(Notification::subaccounts(vec![pointer], SubaccountEventType::New));
    }

    pub fn subaccount_synced(&self, accounts: Vec<u32>) {
        self.notify(Notification::subaccounts(accounts, SubaccountEventType::Synced));
    }

    #[cfg(not(feature = "testing"))]
    pub fn push(&self, _value: Value) {
        //does nothing in non testing mode
    }
}

#[cfg(feature = "testing")]
impl NativeNotif {
    pub fn new() -> Self {
        NativeNotif {
            native: None,
            testing: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
        }
    }

    pub fn filter_events(&self, event: &str) -> Vec<Value> {
        self.testing
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.get("event").unwrap().as_str().unwrap() == event)
            .cloned()
            .collect()
    }

    pub fn push(&self, value: Value) {
        self.testing.lock().unwrap().push(value);
    }
}
