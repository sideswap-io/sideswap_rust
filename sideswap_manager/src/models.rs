use sideswap_api::OrderId;
use sqlx::types::Text;

#[derive(Clone)]
pub struct Peg {
    pub order_id: Text<OrderId>,
}

#[derive(Clone)]
pub struct MonitoredTx {
    pub txid: Text<elements::Txid>,
    pub description: Option<String>,
    pub user_note: Option<String>,
}
