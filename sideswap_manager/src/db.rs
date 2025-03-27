use std::path::Path;

use sideswap_api::OrderId;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    types::Text,
    SqlitePool,
};

use crate::models::{MonitoredTx, Peg};

pub struct Db {
    pool: SqlitePool,
}

impl Db {
    async fn open_with_options(option: SqliteConnectOptions) -> Self {
        let pool = SqlitePoolOptions::new()
            .connect_with(option.foreign_keys(true))
            .await
            .expect("should not fail");

        sqlx::migrate!().run(&pool).await.expect("should not fail");

        Self { pool }
    }

    pub async fn open_file(path: impl AsRef<Path>) -> Self {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);

        Self::open_with_options(options).await
    }

    pub async fn add_peg(&self, peg: Peg) {
        let order_id = Text(peg.order_id.0);
        sqlx::query!("insert into pegs (order_id) values (?)", order_id)
            .execute(&self.pool)
            .await
            .expect("must not fail");
    }

    pub async fn delete_peg(&self, order_id: OrderId) {
        let order_id = Text(order_id);
        sqlx::query!("delete from pegs where order_id = ?", order_id)
            .execute(&self.pool)
            .await
            .expect("must not fail");
    }

    pub async fn load_pegs(&self) -> Vec<Peg> {
        sqlx::query_as!(
            Peg,
            "select order_id as 'order_id!: Text<OrderId>' from pegs"
        )
        .fetch_all(&self.pool)
        .await
        .expect("must not fail")
    }

    pub async fn add_monitored_tx(&self, tx: MonitoredTx) {
        let txid = Text(tx.txid.0);
        sqlx::query!(
            "insert into monitored_txs (txid, description, user_note) values (?, ?, ?)",
            txid,
            tx.description,
            tx.user_note,
        )
        .execute(&self.pool)
        .await
        .expect("must not fail");
    }

    pub async fn delete_monitored_tx(&self, txid: elements::Txid) {
        let txid = Text(txid);
        sqlx::query!("delete from monitored_txs where txid = ?", txid)
            .execute(&self.pool)
            .await
            .expect("must not fail");
    }

    pub async fn load_monitored_txs(&self) -> Vec<MonitoredTx> {
        sqlx::query_as!(
            MonitoredTx,
            "select txid as 'txid!: Text<elements::Txid>', description, user_note from monitored_txs"
        )
        .fetch_all(&self.pool)
        .await
        .expect("must not fail")
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

#[cfg(test)]
mod tests;
