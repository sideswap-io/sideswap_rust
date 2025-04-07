use std::{path::Path, str::FromStr};

use sideswap_api::OrderId;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    types::Text,
    SqlitePool,
};

use crate::models::{self, MonitoredTx, Peg};

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

    pub async fn add_address(&self, addr: models::Address) {
        sqlx::query!(
            "insert into addresses (ind, address, user_note) values (?, ?, ?)",
            addr.ind,
            addr.address,
            addr.user_note,
        )
        .execute(&self.pool)
        .await
        .expect("must not fail");
    }

    pub async fn load_addresses(&self) -> Vec<models::Address> {
        sqlx::query_as!(
            models::Address,
            "select ind, address as 'address!: Text<elements::Address>', user_note from addresses"
        )
        .fetch_all(&self.pool)
        .await
        .expect("must not fail")
    }

    pub async fn set_setting<T: ToString>(&self, key: &str, value: &T) {
        let value = value.to_string();

        sqlx::query!("delete from settings where key = ?", key)
            .execute(&self.pool)
            .await
            .expect("must not fail");

        sqlx::query!(
            "insert into settings (key, value) values (?, ?)",
            key,
            value,
        )
        .execute(&self.pool)
        .await
        .expect("must not fail");
    }

    pub async fn get_setting<T>(&self, key: &str) -> Option<T>
    where
        T: FromStr,
        <T as FromStr>::Err: std::fmt::Display,
    {
        let value = sqlx::query_scalar!("select value from settings where key = ?", key)
            .fetch_optional(&self.pool)
            .await
            .expect("must not fail");

        value.map(|value| {
            T::from_str(&value).unwrap_or_else(|err| {
                panic!("invalid setting value, key: {key}, value: {value}: {err}")
            })
        })
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

#[cfg(test)]
mod tests;
