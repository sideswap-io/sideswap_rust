alter table swaps rename to monitored_txs;

alter table monitored_txs add column note text;
