alter table monitored_txs rename column note to description;

alter table monitored_txs add column user_note text;
