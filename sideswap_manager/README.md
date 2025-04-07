# SideSwap Manager

A self-hosted program for managing liquid bitcoin assets and accessing the [SideSwap](https://sideswap.io/) API.

This manager:

- Loads a single configuration file (TOML) with your mnemonic, environment (testnet or mainnet), and other settings.
- Runs a WebSocket server on your machine.
- Accepts WebSocket control connections to perform swaps, send transactions, get wallet status, request new addresses, and more.

---

## Table of Contents

1. [Building and Installation](#building-and-installation)
1. [Configuration](#configuration)
1. [Running the program](#running-the-program)
1. [Connecting to the program](#connecting-to-the-program)
1. [Example receiving assets](#receiving-assets)
1. [Example sending assets](#sending-assets)
1. [Example making a swap](#making-swaps)
1. [Example of a peg-in](#making-peg-ins)
1. [Example of a peg-out](#making-peg-outs)
1. [API reference](#api-reference)

---

## Building and Installation

1. **Install Rust**
   The easiest way is via [rustup](https://rustup.rs/).

1. **Clone the repository**
   ```bash
   git clone https://github.com/sideswap-io/sideswap_rust
   cd sideswap_rust
   ```

1. **Build the SideSwap Manager**
   ```bash
   cargo build --release --package sideswap_manager
   ```
   This produces a binary at `./target/release/sideswap_manager`.

---

## Configuration

The manager uses a single TOML configuration file. An example:

```toml
env = "Testnet" # SideSwap testnet server (Liquid Testnet network)
#env = "Prod" # SideSwap production server (Liquid main network)

# The dir for storing work files. The contents must be preserved for wallet state.
work_dir = "/home/user/sideswap_manager/work_dir"

mnemonic = "<YOUR_MNEMONIC>"
script_variant = "wpkh" # Alternatively "shwpkh" for nested segwit addresses

[ws_server]
listen_on = "127.0.0.1:3102"
```

**Key fields**:

- `env`: can be `"Prod"` or `"Testnet"`.
- `work_dir`: a directory on your system where the manager will store wallet-related data (e.g., DB, logs).
- `mnemonic`: your 12- or 24-word seed phrase. **Keep this secret and secure.**
- `script_variant`: either `wpkh` (native segwit) or `shwpkh` (nested segwit).
- `[ws_server].listen_on`: IP and port on which the manager will open its WebSocket server.

See [Settings](https://sideswap.io/docs/rust/sideswap_manager/struct.Settings.html) API reference for details.

Fields can be set using environment variables. For example, to set the mnemonic, use the `APP_MNEMONIC` environment variable. In this case, the mnemonic can be removed from the config.

Using different mnemonic/script variants with the same working directory is not supported.
The program stores the current wallet ID in the DB in the working directory and checks it on startup.

When started, the manager creates a format file in the work directory.
Edit `log_config.toml` if you want to adjust the logging.
For example, to redirect output to stdout instead of a file, change the `[root]` section:

```toml
[root]
level = "debug"
appenders = ["stdout"]
```
See [log4rs](https://docs.rs/log4rs/latest/log4rs/) for more details.

---
## Running the program
```bash
./target/release/sideswap_manager config/example.toml
```

The application will:

- Parse your config file.
- Initialize the wallet.
- Connect to SideSwap servers and Electrum (Electrs) servers in the background.
- Start a local WebSocket server listening at `listen_on` (e.g., `127.0.0.1:3102`).

---

## Connecting to the program

You can connect to the WebSocket interface using any WebSocket client.
For example, using [`websocat`](https://github.com/vi/websocat):

```bash
websocat ws://127.0.0.1:3102
```

Upon connection, the manager will begin sending notifications (e.g., wallet balances, peg statuses) and will accept JSON requests.

---

## Example Usage

### Receiving assets

Below is a step-by-step example of using the manager to receive assets.

1. **Connect via WebSocket**
   The manager immediately sends your current wallet balances (if any):
   ```json
   {"Notif":{"notif":{"Balances":{"balances":{"L-BTC":0.00037277},"confirmed":{"L-BTC":0.00037277}}}}}
   ```

1. **Request a new address**
   ```json
   {"Req":{"id":1,"req":{"NewAddress": {"user_note": "My note"}}}}
   ```
   ```json
   {"Resp":{"id":1,"resp":{"NewAddress":{"index":0,"address":"lq1qqwn8f2zpzxj26xapdk23u5v3ky0jhu7f6xnl29dh8g53s4vw8awf0d8jvpka5y49xzpcz4lnjnpqvu4exsunknpake9d22sxa"}}}}
   ```
   Sending another `NewAddress` request will return a new address (until the gap limit of 20 is reached).

1. **Send some asset to the new address**
   Then wait for the balance notification:
   ```json
   {"Notif":{"notif":{"Balances":{"balances":{"L-BTC":0.00087251},"confirmed":{"L-BTC":0.00037277}}}}}
   ```
   Initially, the wallet sees an unconfirmed transaction (`balances` differs from `confirmed`).
   After a short time (Liquid Bitcoin block time is about 1 minute) the balance is reported as confirmed:
   ```json
   {"Notif":{"notif":{"Balances":{"balances":{"L-BTC":0.00087251},"confirmed":{"L-BTC":0.00087251}}}}}
   ```
   Received UTXOs can be spent without waiting for confirmation.

1. **List wallet transactions**
   ```json
   {"Req":{"id":1,"req":{"GetWalletTxs": {}}}}
   ```
   ```json
   {"Resp":{"id":1,"resp":{"GetWalletTxs":{"txs":[{"txid":"4616ba6f6707544712aa1838481e3b6f7b03ff37d8946a404d7a5630d82b2e08","height":null,"balance":{"L-BTC":0.00049974},"network_fee":26,"timestamp":null,"tx_type":"Incoming"},{"txid":"64f15dd0720677df640f285b8a89cd085967e994d6d27ca31f443a20b88ee19e","height":3320223,"balance":{"L-BTC":0.00037277},"network_fee":22,"timestamp":1743746770000,"tx_type":"Incoming"}]}}}}
   ```
   `height` and `timestamp` will be `null` for transactions still in the mempool.

1. **List generated addresses**

   Previously generated addresses can be loaded from the DB with this request:

   ```json
   {"Req":{"id":1,"req":{"ListAddresses": {}}}}
   ```

   ```json
   {"Resp":{"id":1,"resp":{"ListAddresses":{"addresses":[{"index":0,"address":"lq1qqwn8f2zpzxj26xapdk23u5v3ky0jhu7f6xnl29dh8g53s4vw8awf0d8jvpka5y49xzpcz4lnjnpqvu4exsunknpake9d22sxa","user_note":"My note"}]}}}}
   ```

### Sending assets

In addition to the sending assets, the wallet must have some L-BTC to pay the network fee (about 25-50 L-sats per transaction).
Below is a step-by-step example of sending assets (using Liquid Testnet).

1. **Create a transaction**

   ```json
   {"Req":{"id":1,"req":{"CreateTx": {"recipients":[{"address":"vjU3KGnCKrsZkVPMTzTBo31fPrcXpqNsyoSAEvLP2apepS1JZqvN69oj4deXt3AiBuY1ZjzRCdLkb1aQ", "asset":"USDt", "amount": 10}]}}}}
   ```
   ```json
   {"Resp":{"id":1,"resp":{"CreateTx":{"txid":"ca461ad0332f1f51ff98bc5e21bde82ccfbe74022d8630eab06cf80014e6434b","network_fee":47}}}}
   ```

1. **Send the transaction**

   ```json
   {"Req":{"id":1,"req":{"SendTx": {"txid":"ca461ad0332f1f51ff98bc5e21bde82ccfbe74022d8630eab06cf80014e6434b", "user_note":"My note"}}}}
   ```
   ```json
   {"Resp":{"id":1,"resp":{"SendTx":{"res_wallet":{"success":{}},"res_server":{"success":{}}}}}}
   ```
   *Warning*: If the request fails, it is generally not safe to assume the transaction didn’t get broadcast.
   See [SendTx](https://sideswap.io/docs/rust/sideswap_manager/api/struct.SendTxReq.html) documentation for details.

1. **List monitored transactions***

   ```json
   {"Req":{"id":1,"req":{"GetMonitoredTxs": {}}}}
   ```
   ```json
   {"Resp":{"id":1,"resp":{"GetMonitoredTxs":{"txs":[{"txid":"ca461ad0332f1f51ff98bc5e21bde82ccfbe74022d8630eab06cf80014e6434b","status":"Confirmed","description":"send 10 USDt to vjU3KGnCKrsZkVPMTzTBo31fPrcXpqNsyoSAEvLP2apepS1JZqvN69oj4deXt3AiBuY1ZjzRCdLkb1aQ","user_note":"My note"}]}}}}
   ```
   Initially, you might see `NotFound` or `Mempool` as status. This example shows it’s confirmed.

1. **Remove the monitored transaction** (optional)

   ```json
   {"Req":{"id":1,"req":{"DelMonitoredTx":{"txid":"ca461ad0332f1f51ff98bc5e21bde82ccfbe74022d8630eab06cf80014e6434b"}}}}
   ```
   ```json
   {"Resp":{"id":1,"resp":{"DelMonitoredTx":{}}}}
   ```

### Making swaps

Below is a short example of making a swap.

1. **Get a quote**
   ```json
   {"Req":{"id":2,"req":{"GetQuote":{"send_asset":"USDt","send_amount":20,"recv_asset":"L-BTC","receive_address":"vjU3KGnCKrsZkVPMTzTBo31fPrcXpqNsyoSAEvLP2apepS1JZqvN69oj4deXt3AiBuY1ZjzRCdLkb1aQ"}}}}
   ```
   `receive_address` can be a third-party address, such as a peg-out address.

   ```json
   {"Resp":{"id":2,"resp":{"GetQuote":{"quote_id":1743760325578,"recv_amount":0.00023395,"ttl":29839,"txid":"d3b6119bd965eca580c8d0f5c1230b215c252b57400f204395892f992f4720a9"}}}}
   ```

1. **Accept the quote**

   The quote can be accepted withing the TTL period.

   ```json
   {"Req":{"id":3,"req":{"AcceptQuote":{"quote_id":1743760325578}}}}
   ```
   ```json
   {"Resp":{"id":3,"resp":{"AcceptQuote":{"txid":"d3b6119bd965eca580c8d0f5c1230b215c252b57400f204395892f992f4720a9"}}}}
   ```
   *Warning*: If the request fails, it is generally not safe to assume that the swap failed.
   See [AcceptQuote](https://sideswap.io/docs/rust/sideswap_manager/api/struct.AcceptQuoteReq.html) documentation for details.

1. **Monitor the transaction**

   ```json
   {"Req":{"id":1,"req":{"GetMonitoredTxs": {}}}}
   ```
   ```json
   {"Resp":{"id":1,"resp":{"GetMonitoredTxs":{"txs":[{"txid":"d3b6119bd965eca580c8d0f5c1230b215c252b57400f204395892f992f4720a9","status":"Mempool","description":"swap 20 USDt for 0.00023395 L-BTC to vjU3KGnCKrsZkVPMTzTBo31fPrcXpqNsyoSAEvLP2apepS1JZqvN69oj4deXt3AiBuY1ZjzRCdLkb1aQ","user_note":null}]}}}}
   ```

### Making peg-ins

Below is an example of converting BTC to L-BTC.

1. **Request peg-in**

   ```json
   {"Req":{"id":3,"req":{"NewPeg":{"addr_recv":"VJLBkjLEhUUF78SNjy1zFUNaeA3SY1dBy5kxU2FmvMDrVSwPQUWAVtc5PxtbMfkp7wvCtVRgBT45d9KB","peg_in":true}}}}
   ```
   ```json
   {"Resp":{"id":3,"resp":{"NewPeg":{"peg":{"order_id":"ccfdfcf7fcff37881a111b1ef62cf9089d7847fae85c48f1ed3b1d2775d96d8c","peg_in":true,"addr_server":"bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq","addr_recv":"VJLBkjLEhUUF78SNjy1zFUNaeA3SY1dBy5kxU2FmvMDrVSwPQUWAVtc5PxtbMfkp7wvCtVRgBT45d9KB","list":[],"created_at":1743761124790,"return_address":null}}}}}
   ```

   ```json
   {"Notif":{"notif":{"PegStatus":{"peg":{"order_id":"ccfdfcf7fcff37881a111b1ef62cf9089d7847fae85c48f1ed3b1d2775d96d8c","peg_in":true,"addr_server":"bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq","addr_recv":"VJLBkjLEhUUF78SNjy1zFUNaeA3SY1dBy5kxU2FmvMDrVSwPQUWAVtc5PxtbMfkp7wvCtVRgBT45d9KB","list":[],"created_at":1743761124790,"return_address":null}}}}}
   ```

1. **Send BTC**

   Here 0.00086831 BTC was sent to `bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq`.

1. **Wait for notifications**

   - Unconfirmed transaction detected:
   ```json
   {"Notif":{"notif":{"PegStatus":{"peg":{"order_id":"ccfdfcf7fcff37881a111b1ef62cf9089d7847fae85c48f1ed3b1d2775d96d8c","peg_in":true,"addr_server":"bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq","addr_recv":"VJLBkjLEhUUF78SNjy1zFUNaeA3SY1dBy5kxU2FmvMDrVSwPQUWAVtc5PxtbMfkp7wvCtVRgBT45d9KB","list":[{"tx_hash":"730f508f9f08ed5b07bf8531b9f3ec09bb28afad6ae8ddad1daa9bf8c242264b","vout":0,"peg_amount":0.00086831,"payout_amount":0.00086537,"tx_state":"Detected","detected_confs":0,"total_confs":2,"created_at":1743761529805,"payout_txid":null}],"created_at":1743761124790,"return_address":null}}}}}
   ```
   - The transaction included in a block:
   ```json
   {"Notif":{"notif":{"PegStatus":{"peg":{"order_id":"ccfdfcf7fcff37881a111b1ef62cf9089d7847fae85c48f1ed3b1d2775d96d8c","peg_in":true,"addr_server":"bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq","addr_recv":"VJLBkjLEhUUF78SNjy1zFUNaeA3SY1dBy5kxU2FmvMDrVSwPQUWAVtc5PxtbMfkp7wvCtVRgBT45d9KB","list":[{"tx_hash":"730f508f9f08ed5b07bf8531b9f3ec09bb28afad6ae8ddad1daa9bf8c242264b","vout":0,"peg_amount":0.00086831,"payout_amount":0.00086537,"tx_state":"Detected","detected_confs":1,"total_confs":2,"created_at":1743761529805,"payout_txid":null}],"created_at":1743761124790,"return_address":null}}}}}
   ```

   - The peg-in complete:
   ```json
   {"Notif":{"notif":{"PegStatus":{"peg":{"order_id":"ccfdfcf7fcff37881a111b1ef62cf9089d7847fae85c48f1ed3b1d2775d96d8c","peg_in":true,"addr_server":"bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq","addr_recv":"VJLBkjLEhUUF78SNjy1zFUNaeA3SY1dBy5kxU2FmvMDrVSwPQUWAVtc5PxtbMfkp7wvCtVRgBT45d9KB","list":[{"tx_hash":"730f508f9f08ed5b07bf8531b9f3ec09bb28afad6ae8ddad1daa9bf8c242264b","vout":0,"peg_amount":0.00086831,"payout_amount":0.00086537,"tx_state":"Done","detected_confs":null,"total_confs":null,"created_at":1743761529805,"payout_txid":"20879e229f2a860e67c047c36d95cea0b59d6934f7165f13180108203a1023df"}],"created_at":1743761124790,"return_address":null}}}}}
   ```

1. **Remove peg-in from the DB** (optional)

   The peg-in/peg-out order can be removed from the list of monitored pegs from the DB.
   This will stops the manager from sending `PegStatusNotif` updates for it.

   ```json
   {"Req":{"id":3,"req":{"DelPeg":{"order_id":"ccfdfcf7fcff37881a111b1ef62cf9089d7847fae85c48f1ed3b1d2775d96d8c"}}}}
   ```
   ```json
   {"Resp":{"id":3,"resp":{"DelPeg":{}}}}
   ```

### Making peg-outs

Below is an example of converting L-BTC to BTC.

1. **Make a new peg-out request**

   ```json
   {"Req":{"id":3,"req":{"NewPeg":{"addr_recv":"bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq","peg_in":false}}}}
   ```

   ```json
   {"Resp":{"id":3,"resp":{"NewPeg":{"peg":{"order_id":"aa7ad2bc3eb2e4859144fc09a36fe4a809e9bdcb499768f41a0482eee2e9d117","peg_in":false,"addr_server":"VJLCeEPisKk55xsw3z9kveCriekty3ivwftM1FfjP69AzeoJ7t4iSjbBidoPmEuGLfgW4KjMdtZkQgn2","addr_recv":"bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq","list":[],"created_at":1743761161667,"return_address":null}}}}}
   ```

   ```json
   {"Notif":{"notif":{"PegStatus":{"peg":{"order_id":"aa7ad2bc3eb2e4859144fc09a36fe4a809e9bdcb499768f41a0482eee2e9d117","peg_in":false,"addr_server":"VJLCeEPisKk55xsw3z9kveCriekty3ivwftM1FfjP69AzeoJ7t4iSjbBidoPmEuGLfgW4KjMdtZkQgn2","addr_recv":"bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq","list":[],"created_at":1743761161667,"return_address":null}}}}}
   ```

1. **Send L-BTC**

   Here 0.000872 L-BTC was sent to `VJLCeEPisKk55xsw3z9kveCriekty3ivwftM1FfjP69AzeoJ7t4iSjbBidoPmEuGLfgW4KjMdtZkQgn2`.

1. **Wait for notifications**

   - Unconfirmed transaction detected:
   ```json
   {"Notif":{"notif":{"PegStatus":{"peg":{"order_id":"aa7ad2bc3eb2e4859144fc09a36fe4a809e9bdcb499768f41a0482eee2e9d117","peg_in":false,"addr_server":"VJLCeEPisKk55xsw3z9kveCriekty3ivwftM1FfjP69AzeoJ7t4iSjbBidoPmEuGLfgW4KjMdtZkQgn2","addr_recv":"bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq","list":[{"tx_hash":"d45dc22cac2550cb5109fa73e061ed6315ef8c8c7d042093259e25c80fed9a65","vout":0,"peg_amount":0.000872,"payout_amount":0.00087113,"tx_state":"Detected","detected_confs":0,"total_confs":2,"created_at":1743761321609,"payout_txid":null}],"created_at":1743761161667,"return_address":null}}}}}
   ```

   - The transaction included in a block:
   ```json
   {"Notif":{"notif":{"PegStatus":{"peg":{"order_id":"aa7ad2bc3eb2e4859144fc09a36fe4a809e9bdcb499768f41a0482eee2e9d117","peg_in":false,"addr_server":"VJLCeEPisKk55xsw3z9kveCriekty3ivwftM1FfjP69AzeoJ7t4iSjbBidoPmEuGLfgW4KjMdtZkQgn2","addr_recv":"bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq","list":[{"tx_hash":"d45dc22cac2550cb5109fa73e061ed6315ef8c8c7d042093259e25c80fed9a65","vout":0,"peg_amount":0.000872,"payout_amount":0.00087113,"tx_state":"Detected","detected_confs":1,"total_confs":2,"created_at":1743761321609,"payout_txid":null}],"created_at":1743761161667,"return_address":null}}}}}
   ```

   - The peg-out complete:
   ```json
   {"Notif":{"notif":{"PegStatus":{"peg":{"order_id":"aa7ad2bc3eb2e4859144fc09a36fe4a809e9bdcb499768f41a0482eee2e9d117","peg_in":false,"addr_server":"VJLCeEPisKk55xsw3z9kveCriekty3ivwftM1FfjP69AzeoJ7t4iSjbBidoPmEuGLfgW4KjMdtZkQgn2","addr_recv":"bc1qjq4gy9tf8ss9s65m3a5z447xz92u0v7lutxkd6qg3hjgqgah84dqxckyfq","list":[{"tx_hash":"d45dc22cac2550cb5109fa73e061ed6315ef8c8c7d042093259e25c80fed9a65","vout":0,"peg_amount":0.000872,"payout_amount":0.00087113,"tx_state":"Done","detected_confs":null,"total_confs":null,"created_at":1743761321609,"payout_txid":"730f508f9f08ed5b07bf8531b9f3ec09bb28afad6ae8ddad1daa9bf8c242264b"}],"created_at":1743761161667,"return_address":null}}}}}
   ```

1. **Remove peg-out from the DB** (optional)

   Same as above.

---

## API reference

[API Reference](https://sideswap.io/docs/rust/sideswap_manager/api/) for detailed request/response structures, error codes, etc.
