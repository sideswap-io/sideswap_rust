use elements::AssetId;

use crate::utxo_select::RecipientAddress;
use crate::verify;

use super::{
    change_wallets, select_asset_inputs, tx_weight, updated_recipients, weight_to_fee,
    DEFAULT_FEE_RATE,
};

use super::{recipient_totals, Change, ChangeWallets, Error, Recipient, Utxo};

#[derive(Debug)]
pub struct Args {
    pub policy_asset: AssetId,
    pub fee_asset: AssetId,
    pub utxos: Vec<Utxo>,
    pub recipients: Vec<Recipient>,
    pub server_utxos: Vec<Utxo>,
    pub price: f64,
    pub fixed_fee: u64,
    pub deduct_fee: Option<usize>,
    pub force_change_wallets: ChangeWallets,
    pub use_all_utxos: bool,
}

#[derive(Debug)]
pub struct Res {
    pub inputs: Vec<Utxo>,
    pub updated_recipients: Vec<Recipient>,
    pub change: Vec<Change>,
    pub server_inputs: Vec<Utxo>,
    pub server_change: Option<Change>,
    pub network_fee: u64,
    pub server_fee: u64,
}

fn try_select(args: Args) -> Result<Res, Error> {
    let Args {
        policy_asset,
        fee_asset,
        utxos,
        recipients,
        server_utxos,
        price,
        fixed_fee,
        deduct_fee,
        force_change_wallets,
        use_all_utxos,
    } = args;

    verify!(
        utxos.iter().all(|utxo| utxo.value > 0),
        Error::InvalidArgs("utxo value is 0")
    );

    verify!(
        recipients.iter().all(|recipient| recipient.amount > 0),
        Error::InvalidArgs("recipient amount is 0")
    );

    if let Some(index) = deduct_fee {
        let recipient = recipients.get(index).ok_or(Error::InvalidArgs(
            "can't deduct network fee from the output, no such index",
        ))?;
        verify!(
            recipient.asset_id == fee_asset,
            Error::InvalidArgs("can't deduct network fee from the output, different asset")
        );
    }

    let recipient_totals = recipient_totals(&recipients)?;

    let change_wallets = change_wallets(&utxos, force_change_wallets);

    let (asset_inputs, asset_change) = select_asset_inputs(
        &policy_asset,
        utxos.clone(),
        &recipient_totals,
        &change_wallets,
        use_all_utxos,
    )?;

    let asset_inputs = asset_inputs
        .into_iter()
        .filter(|utxo| utxo.asset_id != fee_asset)
        .collect::<Vec<_>>();
    let asset_change = asset_change
        .into_iter()
        .filter(|change| change.asset_id != fee_asset)
        .collect::<Vec<_>>();

    let server_input = server_utxos
        .into_iter()
        .max_by_key(|utxo| utxo.value)
        .ok_or(Error::InvalidArgs("server_utxos is empty"))?;

    let fee_asset_utxos = utxos
        .into_iter()
        .filter(|utxo| utxo.asset_id == fee_asset)
        .collect::<Vec<_>>();

    verify!(!fee_asset_utxos.is_empty(), Error::InsufficientFunds);

    let initial_count = if !use_all_utxos {
        1
    } else {
        fee_asset_utxos.len()
    };

    let mut best = None;

    let recipients_fee_asset_total = recipient_totals
        .get(&fee_asset)
        .copied()
        .unwrap_or_default();

    let fee_asset_wallet = *change_wallets.get(&fee_asset).expect("must be known");

    for with_change in [false, true] {
        for count in initial_count..=fee_asset_utxos.len() {
            let fee_asset_inputs = &fee_asset_utxos[0..count];

            let fee_asset_total = fee_asset_inputs.iter().map(|utxo| utxo.value).sum::<u64>();
            if fee_asset_total < recipients_fee_asset_total {
                continue;
            }

            let tx_weight = tx_weight(
                asset_inputs
                    .iter()
                    .chain(fee_asset_inputs.iter())
                    .chain(std::iter::once(&server_input))
                    .map(|utxo| utxo.wallet),
                recipients
                    .iter()
                    .map(|recipient| &recipient.address)
                    .chain(std::iter::once(&RecipientAddress::Unknown(
                        server_input.wallet,
                    ))),
                asset_change
                    .iter()
                    .map(|change| change.wallet)
                    .chain(with_change.then_some(fee_asset_wallet))
                    .chain(std::iter::once(server_input.wallet)),
            );

            let network_fee = weight_to_fee(tx_weight, DEFAULT_FEE_RATE);

            verify!(
                network_fee < server_input.value,
                Error::InvalidArgs("server UTXO is too small")
            );

            let server_change_amount = server_input.value - network_fee;

            let server_fee_min = (network_fee as f64 * price) as u64 + fixed_fee;

            let server_fee = if with_change || deduct_fee.is_some() {
                server_fee_min
            } else {
                let server_fee = fee_asset_total - recipients_fee_asset_total;
                if server_fee < server_fee_min {
                    continue;
                }
                server_fee
            };

            let fee_asset_change = if deduct_fee.is_some() {
                fee_asset_total - recipients_fee_asset_total
            } else {
                if recipients_fee_asset_total + server_fee > fee_asset_total {
                    continue;
                }
                fee_asset_total - recipients_fee_asset_total - server_fee
            };

            if with_change != (fee_asset_change != 0) {
                continue;
            }

            let fee_asset_change = with_change.then_some(Change {
                wallet: fee_asset_wallet,
                asset_id: fee_asset,
                value: fee_asset_change,
            });

            let server_change = Change {
                wallet: server_input.clone().wallet,
                asset_id: policy_asset,
                value: server_change_amount,
            };

            if best
                .as_ref()
                .map(|best: &Res| best.server_fee > server_fee)
                .unwrap_or(true)
            {
                best = Some(Res {
                    inputs: asset_inputs
                        .iter()
                        .chain(fee_asset_inputs.iter())
                        .cloned()
                        .collect(),
                    updated_recipients: Vec::new(),
                    change: asset_change
                        .iter()
                        .cloned()
                        .chain(fee_asset_change)
                        .collect(),
                    server_inputs: vec![server_input.clone()],
                    server_change: Some(server_change),
                    network_fee,
                    server_fee,
                })
            };
        }
    }

    if let Some(best) = best.as_mut() {
        best.updated_recipients =
            updated_recipients(recipients.clone(), best.server_fee, deduct_fee)?;
    }

    best.ok_or(Error::InsufficientFunds)
}

pub fn select(args: Args) -> Result<Res, Error> {
    log::debug!("utxo select: {args:#?}");
    let res = try_select(args);
    log::debug!("utxo res: {res:#?}");
    res
}

#[cfg(test)]
mod tests;
