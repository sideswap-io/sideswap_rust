use std::collections::{BTreeMap, BTreeSet, HashMap};

use elements::{Address, AssetId, Txid};
use serde::Serialize;

use crate::{coin_select::no_change_or_naive, verify};

pub mod payjoin;

pub const WEIGHT_TX_FIXED: usize = 222;

pub const WEIGHT_OUTPUT_FIXED: usize = 178;

pub const DEFAULT_FEE_RATE: f64 = 0.1;

pub fn vsize_to_fee(vsize: usize, fee_rate: f64) -> u64 {
    (vsize as f64 * fee_rate).ceil() as u64
}

pub fn weight_to_vsize(weight: usize) -> usize {
    (weight + 3) / 4
}

pub fn weight_to_fee(weight: usize, fee_rate: f64) -> u64 {
    vsize_to_fee(weight_to_vsize(weight), fee_rate)
}

// Must be sorted in order of priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum WalletType {
    Native,
    Nested,
    AMP,
}

#[derive(Debug, Clone)]
pub enum RecipientAddress {
    Known(Address),
    Unknown(WalletType),
}

impl RecipientAddress {
    pub fn known(&self) -> Option<&elements::Address> {
        match self {
            RecipientAddress::Known(address) => Some(address),
            RecipientAddress::Unknown(_wallet_type) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Recipient {
    pub address: RecipientAddress,
    pub asset_id: AssetId,
    pub amount: u64,
}

impl WalletType {
    /// Without grinding (because Jade does not allow grinding with Anti-Exfil enabled)
    pub fn input_weight(self) -> usize {
        match self {
            WalletType::Native => 275,
            WalletType::Nested => 367,
            WalletType::AMP => 526,
        }
    }

    pub fn script_pubkey_len(self) -> usize {
        match self {
            WalletType::Native => 22,
            WalletType::Nested | WalletType::AMP => 23,
        }
    }

    pub fn output_weight(self) -> usize {
        WEIGHT_OUTPUT_FIXED + self.script_pubkey_len() * 4
    }
}

pub type ChangeWallets = BTreeMap<AssetId, WalletType>;

#[derive(Debug, Clone)]
pub struct Utxo {
    pub wallet: WalletType,
    pub txid: Txid,
    pub vout: u32,
    pub asset_id: AssetId,
    pub value: u64,
}

#[derive(Debug, Clone)]
pub struct Change {
    pub wallet: WalletType,
    pub asset_id: AssetId,
    pub value: u64,
}

#[derive(Debug)]
pub struct Args {
    pub policy_asset: AssetId,
    pub utxos: Vec<Utxo>,
    pub recipients: Vec<Recipient>,
    pub deduct_fee: Option<usize>,
    pub force_change_wallets: ChangeWallets,
    pub use_all_utxos: bool,
}

#[derive(Debug)]
pub struct Res {
    pub inputs: Vec<Utxo>,
    pub updated_recipients: Vec<Recipient>,
    pub change: Vec<Change>,
    pub network_fee: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid args: {0}")]
    InvalidArgs(&'static str),
    #[error("insufficient funds")]
    InsufficientFunds,
}

fn change_wallets(utxos: &[Utxo], force_change_wallets: ChangeWallets) -> ChangeWallets {
    let mut wallets = ChangeWallets::new();

    // This will keep AMP assets change in the AMP wallet.
    // AMP only will keep all the change in the AMP wallet.
    for utxo in utxos {
        let wallet = wallets.entry(utxo.asset_id).or_insert(utxo.wallet);
        // For example, if we have USDt in both Nested and AMP wallets,
        // this will redirect USDt change to the Nested wallet
        *wallet = std::cmp::min(*wallet, utxo.wallet);
    }

    // This will allow redirect non-AMP assets change to a prefered wallet (for example, Native SegWit)
    for (asset_id, wallet) in force_change_wallets {
        wallets.insert(asset_id, wallet);
    }

    wallets
}

fn recipient_totals(recipients: &[Recipient]) -> Result<BTreeMap<AssetId, u64>, Error> {
    let mut totals = BTreeMap::<AssetId, u64>::new();

    for recipient in recipients.iter() {
        let value = totals.entry(recipient.asset_id).or_default();
        *value = value
            .checked_add(recipient.amount)
            .ok_or(Error::InvalidArgs("amount overflow"))?;
    }

    Ok(totals)
}

fn select_utxos<'a>(selected: &[u64], utxos: impl Iterator<Item = &'a Utxo>) -> Vec<Utxo> {
    let mut required_counts = HashMap::with_capacity(selected.len());
    for &value in selected {
        *required_counts.entry(value).or_insert(0) += 1;
    }

    let mut result = Vec::<Utxo>::with_capacity(selected.len());

    for utxo in utxos {
        if let Some(count) = required_counts.get_mut(&utxo.value) {
            if *count > 0 {
                result.push(utxo.clone());
                *count -= 1;
            }
        }
    }

    result
}

fn select_asset_inputs(
    policy_asset: &AssetId,
    utxos: Vec<Utxo>,
    recipient_totals: &BTreeMap<AssetId, u64>,
    change_wallets: &ChangeWallets,
    use_all_utxos: bool,
) -> Result<(Vec<Utxo>, Vec<Change>), Error> {
    let mut inputs = Vec::new();
    let mut change = Vec::new();

    let required_assets = utxos
        .iter()
        .filter_map(|utxo| use_all_utxos.then_some(utxo.asset_id))
        .chain(recipient_totals.keys().copied())
        .filter(|asset_id| asset_id != policy_asset)
        .collect::<BTreeSet<_>>();

    for asset_id in required_assets {
        let target = recipient_totals.get(&asset_id).copied().unwrap_or_default();

        let asset_utxos = utxos
            .iter()
            .filter(|utxo| utxo.asset_id == asset_id)
            .collect::<Vec<_>>();

        let coins = asset_utxos
            .iter()
            .map(|utxo| utxo.value)
            .collect::<Vec<_>>();

        let available = coins.iter().sum::<u64>();
        verify!(available >= target, Error::InsufficientFunds);

        let selected = if !use_all_utxos {
            no_change_or_naive(target, &coins).ok_or(Error::InsufficientFunds)?
        } else {
            coins
        };

        let total = selected.iter().copied().sum::<u64>();
        assert!(total >= target);
        let change_amount = total - target;

        let mut asset_inputs = select_utxos(&selected, asset_utxos.into_iter());
        inputs.append(&mut asset_inputs);

        if change_amount > 0 {
            let wallet = *change_wallets
                .get(&asset_id)
                .ok_or(Error::InsufficientFunds)?;
            change.push(Change {
                wallet,
                asset_id,
                value: change_amount,
            });
        }
    }

    Ok((inputs, change))
}

fn select_bitcoin_inputs(
    policy_asset: &AssetId,
    bitcoin_utxos: Vec<&Utxo>,
    target: u64,
    base_weight: usize,
    change_wallets: &ChangeWallets,
    deduct_fee: Option<usize>,
    use_all_utxos: bool,
) -> Result<(Vec<Utxo>, Option<Change>, u64), Error> {
    let coins = bitcoin_utxos
        .iter()
        .map(|utxo| utxo.value)
        .collect::<Vec<_>>();

    let change_wallet = *change_wallets
        .get(policy_asset)
        .ok_or(Error::InsufficientFunds)?;

    if deduct_fee.is_some() {
        // Fee is deducted from a recipient output, no need for iterative fee calculation here
        let available = coins.iter().sum::<u64>();
        verify!(available >= target, Error::InsufficientFunds);

        let selected = if !use_all_utxos {
            no_change_or_naive(target, &coins).ok_or(Error::InsufficientFunds)?
        } else {
            coins
        };

        let total = selected.iter().copied().sum::<u64>();

        let bitcoin_inputs = select_utxos(&selected, bitcoin_utxos.into_iter());

        let change_amount = total - target;

        let change = (change_amount > 0).then_some(Change {
            wallet: change_wallet,
            asset_id: *policy_asset,
            value: change_amount,
        });

        let total_weight = base_weight
            + bitcoin_inputs
                .iter()
                .map(|utxo| utxo.wallet.input_weight())
                .sum::<usize>()
            + change
                .as_ref()
                .map(|change| change.wallet.output_weight())
                .unwrap_or(0);

        let network_fee = weight_to_fee(total_weight, DEFAULT_FEE_RATE);

        Ok((bitcoin_inputs, change, network_fee))
    } else {
        // Fee is paid by inputs, potentially creating change.
        // Need to iterate because fee depends on inputs and change, which depend on fee.

        let coins = bitcoin_utxos
            .iter()
            .map(|utxo| utxo.value)
            .collect::<Vec<_>>();
        let available_bitcoin = coins.iter().sum::<u64>();

        let mut current_fee = 0;

        loop {
            let required_amount = target + current_fee;

            verify!(
                available_bitcoin >= required_amount,
                Error::InsufficientFunds
            );

            let selected_coins = if !use_all_utxos {
                no_change_or_naive(required_amount, &coins).ok_or(Error::InsufficientFunds)?
            } else {
                coins.clone()
            };

            let bitcoin_inputs = select_utxos(&selected_coins, bitcoin_utxos.iter().copied());
            let total_input_value = selected_coins.iter().sum::<u64>();

            verify!(
                total_input_value >= required_amount,
                Error::InsufficientFunds
            );

            // Calculate potential change based on current fee estimate
            // Must subtract required_amount (target + current_fee)
            let change_amount_potential = total_input_value - required_amount;
            // A change output is needed if potential change > 0 (ignoring dust for now)
            let change_needed = change_amount_potential > 0;

            let bitcoin_inputs_weight = bitcoin_inputs
                .iter()
                .map(|utxo| utxo.wallet.input_weight())
                .sum::<usize>();
            let change_output_weight = if change_needed {
                change_wallet.output_weight()
            } else {
                0
            };

            let total_weight = base_weight + bitcoin_inputs_weight + change_output_weight;
            let new_fee = weight_to_fee(total_weight, DEFAULT_FEE_RATE);

            if new_fee == current_fee {
                let target_plus_final_fee = target + new_fee;

                // This check should ideally always pass if the loop converged correctly,
                // but verifies against edge cases or potential logic flaws.
                verify!(
                    total_input_value >= target_plus_final_fee,
                    Error::InsufficientFunds
                );

                let final_change_amount = total_input_value - target_plus_final_fee;

                let change = (final_change_amount > 0).then_some(Change {
                    wallet: change_wallet,
                    asset_id: *policy_asset,
                    value: final_change_amount,
                });

                return Ok((bitcoin_inputs, change, new_fee));
            } else {
                // Fee estimate changed, update and loop again
                current_fee = new_fee;
                // The next iteration will use the updated fee to calculate required_amount
                // and potentially re-select coins.
            }
        }
    }
}

pub fn tx_weight<'a>(
    inputs: impl Iterator<Item = WalletType>,
    outputs: impl Iterator<Item = &'a RecipientAddress>,
    change: impl Iterator<Item = WalletType>,
) -> usize {
    WEIGHT_TX_FIXED
        + inputs.map(WalletType::input_weight).sum::<usize>()
        + outputs
            .map(|address| match address {
                RecipientAddress::Known(address) => {
                    WEIGHT_OUTPUT_FIXED + address.script_pubkey().len() * 4
                }
                RecipientAddress::Unknown(wallet_type) => wallet_type.output_weight(),
            })
            .sum::<usize>()
        + change.map(WalletType::output_weight).sum::<usize>()
}

fn updated_recipients(
    mut recipients: Vec<Recipient>,
    network_fee: u64,
    deduct_fee: Option<usize>,
) -> Result<Vec<Recipient>, Error> {
    if let Some(index) = deduct_fee {
        let recipient = &mut recipients[index];
        verify!(
            recipient.amount > network_fee,
            Error::InvalidArgs("can't deduct fee because the recipient amount is too small")
        );
        recipient.amount -= network_fee;
    }
    Ok(recipients)
}

// TODO: Make sure mo more than 256 inputs are selected
fn try_select(args: Args) -> Result<Res, Error> {
    log::debug!("utxo select: {args:#?}");

    let Args {
        policy_asset,
        utxos,
        recipients,
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
            recipient.asset_id == policy_asset,
            Error::InvalidArgs("can't deduct network fee from the output, different asset")
        );
    }

    let change_wallets = change_wallets(&utxos, force_change_wallets);

    let recipient_totals = recipient_totals(&recipients)?;

    let (asset_inputs, asset_change) = select_asset_inputs(
        &policy_asset,
        utxos.clone(),
        &recipient_totals,
        &change_wallets,
        use_all_utxos,
    )?;

    let base_weight = tx_weight(
        asset_inputs.iter().map(|utxo| utxo.wallet),
        recipients.iter().map(|recipient| &recipient.address),
        asset_change.iter().map(|change| change.wallet),
    );

    let bitcoin_utxos = utxos
        .iter()
        .filter(|utxo| utxo.asset_id == policy_asset)
        .collect::<Vec<_>>();

    let recipients_bitcoin_total = recipient_totals
        .get(&policy_asset)
        .copied()
        .unwrap_or_default();

    let (bitcoin_inputs, bitcoin_change, network_fee) = select_bitcoin_inputs(
        &policy_asset,
        bitcoin_utxos,
        recipients_bitcoin_total,
        base_weight,
        &change_wallets,
        deduct_fee,
        use_all_utxos,
    )?;

    let inputs = asset_inputs
        .into_iter()
        .chain(bitcoin_inputs.into_iter())
        .collect::<Vec<_>>();

    let updated_recipients = updated_recipients(recipients, network_fee, deduct_fee)?;

    let change = asset_change
        .into_iter()
        .chain(bitcoin_change.into_iter())
        .collect::<Vec<_>>();

    Ok(Res {
        inputs,
        updated_recipients,
        change,
        network_fee,
    })
}

pub fn select(args: Args) -> Result<Res, Error> {
    log::debug!("utxo select: {args:#?}");
    let res = try_select(args);
    log::debug!("utxo res: {res:#?}");
    res
}

#[cfg(test)]
mod tests;
