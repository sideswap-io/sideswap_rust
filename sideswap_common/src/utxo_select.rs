use std::collections::{BTreeMap, BTreeSet, HashMap};

use elements::{Address, AssetId, Txid};
use serde::Serialize;

use crate::{
    coin_select::{in_range, no_change_or_naive},
    verify,
};

pub mod payjoin;

pub const WEIGHT_TX_FIXED: usize = 222;

pub const WEIGHT_OUTPUT_FIXED: usize = 178;

pub const DEFAULT_FEE_RATE: f64 = 0.1;

pub fn vsize_to_fee(vsize: usize, fee_rate: f64) -> u64 {
    (vsize as f64 * fee_rate).ceil() as u64
}

pub fn weight_to_vsize(weight: usize) -> usize {
    weight.div_ceil(4)
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Utxo {
    pub wallet: WalletType,
    pub asset_id: AssetId,
    pub value: u64,
    pub txid: Txid,
    pub vout: u32,
}

#[derive(Debug, Clone)]
pub struct Change {
    pub wallet: WalletType,
    pub asset_id: AssetId,
    pub value: u64,
}

#[derive(Debug, Clone)]
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
    let scale = 40;

    let utxo_value = |utxo: &Utxo| -> u64 {
        (utxo.value * scale).saturating_sub(utxo.wallet.input_weight() as u64)
    };

    // let bitcoin_utxos = {
    //     // Sort from the biggest to the smallest
    //     let mut bitcoin_utxos = bitcoin_utxos;
    //     bitcoin_utxos.sort_by_key(|utxo| utxo_value(utxo));
    //     bitcoin_utxos.reverse();
    //     bitcoin_utxos
    // };

    let coins = bitcoin_utxos
        .iter()
        .map(|utxo| utxo.value)
        .collect::<Vec<_>>();

    let change_wallet = *change_wallets
        .get(policy_asset)
        .ok_or(Error::InsufficientFunds)?;

    // Fee is deducted from a recipient output, no need for iterative fee calculation here
    let available = coins.iter().sum::<u64>();
    verify!(
        available > target || available == target && deduct_fee.is_some(),
        Error::InsufficientFunds
    );

    if deduct_fee.is_some() {
        let selected = if !use_all_utxos {
            no_change_or_naive(target, &coins).expect("must not fail")
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
    } else if use_all_utxos {
        let bitcoin_inputs_weight = bitcoin_utxos
            .iter()
            .map(|utxo| utxo.wallet.input_weight())
            .sum::<usize>();

        let total_weight_without_change = base_weight + bitcoin_inputs_weight;

        let min_fee_without_change = weight_to_fee(total_weight_without_change, DEFAULT_FEE_RATE);

        let fee_without_change = available - target;

        verify!(
            fee_without_change >= min_fee_without_change,
            Error::InsufficientFunds
        );

        let all_utxos = bitcoin_utxos.into_iter().cloned().collect::<Vec<_>>();

        let change_output_weight = change_wallet.output_weight();

        let total_weight_with_change = base_weight + bitcoin_inputs_weight + change_output_weight;

        let fee_with_change = weight_to_fee(total_weight_with_change, DEFAULT_FEE_RATE);

        let change_amount = (available - target).saturating_sub(fee_with_change);

        if change_amount > 0 {
            let change = Change {
                wallet: change_wallet,
                asset_id: *policy_asset,
                value: change_amount,
            };

            Ok((all_utxos, Some(change), fee_with_change))
        } else {
            Ok((all_utxos, None, fee_without_change))
        }
    } else {
        // Try to select without change first

        let coins = bitcoin_utxos
            .iter()
            .filter_map(|utxo| {
                let value = utxo_value(utxo);
                (value > 0).then_some(value)
            })
            .collect::<Vec<_>>();

        let without_change = in_range(
            target * scale + base_weight as u64,
            change_wallet.output_weight() as u64,
            0,
            &coins,
        );

        if let Some(without_change) = without_change {
            let mut counters = BTreeMap::<u64, usize>::new();
            for coin in without_change {
                *counters.entry(coin).or_default() += 1;
            }

            let mut selected_utxos = Vec::new();
            let mut selected_total = 0;
            for utxo in bitcoin_utxos {
                let value = utxo_value(utxo);
                let count = counters.entry(value).or_default();
                if *count > 0 {
                    *count -= 1;
                    selected_utxos.push(utxo.clone());
                    selected_total += utxo.value;
                }
            }

            let bitcoin_inputs_weight = selected_utxos
                .iter()
                .map(|utxo| utxo.wallet.input_weight())
                .sum::<usize>();

            let total_weight_without_change = base_weight + bitcoin_inputs_weight;

            let min_fee_without_change =
                weight_to_fee(total_weight_without_change, DEFAULT_FEE_RATE);

            let fee_without_change = selected_total - target;

            assert!(fee_without_change >= min_fee_without_change);

            Ok((selected_utxos, None, fee_without_change))
        } else {
            let mut selected_utxos = Vec::new();
            let mut total_selected = 0;
            let mut bitcoin_inputs_weight = 0;

            for utxo in bitcoin_utxos {
                selected_utxos.push(utxo.clone());
                total_selected += utxo.value;
                bitcoin_inputs_weight += utxo.wallet.input_weight();

                let total_weight_with_change =
                    base_weight + bitcoin_inputs_weight + change_wallet.output_weight();

                let network_fee = weight_to_fee(total_weight_with_change, DEFAULT_FEE_RATE);

                if total_selected < target + network_fee {
                    continue;
                }
                let change_amount = total_selected - target - network_fee;
                let change = Change {
                    wallet: change_wallet,
                    asset_id: *policy_asset,
                    value: change_amount,
                };

                return Ok((selected_utxos, Some(change), network_fee));
            }

            Err(Error::InsufficientFunds)
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

    let utxos = {
        let mut utxos = utxos;
        utxos.sort();
        utxos
    };

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
        .chain(bitcoin_inputs)
        .collect::<Vec<_>>();

    let updated_recipients = updated_recipients(recipients, network_fee, deduct_fee)?;

    let change = asset_change
        .into_iter()
        .chain(bitcoin_change)
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
