use anyhow::ensure;
use elements::{AssetId, TxOutSecrets, Txid, pset::PartiallySignedTransaction};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use sideswap_api::{AssetBlindingFactor, ValueBlindingFactor};

use crate::pset_blind::OptBlindedOutputs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsetInput {
    pub txid: Txid,
    pub vout: u32,
    pub script_pub_key: elements::script::Script,
    pub asset_commitment: elements::confidential::Asset,
    pub value_commitment: elements::confidential::Value,
    pub tx_out_sec: TxOutSecrets,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsetOutput {
    pub address: elements::Address,
    pub asset_id: AssetId,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offline {
    pub input: PsetInput,

    pub output: PsetOutput,

    pub output_asset_bf: AssetBlindingFactor,
    pub output_value_bf: ValueBlindingFactor,
    pub output_ephemeral_sk: elements::secp256k1_zkp::SecretKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructPsetArgs {
    pub policy_asset: AssetId,
    pub offlines: Vec<Offline>,
    pub inputs: Vec<PsetInput>,
    pub outputs: Vec<PsetOutput>,
    pub network_fee: u64,
}

pub struct ConstructedPset {
    pub blinded_pset: PartiallySignedTransaction,
    pub blinded_outputs: OptBlindedOutputs,
}

fn pset_input(input: PsetInput) -> elements::pset::Input {
    let PsetInput {
        txid,
        vout,
        script_pub_key,
        asset_commitment,
        value_commitment,
        tx_out_sec: _,
    } = input;

    let mut pset_input = elements::pset::Input::from_prevout(elements::OutPoint { txid, vout });

    pset_input.witness_utxo = Some(elements::TxOut {
        asset: asset_commitment,
        value: value_commitment,
        nonce: elements::confidential::Nonce::Null,
        script_pubkey: script_pub_key,
        witness: elements::TxOutWitness::default(),
    });

    pset_input
}

fn pset_output(output: PsetOutput) -> Result<elements::pset::Output, anyhow::Error> {
    let PsetOutput {
        address,
        asset_id,
        amount,
    } = output;

    ensure!(amount > 0);

    // A confidential (blinded) recipient gets a blinded output; an
    // unconfidential recipient gets an explicit output. `blind_pset` already
    // treats an output with no `blinding_key` as explicit and balances the
    // transaction against the wallet's own (always blinded) change output, so
    // mixing the two is safe as long as at least one blinded output remains —
    // which the change output guarantees. Unconfidential recipients are
    // needed for contracts that must read explicit amounts on-chain (e.g. a
    // Simplicity covenant); the amount and asset of such an output are public
    // by construction.
    let txout = elements::TxOut {
        asset: elements::confidential::Asset::Explicit(asset_id),
        value: elements::confidential::Value::Explicit(amount),
        nonce: match address.blinding_pubkey {
            Some(blinding_pubkey) => elements::confidential::Nonce::Confidential(blinding_pubkey),
            None => elements::confidential::Nonce::Null,
        },
        script_pubkey: address.script_pubkey(),
        witness: elements::TxOutWitness::default(),
    };

    let mut output = elements::pset::Output::from_txout(txout);

    if let Some(blinding_pubkey) = address.blinding_pubkey {
        output.blinding_key = Some(bitcoin::PublicKey::new(blinding_pubkey));
        output.blinder_index = Some(0);
    }

    Ok(output)
}

fn pset_network_fee(asset: AssetId, amount: u64) -> elements::pset::Output {
    let network_fee_output = elements::TxOut::new_fee(amount, asset);
    elements::pset::Output::from_txout(network_fee_output)
}

pub fn construct_pset(args: ConstructPsetArgs) -> Result<ConstructedPset, anyhow::Error> {
    let ConstructPsetArgs {
        policy_asset,
        mut inputs,
        mut outputs,
        offlines,
        network_fee,
    } = args;

    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input_secrets = Vec::new();
    let mut blinding_factors = Vec::new();

    let mut rng = rand::thread_rng();
    inputs.shuffle(&mut rng);
    outputs.shuffle(&mut rng);

    for offline in offlines {
        blinding_factors.push((
            offline.output_asset_bf,
            offline.output_value_bf,
            offline.output_ephemeral_sk,
        ));

        input_secrets.push(offline.input.tx_out_sec);

        pset.add_input(pset_input(offline.input));

        pset.add_output(pset_output(offline.output)?);
    }

    for input in inputs.into_iter() {
        input_secrets.push(input.tx_out_sec);

        pset.add_input(pset_input(input));
    }

    for output in outputs {
        pset.add_output(pset_output(output)?);
    }

    pset.add_output(pset_network_fee(policy_asset, network_fee));

    let blinded_outputs =
        crate::pset_blind::blind_pset(&mut pset, &input_secrets, &blinding_factors)?;

    Ok(ConstructedPset {
        blinded_pset: pset,
        blinded_outputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tap_address(blinded: bool) -> elements::Address {
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let sk = elements::secp256k1_zkp::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let (xonly, _) = sk.x_only_public_key(&secp);
        let blinder = blinded.then(|| {
            let bsk = elements::secp256k1_zkp::SecretKey::from_slice(&[0x22; 32]).unwrap();
            elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &bsk)
        });
        elements::Address::p2tr(
            &secp,
            xonly,
            None,
            blinder,
            &elements::AddressParams::LIQUID_TESTNET,
        )
    }

    /// An unconfidential recipient yields an explicit output with no blinding
    /// key — `blind_pset` will then leave it unblinded and balance the tx
    /// against the wallet's blinded change.
    #[test]
    fn unconfidential_recipient_makes_an_explicit_output() {
        let addr = tap_address(false);
        assert!(!addr.is_blinded());
        let asset_id = AssetId::from_slice(&[0x33; 32]).unwrap();
        let out = pset_output(PsetOutput { address: addr, asset_id, amount: 1000 }).unwrap();
        assert!(out.blinding_key.is_none(), "explicit output must carry no blinding key");
        assert!(out.blinder_index.is_none());
        assert_eq!(out.amount, Some(1000));
        assert_eq!(out.asset, Some(asset_id));
    }

    /// A confidential recipient is unchanged: blinded output, blinder index 0.
    #[test]
    fn confidential_recipient_stays_blinded() {
        let addr = tap_address(true);
        assert!(addr.is_blinded());
        let asset_id = AssetId::from_slice(&[0x33; 32]).unwrap();
        let out = pset_output(PsetOutput { address: addr, asset_id, amount: 1000 }).unwrap();
        assert!(out.blinding_key.is_some(), "blinded recipient must keep its blinding key");
        assert_eq!(out.blinder_index, Some(0));
    }
}
