use std::collections::BTreeMap;

use bitcoin::secp256k1::{SecretKey, SECP256K1};
use elements::{
    secp256k1_zkp::{Generator, PedersenCommitment},
    AssetId,
};
use sideswap_api::{AssetBlindingFactor, ValueBlindingFactor};

use crate::verify;

#[derive(Debug, PartialEq, Eq)]
pub struct SwapAmount {
    pub send_asset: AssetId,
    pub send_amount: u64,
    pub recv_asset: AssetId,
    pub recv_amount: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("protocol error: {0}")]
    Protocol(&'static str),
}

pub fn get_swap_amount(
    tx: &elements::Transaction,
    utxos: &[sideswap_api::Utxo],
    receive_address: &elements::Address,
    change_address: &elements::Address,
    receive_ephemeral_sk: SecretKey,
    change_ephemeral_sk: Option<SecretKey>,
) -> Result<SwapAmount, Error> {
    let txid = tx.txid();
    let mut inputs = BTreeMap::<AssetId, u64>::new();

    for input in tx.input.iter() {
        let utxo = utxos.iter().find(|utxo| {
            utxo.txid == input.previous_output.txid && utxo.vout == input.previous_output.vout
        });
        if let Some(utxo) = utxo {
            let total = inputs.entry(utxo.asset).or_default();
            *total = total
                .checked_add(utxo.value)
                .ok_or(Error::Protocol("input total amount overflow"))?;
        }
    }
    let inputs = inputs.into_iter().collect::<Vec<_>>();

    let (send_asset, mut send_amount) = match inputs.as_slice() {
        [input] => Ok(*input),
        [] => Err(Error::Protocol("no UTXO asset found")),
        _ => Err(Error::Protocol("more than one input asset found")),
    }?;

    let mut output_amounts = BTreeMap::<AssetId, u64>::new();

    let receive_pubkey = receive_address.script_pubkey();
    let change_pubkey = change_address.script_pubkey();

    for (vout, output) in tx.output.iter().enumerate() {
        let (address, ephemeral_sk) = if output.script_pubkey == receive_pubkey {
            (receive_address, receive_ephemeral_sk)
        } else if output.script_pubkey == change_pubkey {
            let change_ephemeral_sk =
                change_ephemeral_sk.ok_or(Error::Protocol("change_ephemeral_sk is not set"))?;
            (change_address, change_ephemeral_sk)
        } else {
            continue;
        };

        let blinding_pk = address
            .blinding_pubkey
            .ok_or(Error::Protocol("addresses must be confidential"))?;

        let (nonce, shared_secret) =
            elements::confidential::Nonce::with_ephemeral_sk(SECP256K1, ephemeral_sk, &blinding_pk);

        let commitment = output
            .value
            .commitment()
            .ok_or(Error::Protocol("output value must be confidential"))?;
        let additional_generator = output
            .asset
            .commitment()
            .ok_or(Error::Protocol("output asset must be confidential"))?;
        verify!(
            output.nonce == nonce,
            Error::Protocol("unexpected output nonce")
        );

        let rangeproof = output
            .witness
            .rangeproof
            .as_ref()
            .ok_or(Error::Protocol("missing rangeproof"))?;

        let (opening, _) = rangeproof
            .rewind(
                SECP256K1,
                commitment,
                shared_secret,
                output.script_pubkey.as_bytes(),
                additional_generator,
            )
            .map_err(|_| Error::Protocol("unblind error"))?;

        let (asset, asset_bf) = opening
            .message
            .as_ref()
            .split_at_checked(32)
            .ok_or(Error::Protocol("message split error"))?;
        let asset = AssetId::from_slice(asset)
            .map_err(|_| Error::Protocol("invalid asset_id in message"))?;
        let asset_bf = AssetBlindingFactor::from_slice(&asset_bf[..32])
            .map_err(|_| Error::Protocol("invalid asset_bf in message"))?;

        let value = opening.value;
        let value_bf = ValueBlindingFactor::from_slice(opening.blinding_factor.as_ref())
            .map_err(|_| Error::Protocol("invalid value_bf in message"))?;

        let expected_generator =
            Generator::new_blinded(SECP256K1, asset.into_tag(), asset_bf.into_inner());
        verify!(
            additional_generator == expected_generator,
            Error::Protocol("unexpected asset commitment")
        );
        let expected_commitment =
            PedersenCommitment::new(SECP256K1, value, value_bf.into_inner(), expected_generator);
        verify!(
            commitment == expected_commitment,
            Error::Protocol("unexpected value commitment")
        );

        log::debug!("unblinded output, txid: {txid}, vout: {vout}, asset: {asset}, asset_bf: {asset_bf}, value: {value}, value_bf: {value_bf}");
        let total = output_amounts.entry(asset).or_default();
        *total = total
            .checked_add(value)
            .ok_or(Error::Protocol("output total amount overflow"))?;
    }

    let change_output = output_amounts.remove(&send_asset);
    if let Some(change_amount) = change_output {
        send_amount = send_amount
            .checked_sub(change_amount)
            .ok_or(Error::Protocol("change amount underflow"))?;
    }

    let outputs = output_amounts.into_iter().collect::<Vec<_>>();

    let (recv_asset, recv_amount) = match outputs.as_slice() {
        [output] => Ok(*output),
        [] => Err(Error::Protocol("no receive output found")),
        _ => Err(Error::Protocol("more than one receive output found")),
    }?;

    Ok(SwapAmount {
        send_asset,
        send_amount,
        recv_asset,
        recv_amount,
    })
}
