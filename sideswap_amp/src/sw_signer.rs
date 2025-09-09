use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin_hashes::Hash;
use elements::pset::PartiallySignedTransaction;
use elements_miniscript::slip77::MasterBlindingKey;
use secp256k1::{SECP256K1, ecdsa::Signature};
use sideswap_common::green_backend::GREEN_DUMMY_SIG;
use sideswap_types::network::Network;

use crate::{Error, Signer, Utxo, address_user_path};

pub struct SwSigner {
    network: Network,
    master_blinding_key: MasterBlindingKey,
    master_key: Xpriv,
}

impl SwSigner {
    pub fn new(network: Network, mnemonic: &bip39::Mnemonic) -> SwSigner {
        let bitcoin_network = network.to_bitcoin_network();

        let seed = mnemonic.to_seed("");
        let master_blinding_key = MasterBlindingKey::from_seed(&seed);
        let master_key = Xpriv::new_master(bitcoin_network, &seed).expect("must not fail");

        SwSigner {
            network,
            master_blinding_key,
            master_key,
        }
    }

    pub fn user_signatures(
        &self,
        mut pset: PartiallySignedTransaction,
        used_utxos: Vec<Utxo>,
    ) -> Result<PartiallySignedTransaction, Error> {
        let mut tx = pset.extract_tx()?;
        let tx_copy = tx.clone();

        for (pset_input, tx_input) in pset.inputs().iter().zip(tx.input.iter_mut()) {
            let redeem_script = used_utxos
                .iter()
                .find(|utxo| utxo.outpoint == tx_input.previous_output)
                .map(|utxo| utxo.redeem_script.clone())
                .or_else(|| pset_input.redeem_script.clone());

            if let Some(redeem_script) = redeem_script {
                tx_input.script_sig = elements::script::Builder::new()
                    .push_slice(redeem_script.as_bytes())
                    .into_script();
            } else if let Some(final_script) = pset_input.final_script_sig.clone() {
                tx_input.script_sig = final_script;
            } else {
                // Green backend won't sign without script_sig (it returns "Partial signing of pre-segwit transactions is not supported")
                // Make sure this works as expected with native segwit (the check will return false positive error).
                // abort!(Error::NoRedeem(
                //     pset_input.previous_txid,
                //     pset_input.previous_output_index
                // ))
            }
        }

        let mut sighash_cache = elements::sighash::SighashCache::new(&tx_copy);
        for (index, tx_input) in tx.input.iter_mut().enumerate() {
            if let Some(utxo) = used_utxos
                .iter()
                .find(|utxo| utxo.outpoint == tx_input.previous_output)
            {
                let hash_ty = elements_miniscript::elements::EcdsaSighashType::All;
                let sighash = sighash_cache.segwitv0_sighash(
                    index,
                    &utxo.prevout_script,
                    utxo.txout.value,
                    hash_ty,
                );
                let msg =
                    elements::secp256k1_zkp::Message::from_digest_slice(&sighash[..]).unwrap();

                let path = address_user_path(utxo.subaccount, utxo.pointer);

                let priv_key = self
                    .master_key
                    .derive_priv(SECP256K1, &path)
                    .expect("must not fail");

                let user_sig = SECP256K1.sign_ecdsa_low_r(&msg, &priv_key.private_key);

                let user_sig = elements_miniscript::elementssig_to_rawsig(&(user_sig, hash_ty));

                tx_input.witness.script_witness = vec![
                    vec![],
                    GREEN_DUMMY_SIG.to_vec(),
                    user_sig,
                    utxo.prevout_script.to_bytes(),
                ];
            }
        }

        sideswap_common::pset::copy_tx_signatures(&tx, &mut pset);

        Ok(pset)
    }
}

impl Signer for SwSigner {
    fn network(&self) -> Network {
        self.network
    }

    fn get_master_blinding_key(&self) -> Result<MasterBlindingKey, Error> {
        Ok(self.master_blinding_key)
    }

    fn get_xpub(&self, path: &[ChildNumber]) -> Result<Xpub, Error> {
        let user_xpriv = self
            .master_key
            .derive_priv(SECP256K1, &path)
            .expect("should not fail");
        Ok(Xpub::from_priv(SECP256K1, &user_xpriv))
    }

    fn sign_message(&self, path: &[ChildNumber], message: String) -> Result<Signature, Error> {
        let user_xpriv = self
            .master_key
            .derive_priv(SECP256K1, &path)
            .expect("should not fail");
        let keypair = user_xpriv.to_keypair(SECP256K1);
        let message_hash = bitcoin::sign_message::signed_msg_hash(&message);
        let message = bitcoin::secp256k1::Message::from_digest(message_hash.to_byte_array());
        let signature = SECP256K1.sign_ecdsa(&message, &keypair.secret_key());
        Ok(signature)
    }
}
