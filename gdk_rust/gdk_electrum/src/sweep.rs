use crate::error::Error;
use crate::session::determine_electrum_url;
use gdk_common::be::{BEScript, BEScriptConvert};
use gdk_common::bitcoin::{Address, CompressedPublicKey, Network, PublicKey};
use gdk_common::electrum_client::Client;
use gdk_common::error::Error::InvalidAddressType;
use gdk_common::network::NetworkParameters;
use gdk_common::scripts::p2pkh_script;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SweepOpt {
    /// The network parameters
    pub network: NetworkParameters,

    /// Maximum timeout for network calls,
    /// the final timeout in seconds is roughly equivalent to 2 + `timeout` * 2
    ///
    /// Cannot be specified if `network.proxy` is non empty.
    pub timeout: Option<u8>,

    /// The public key to sweep
    pub public_key: String,

    /// The address type to sweep
    pub address_type: String,
}

impl SweepOpt {
    /// Build the Electrum client
    pub fn build_client(&self) -> Result<Client, Error> {
        let url = determine_electrum_url(&self.network)?;
        url.build_client(self.network.proxy.as_deref(), self.timeout)
    }

    /// Compute the script_pubkey and script_code
    pub fn scripts(&self) -> Result<(BEScript, BEScript), Error> {
        let public_key = PublicKey::from_str(&self.public_key)?;
        let compressed = CompressedPublicKey(public_key.inner.clone());
        let script_code = p2pkh_script(&public_key).into_be();
        let script_pubkey = match self.address_type.as_str() {
            "p2pkh" => script_code.clone(),
            "p2wpkh" => Address::p2wpkh(&compressed, Network::Regtest).script_pubkey().into_be(),
            "p2sh-p2wpkh" => {
                Address::p2shwpkh(&compressed, Network::Regtest).script_pubkey().into_be()
            }
            _ => return Err(Error::Common(InvalidAddressType)),
        };
        Ok((script_pubkey, script_code))
    }
}
