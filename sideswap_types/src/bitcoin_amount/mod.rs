use std::str::FromStr;

use elements::bitcoin;

/// Unsigned bitcoin amount encoded as a JSON number in BTC units.
/// Parsed from the decimal JSON representation without converting through f64.
/// Requires serde_json with the `arbitrary_precision` feature.
/// Used with Bitcoin Core/Elements RPC.
#[derive(Debug, Clone, Copy)]
pub struct UnsignedBtcAmount(u64);

impl UnsignedBtcAmount {
    pub fn new(value: u64) -> Self {
        Self(value)
    }
}

impl<'de> serde::Deserialize<'de> for UnsignedBtcAmount {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = serde_json::Number::deserialize(d)?;
        let value = bitcoin::Amount::from_str_in(&value.as_str(), bitcoin::Denomination::Bitcoin)
            .map_err(serde::de::Error::custom)?;
        Ok(UnsignedBtcAmount(value.to_sat()))
    }
}

impl serde::Serialize for UnsignedBtcAmount {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let value = bitcoin::amount::Amount::from_sat(self.0)
            .display_in(bitcoin::Denomination::Bitcoin)
            .to_string();
        let value = serde_json::Number::from_str(&value).map_err(serde::ser::Error::custom)?;
        value.serialize(s)
    }
}

impl UnsignedBtcAmount {
    pub fn to_sat(&self) -> u64 {
        self.0
    }

    pub fn to_btc_lossy(&self) -> f64 {
        bitcoin::amount::Amount::from_sat(self.0).to_btc()
    }
}

/// Signed bitcoin amount encoded as a JSON number in BTC units.
/// Parsed from the decimal JSON representation without converting through f64.
/// Requires serde_json with the `arbitrary_precision` feature.
/// Used with Bitcoin Core/Elements RPC.
#[derive(Debug, Clone, Copy)]
pub struct SignedBtcAmount(i64);

impl SignedBtcAmount {
    pub fn new(value: i64) -> Self {
        Self(value)
    }
}

impl<'de> serde::Deserialize<'de> for SignedBtcAmount {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = serde_json::Number::deserialize(d)?;
        let value =
            bitcoin::SignedAmount::from_str_in(&value.as_str(), bitcoin::Denomination::Bitcoin)
                .map_err(serde::de::Error::custom)?;
        Ok(SignedBtcAmount(value.to_sat()))
    }
}

impl serde::Serialize for SignedBtcAmount {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let value = bitcoin::amount::SignedAmount::from_sat(self.0)
            .display_in(bitcoin::Denomination::Bitcoin)
            .to_string();
        let value = serde_json::Number::from_str(&value).expect("must not fail");
        value.serialize(s)
    }
}

impl SignedBtcAmount {
    pub fn to_sat(&self) -> i64 {
        self.0
    }

    pub fn to_btc_lossy(&self) -> f64 {
        bitcoin::amount::SignedAmount::from_sat(self.0).to_btc()
    }
}

#[cfg(test)]
mod tests;
