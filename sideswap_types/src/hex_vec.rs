use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

// Wrapper struct for Vec<u8> used to serialize and deserialize vectors as hex strings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexVec(pub Vec<u8>);

impl Serialize for HexVec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = hex::encode(&self.0);
        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for HexVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HexVecVisitor;

        impl<'de> serde::de::Visitor<'de> for HexVecVisitor {
            type Value = HexVec;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a hex-encoded string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                hex::decode(v)
                    .map(HexVec)
                    .map_err(|e| E::custom(format!("failed to decode hex: {}", e)))
            }
        }

        deserializer.deserialize_str(HexVecVisitor)
    }
}

impl From<Vec<u8>> for HexVec {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<HexVec> for Vec<u8> {
    fn from(value: HexVec) -> Self {
        value.0
    }
}

impl std::ops::Deref for HexVec {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for HexVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for HexVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_string = hex::encode(&self.0);
        write!(f, "{}", hex_string)
    }
}
