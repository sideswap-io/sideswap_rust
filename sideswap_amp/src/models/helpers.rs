use std::{marker::PhantomData, str::FromStr};

use hex::FromHex;
use serde::{de::IntoDeserializer, Deserialize};

pub fn deserialize_hex<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: elements::encode::Decodable,
{
    struct Helper<T>(PhantomData<T>);

    impl<T> serde::de::Visitor<'_> for Helper<T>
    where
        T: elements::encode::Decodable,
    {
        type Value = T;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                f,
                "a hex‑encoded string representing an value of type {}",
                std::any::type_name::<T>()
            )
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let bytes = <Vec<u8>>::from_hex(v).map_err(E::custom)?;
            elements::encode::deserialize(&bytes).map_err(E::custom)
        }
    }

    d.deserialize_any(Helper::<T>(PhantomData))
}

pub fn deserialize_nonce<'de, D>(d: D) -> Result<elements::confidential::Nonce, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    struct Helper;

    impl serde::de::Visitor<'_> for Helper {
        type Value = elements::confidential::Nonce;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("66‑char hex string representing elements::confidential::Nonce")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if s == "000000000000000000000000000000000000000000000000000000000000000000" {
                Ok(elements::confidential::Nonce::Null)
            } else {
                deserialize_hex(s.into_deserializer())
            }
        }
    }

    d.deserialize_any(Helper)
}

pub fn deserialize_with_optional_empty_string<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: serde::de::Deserialize<'de>,
{
    struct Helper<T>(PhantomData<T>);

    impl<'de, T> serde::de::Visitor<'de> for Helper<T>
    where
        T: serde::de::Deserialize<'de>,
    {
        type Value = Option<T>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                f,
                "an empty string or a value encoded as a string for {}",
                std::any::type_name::<T>()
            )
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v.is_empty() {
                Ok(None)
            } else {
                T::deserialize(v.into_deserializer()).map(Some)
            }
        }
    }

    d.deserialize_any(Helper::<T>(PhantomData))
}

pub fn deserialize_txid<'de, D>(d: D) -> Result<elements::Txid, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    struct Helper;

    impl serde::de::Visitor<'_> for Helper {
        type Value = elements::Txid;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("64‑char hex string representing elements::Txid")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            elements::Txid::from_str(s).map_err(|e| E::custom(format!("invalid hex txid: {e}")))
        }
    }

    d.deserialize_any(Helper)
}

pub fn deserialize_txid_opt<'de, D>(d: D) -> Result<Option<elements::Txid>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    struct Helper;

    impl serde::de::Visitor<'_> for Helper {
        type Value = Option<elements::Txid>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("optional 64‑char hex string representing elements::Txid")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            elements::Txid::from_str(s)
                .map(Some)
                .map_err(|e| E::custom(format!("invalid hex txid: {e}")))
        }
    }

    d.deserialize_any(Helper)
}
