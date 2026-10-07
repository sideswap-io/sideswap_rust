// Serialized as hex in JSON and byte strings in CBOR
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteArray<const T: usize>(pub [u8; T]);

impl<const LEN: usize> std::fmt::LowerHex for ByteArray<LEN> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for ch in self.0 {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl<const LEN: usize> std::fmt::Display for ByteArray<LEN> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(self, f)
    }
}

impl<const LEN: usize> std::str::FromStr for ByteArray<LEN> {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; LEN];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl<const LEN: usize> serde::Serialize for ByteArray<LEN> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de, const LEN: usize> serde::Deserialize<'de> for ByteArray<LEN> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            // Accept owned strings too (e.g. the `config` crate never lends borrowed data)
            struct HexVisitor<const LEN: usize>;

            impl<const LEN: usize> serde::de::Visitor<'_> for HexVisitor<LEN> {
                type Value = ByteArray<LEN>;

                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(f, "a hex string of {} bytes", LEN)
                }

                fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                    s.parse().map_err(E::custom)
                }
            }

            d.deserialize_str(HexVisitor::<LEN>)
        } else {
            use serde_bytes::Deserialize;
            Ok(Self(<[u8; LEN]>::deserialize(d)?))
        }
    }
}

impl<const LEN: usize> rand::distributions::Distribution<ByteArray<LEN>>
    for rand::distributions::Standard
{
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> ByteArray<LEN> {
        let mut data = [0u8; LEN];
        rng.fill_bytes(&mut data);
        ByteArray(data)
    }
}

pub type ByteArray16 = ByteArray<16>;
pub type ByteArray32 = ByteArray<32>;
pub type ByteArray33 = ByteArray<33>;
