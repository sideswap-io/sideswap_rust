#[derive(Debug, Copy, Clone)]
pub struct StrEncoded<T>(T);

impl<T> StrEncoded<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> AsRef<T> for StrEncoded<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for StrEncoded<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: std::fmt::Display> serde::Serialize for StrEncoded<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de, T> serde::Deserialize<'de> for StrEncoded<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let str = String::deserialize(deserializer)?;
        let value = T::from_str(&str).map_err(serde::de::Error::custom)?;
        Ok(StrEncoded(value))
    }
}
