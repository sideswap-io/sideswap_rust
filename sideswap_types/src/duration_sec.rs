use std::time::Duration;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct DurationSec(u32);

impl DurationSec {
    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.0.into())
    }

    pub fn as_seconds(self) -> u32 {
        self.0
    }

    pub fn from_secs(value: u32) -> DurationSec {
        DurationSec(value)
    }
}

impl From<Duration> for DurationSec {
    fn from(value: Duration) -> Self {
        DurationSec(u32::try_from(value.as_secs()).unwrap_or(u32::MAX))
    }
}
