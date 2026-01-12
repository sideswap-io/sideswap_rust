use std::time::Duration;

use rand::Rng;

pub struct RetryDelayOptions {
    pub base: f64,
    pub max: f64,
    pub multiply: f64,
    pub spread: f64,
}

#[derive(Clone, Debug)]
pub struct RetryDelay {
    initial_base: f64,
    base: f64,
    max: f64,
    multiply: f64,
    spread: f64,
}

impl RetryDelay {
    pub fn new(options: RetryDelayOptions) -> Self {
        let RetryDelayOptions {
            base,
            max,
            multiply,
            spread,
        } = options;

        let initial_base = base;

        RetryDelay {
            initial_base,
            base,
            max,
            multiply,
            spread,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let mut rng = rand::thread_rng();
        let random = rng.gen_range(-self.spread..=self.spread);
        let value = self.base * (1.0 + random);
        self.base = f64::min(self.max, value * self.multiply);
        Duration::from_secs_f64(value)
    }

    pub fn reset(&mut self) {
        self.base = self.initial_base;
    }
}

impl Default for RetryDelay {
    fn default() -> Self {
        Self::new(RetryDelayOptions {
            base: 1.0,
            max: 15.0,
            multiply: 2.0,
            spread: 0.3,
        })
    }
}

#[cfg(test)]
mod tests;
