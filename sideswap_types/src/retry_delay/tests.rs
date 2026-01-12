use super::*;

#[test]
fn zero_spread() {
    let mut retry_delay = RetryDelay::new(RetryDelayOptions {
        base: 1.0,
        max: 30.0,
        multiply: 2.0,
        spread: 0.0,
    });
    retry_delay.next_delay();
}
