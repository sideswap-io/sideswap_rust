/// A price change within this EPS should not have a significant impact
pub const PRICE_EPS: f64 = 1e-12;

pub fn values_near_equal(value_1: f64, value_2: f64, eps: f64) -> bool {
    if value_1.is_nan() || value_2.is_nan() {
        return false;
    }

    if value_1.is_infinite() || value_2.is_infinite() {
        return value_1 == value_2;
    }

    let diff = (value_1 - value_2).abs();

    diff <= eps * value_1.abs().max(value_2.abs())
}

#[cfg(test)]
mod tests;
