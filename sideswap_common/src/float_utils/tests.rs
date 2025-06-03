use super::*;

#[test]
fn prices_compare() {
    assert!(values_near_equal(
        105745.74371892711,
        105745.74371892713,
        PRICE_EPS
    ));

    assert!(values_near_equal(107023.28399999999, 107023.284, PRICE_EPS));

    assert!(!values_near_equal(105745.74371892711, 105745.8, PRICE_EPS));
}
