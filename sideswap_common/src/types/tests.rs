use super::*;

#[test]
fn test_select_utxo() {
    assert_eq!(select_utxo(vec![10], 10), vec![10]);
    assert_eq!(select_utxo(vec![15], 10), vec![15]);
    assert_eq!(select_utxo(vec![15, 10], 25), vec![15, 10]);
    assert_eq!(select_utxo(vec![5000, 10, 5], 15), vec![10, 5]);
    assert_eq!(select_utxo(vec![5000, 10, 5], 16), vec![5000]);
    assert_eq!(select_utxo(vec![1000, 100, 10, 1], 101), vec![100, 1]);
    assert_eq!(select_utxo(vec![1000, 100, 10, 1], 102), vec![100, 10]);
    assert_eq!(select_utxo(vec![1000, 100, 10, 1], 1), vec![1]);
    assert_eq!(select_utxo(vec![1000, 100, 10, 1], 10), vec![10]);
    assert_eq!(select_utxo(vec![1000, 100, 10, 1], 100), vec![100]);
}
