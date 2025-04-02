use std::str::FromStr;

use super::*;

#[test]
fn hash32() {
    let hash_str = "87f29c933a6be42c116866f7fabb1e1210bd42e57fe9cf357dac160700b9b1fa";
    let hash_bin = Hash32::from_str(hash_str).unwrap();
    assert_eq!(hash_str, hash_bin.to_string());

    {
        let elements_txid = elements::Txid::from(hash_bin);
        assert_eq!(elements_txid.to_string(), hash_str);

        let hash_new = Hash32::from(elements_txid);
        assert_eq!(hash_new, hash_bin);
    }

    {
        let bitcoin_txid = elements::bitcoin::Txid::from(hash_bin);
        assert_eq!(bitcoin_txid.to_string(), hash_str);

        let hash_new = Hash32::from(bitcoin_txid);
        assert_eq!(hash_new, hash_bin);
    }
}
