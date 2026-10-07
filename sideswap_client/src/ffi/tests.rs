use super::*;

#[test]
fn test_address_check() {
    // P2TR
    assert!(check_bitcoin_address(
        Env::Prod,
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    ));
}


#[test]
fn test_elements_address_check() {
    // Confidential — the ordinary wallet-to-wallet case.
    assert!(check_elements_address(
        Env::Testnet,
        "tlq1pqtv3uxfrh4lvjpv6xcrkt95r063ldl7w0dd2xf7au5ptm2u2r600ffjsdwz4m5j59au9vsqv4jl84u936njznnt869fr8cmla8lztn3vlk3jt2rluzvx"
    ));

    // Unconfidential — a covenant funding address, which cannot be blinded
    // because the contract has to read the amount on-chain.
    assert!(check_elements_address(
        Env::Testnet,
        "tex1p5egxhp2a6f2z77zkgqx2e0n67zcafepfe4naz53nudl7nl39eckq0efc2u"
    ));

    // Still rejected: not an address, and a valid address for another network.
    assert!(!check_elements_address(Env::Testnet, "not-an-address"));
    assert!(!check_elements_address(
        Env::Prod,
        "tex1p5egxhp2a6f2z77zkgqx2e0n67zcafepfe4naz53nudl7nl39eckq0efc2u"
    ));
}
