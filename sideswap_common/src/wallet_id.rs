use bitcoin::hashes::sha256t_hash_newtype;

sha256t_hash_newtype! {
    /// The tag of the hash
    pub struct WalletIdTag = hash_str("SideSwap-Wallet-Id/1.0");

    /// A tagged hash to generate the wallet id derived from a wallet descriptor
    #[hash_newtype(forward)]
    pub struct WalletIdHash(_);
}
