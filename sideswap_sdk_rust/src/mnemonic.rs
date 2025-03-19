pub fn generate_mnemonic() -> String {
    bip39::Mnemonic::generate(12)
        .expect("should not fail")
        .to_string()
}
