use bitcoin::bip32::ChildNumber;

pub fn path_to_u32(path: &[ChildNumber]) -> Vec<u32> {
    path.iter().copied().map(u32::from).collect::<Vec<_>>()
}

pub fn path_from_u32(path: &[u32]) -> Vec<ChildNumber> {
    path.iter()
        .copied()
        .map(ChildNumber::from)
        .collect::<Vec<_>>()
}
