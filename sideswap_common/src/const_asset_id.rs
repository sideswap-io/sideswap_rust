/// Use for const initialization only.
/// Panics if invalid string is supplied.
pub const fn const_asset_id(s: &str) -> elements::AssetId {
    let mut data: [u8; 32] = hex_literal::decode::<32>(&[s.as_bytes()]);

    let mut left = 0;
    let mut right = data.len() - 1;
    while left < right {
        let tmp = data[left];
        data[left] = data[right];
        data[right] = tmp;
        left += 1;
        right -= 1;
    }

    elements::AssetId::from_inner(bitcoin::hashes::sha256::Midstate(data))
}

#[cfg(test)]
mod tests;
