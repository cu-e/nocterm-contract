use crate::KeyError;

/// `N` bytes from the operating system's secure random generator.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], KeyError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(KeyError::Random)?;
    Ok(bytes)
}

/// A URL-safe random token with 256 bits of entropy (lowercase hex).
pub fn random_token() -> Result<String, KeyError> {
    let bytes = random_bytes::<32>()?;
    Ok(hex::encode(bytes))
}
