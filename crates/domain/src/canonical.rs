use sha2::{Digest, Sha256};

use crate::error::DomainError;

/// Serializes value to RFC 8785 canonical JSON bytes.
pub fn canonical_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, DomainError> {
    serde_jcs::to_vec(value).map_err(|e| DomainError::Canonicalization(e.to_string()))
}

/// Serializes value to RFC 8785 canonical JSON string.
pub fn canonical_json<T: serde::Serialize>(value: &T) -> Result<String, DomainError> {
    serde_jcs::to_string(value).map_err(|e| DomainError::Canonicalization(e.to_string()))
}

/// Computes SHA-256 of RFC 8785 canonical JSON as a 64-character lowercase hex string.
pub fn canonical_sha256<T: serde::Serialize>(value: &T) -> Result<String, DomainError> {
    let bytes = canonical_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}
