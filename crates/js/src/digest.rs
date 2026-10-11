use tracewise_domain::canonical::canonical_sha256;
use tracewise_domain::error::DomainError;

pub fn digest_canonical_value<T: serde::Serialize>(value: &T) -> Result<String, DomainError> {
    canonical_sha256(value)
}
