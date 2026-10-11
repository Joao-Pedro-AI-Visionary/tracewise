use sha2::{Digest, Sha256};

pub const ARTIFACT_CLASSIFICATION_PREFIX_BYTES: usize = 8192;

#[derive(Debug, Clone)]
pub struct HashResult {
    pub sha256: String,
    pub bytes: u64,
    pub prefix: Vec<u8>,
}

pub fn hash_bytes(data: &[u8]) -> HashResult {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256 = hex::encode(hasher.finalize());
    let prefix_len = data.len().min(ARTIFACT_CLASSIFICATION_PREFIX_BYTES);
    HashResult {
        sha256,
        bytes: data.len() as u64,
        prefix: data[..prefix_len].to_vec(),
    }
}

pub fn hash_file(path: &std::path::Path) -> Result<HashResult, std::io::Error> {
    let data = std::fs::read(path)?;
    Ok(hash_bytes(&data))
}
