//! Per-inspection decode budget (REA `ManagedDecodeBudget`).

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::common::{failure, js_len, R};

/// Per-inspection capacity for eagerly retained metadata and its JSON projection.
pub const MAX_METADATA_REPRESENTATION_BYTES: u64 = 64 * 1024 * 1024;

pub struct Budget {
    remaining: Cell<u64>,
    strings: RefCell<HashMap<i64, (String, i64)>>,
    digests: RefCell<HashMap<(bool, usize, usize), String>>,
}

impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}

impl Budget {
    pub fn new() -> Self {
        Self {
            remaining: Cell::new(MAX_METADATA_REPRESENTATION_BYTES),
            strings: RefCell::new(HashMap::new()),
            digests: RefCell::new(HashMap::new()),
        }
    }

    pub fn reserve(&self, bytes: u64, offset: Option<i64>) -> R<()> {
        if bytes > self.remaining.get() {
            return Err(failure(
                "resource-limit",
                "metadata.representation",
                format!(
                    "Managed metadata exceeds the {MAX_METADATA_REPRESENTATION_BYTES} byte representation budget"
                ),
                offset,
            ));
        }
        self.remaining.set(self.remaining.get() - bytes);
        Ok(())
    }

    /// UTF-8 cannot decode to more UTF-16 units than bytes; JSON uses at most six bytes per unit.
    pub fn reserve_string(&self, encoded_bytes: u64, offset: Option<i64>) -> R<()> {
        self.reserve(encoded_bytes.saturating_mul(6).saturating_add(2), offset)
    }

    /// Cache exact backing-buffer ranges (identified by address and length).
    pub fn digest(&self, bytes: &[u8], sha1: bool) -> R<String> {
        let key = (sha1, bytes.as_ptr() as usize, bytes.len());
        if let Some(cached) = self.digests.borrow().get(&key) {
            return Ok(cached.clone());
        }
        self.reserve(256, None)?;
        let digest = if sha1 {
            hex::encode(sha1::Sha1::digest(bytes))
        } else {
            hex::encode(Sha256::digest(bytes))
        };
        self.digests.borrow_mut().insert(key, digest.clone());
        Ok(digest)
    }

    pub fn cached_string(&self, index: i64) -> Option<(String, i64)> {
        self.strings.borrow().get(&index).cloned()
    }

    pub fn cache_string(&self, index: i64, value: String, encoded_bytes: i64) {
        self.strings.borrow_mut().insert(index, (value, encoded_bytes));
    }

    /// `admitManagedProjection`: repeated values count too, since shared heap
    /// strings still expand at the JSON boundary.
    pub fn admit(&self, value: Value) -> R<Value> {
        self.visit(&value)?;
        Ok(value)
    }

    fn visit(&self, item: &Value) -> R<()> {
        match item {
            Value::String(text) => self.reserve_string(js_len(text), None),
            Value::Array(items) => {
                self.reserve(items.len() as u64 + 2, None)?;
                for child in items {
                    self.visit(child)?;
                }
                Ok(())
            }
            Value::Object(map) => {
                self.reserve(2, None)?;
                for (key, child) in map {
                    self.reserve(js_len(key) * 6 + 4, None)?;
                    self.visit(child)?;
                }
                Ok(())
            }
            _ => self.reserve(32, None),
        }
    }
}
