//! Small helpers shared by the derived tools: deterministic ordering and canonical digests.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use serde_json::Value;
use tracewise_domain::canonical::{canonical_json, canonical_sha256};

/// `compareUnicodeCodePoints`: UTF-8 byte order is code point order.
pub fn code_point_cmp(left: &str, right: &str) -> Ordering {
    left.cmp(right)
}

/// JavaScript's default `Array.prototype.sort` order: UTF-16 code units.
pub fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// Deduplicate and order by code point.
pub fn sorted_unique(values: Vec<String>) -> Vec<String> {
    values.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

/// RFC 8785 canonical JSON of a value.
pub fn canonical(value: &Value) -> String {
    canonical_json(value).expect("JSON values always canonicalize")
}

/// SHA-256 over the canonical JSON of a value (`digestCanonicalValue`).
pub fn digest(value: &Value) -> String {
    canonical_sha256(value).expect("JSON values always canonicalize")
}

/// `sorted`: order values by their canonical JSON, compared by code point.
pub fn sorted_by_canonical(values: Vec<Value>) -> Vec<Value> {
    let mut keyed: Vec<(String, Value)> = values.into_iter().map(|value| (canonical(&value), value)).collect();
    keyed.sort_by(|left, right| code_point_cmp(&left.0, &right.0));
    keyed.into_iter().map(|(_, value)| value).collect()
}
