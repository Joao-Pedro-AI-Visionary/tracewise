//! Small shared helpers (JS-compatible number formatting, ordering, hashing, ranges).

use std::collections::HashMap;
use std::hash::Hash;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::ast::{SourceRange, N};

/// `compareUnicodeCodePoints`: lexicographic by Unicode code point.
pub fn compare_code_points(left: &str, right: &str) -> std::cmp::Ordering {
    crate::unicode::compare_unicode_code_points(left, right)
}

/// `compositeKey`: JSON tuple, collision free for any component text.
pub fn composite_key(parts: &[Value]) -> String {
    serde_json::to_string(parts).expect("json tuple")
}

/// Lowercase hex SHA-256 of UTF-8 text (`sha256Text`).
pub fn sha256_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// REA `range(node)`: the node's Babel `loc` as the stable source-range shape.
pub fn range(node: N<'_>) -> SourceRange {
    node.loc()
}

/// REA `sourceRangesEqual(left, right)` with `left` optional.
pub fn source_ranges_equal(left: Option<&SourceRange>, right: &SourceRange) -> bool {
    left == Some(right)
}

/// ECMAScript `String(number)` / `Number::toString(10)`.
pub fn js_number_to_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value == 0.0 {
        return "0".into();
    }
    if value.is_infinite() {
        return if value < 0.0 { "-Infinity".into() } else { "Infinity".into() };
    }
    let sign = if value < 0.0 { "-" } else { "" };
    // Shortest round-trip digits: "d.ddde<exp>".
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').expect("scientific");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let exponent: i32 = exponent.parse().expect("exponent");
    let k = digits.len() as i32;
    let n = exponent + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let exp = format!("e{}{}", if e < 0 { "-" } else { "+" }, e.abs());
        if k == 1 {
            format!("{digits}{exp}")
        } else {
            format!("{}.{}{exp}", &digits[..1], &digits[1..])
        }
    };
    format!("{sign}{body}")
}

/// Insertion-ordered map with JS `Map` semantics: re-inserting a key keeps its first position
/// and replaces the value.
pub struct OrderedMap<K, V> {
    index: HashMap<K, usize>,
    entries: Vec<(K, V)>,
}

impl<K: Hash + Eq + Clone, V> OrderedMap<K, V> {
    pub fn new() -> Self {
        OrderedMap { index: HashMap::new(), entries: Vec::new() }
    }

    pub fn insert(&mut self, key: K, value: V) {
        match self.index.get(&key) {
            Some(&slot) => self.entries[slot].1 = value,
            None => {
                self.index.insert(key.clone(), self.entries.len());
                self.entries.push((key, value));
            }
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.index.get(key).map(|&slot| &self.entries[slot].1)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        match self.index.get(key) {
            Some(&slot) => Some(&mut self.entries[slot].1),
            None => None,
        }
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn into_entries(self) -> Vec<(K, V)> {
        self.entries
    }

    pub fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.entries.iter()
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, v)| v)
    }
}

impl<K: Hash + Eq + Clone, V> Default for OrderedMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

/// Sort values by a deterministic unique key; for equal keys the last value wins but keeps the
/// first position before sorting (`sortedUnique`).
pub fn sorted_unique<T>(values: Vec<T>, key: impl Fn(&T) -> String) -> Vec<T> {
    let mut by_key: OrderedMap<String, T> = OrderedMap::new();
    for value in values {
        by_key.insert(key(&value), value);
    }
    let mut entries = by_key.into_entries();
    entries.sort_by(|a, b| compare_code_points(&a.0, &b.0));
    entries.into_iter().map(|(_, v)| v).collect()
}

#[cfg(test)]
mod tests {
    use super::js_number_to_string as s;

    #[test]
    fn number_to_string_matches_ecmascript() {
        assert_eq!(s(0.0), "0");
        assert_eq!(s(-0.0), "0");
        assert_eq!(s(1.0), "1");
        assert_eq!(s(-1.5), "-1.5");
        assert_eq!(s(100.0), "100");
        assert_eq!(s(1e21), "1e+21");
        assert_eq!(s(1e20), "100000000000000000000");
        assert_eq!(s(1.5e-7), "1.5e-7");
        assert_eq!(s(0.000001), "0.000001");
        assert_eq!(s(123456789.125), "123456789.125");
        assert_eq!(s(9007199254740992.0), "9007199254740992");
        assert_eq!(s(0.1 + 0.2), "0.30000000000000004");
        assert_eq!(s(f64::INFINITY), "Infinity");
        assert_eq!(s(5e-324), "5e-324");
    }
}
