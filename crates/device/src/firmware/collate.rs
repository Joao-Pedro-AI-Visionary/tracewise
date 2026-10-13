//! `String.prototype.localeCompare` (ICU root collation, en-US) as used by REA to
//! order extracted paths.
//!
//! The ASCII order below was read back from Node 22 / ICU 78.3 itself
//! (`fixtures/firmware/collate_pairs.json` holds pair verdicts that the unit
//! tests replay). Primary weights decide first, case (lowercase before
//! uppercase) breaks ties; control characters are ignorable. Non-ASCII
//! characters sort after Latin letters by code point, an approximation that is
//! exact for the ASCII file names firmware extractors produce.

use std::cmp::Ordering;

/// Printable ASCII from lowest to highest primary weight.
const ORDER: &str = "\t\n\u{b}\u{c}\r _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789";

fn primary(c: char) -> Option<(u32, u32)> {
    if let Some(index) = ORDER.find(c) {
        return Some((index as u32, 0));
    }
    if c.is_ascii_alphabetic() {
        let letter = c.to_ascii_lowercase() as u32 - 'a' as u32;
        return Some((1000 + letter, u32::from(c.is_ascii_uppercase())));
    }
    if (c as u32) < 0x20 || c as u32 == 0x7f {
        return None; // ignorable control
    }
    Some((2000 + c as u32, 0))
}

fn keys(text: &str) -> (Vec<u32>, Vec<u32>) {
    let mut weights = Vec::new();
    let mut tertiary = Vec::new();
    for c in text.chars() {
        if let Some((weight, case)) = primary(c) {
            weights.push(weight);
            tertiary.push(case);
        }
    }
    (weights, tertiary)
}

/// `a.localeCompare(b)` as an ordering.
pub fn locale_compare(a: &str, b: &str) -> Ordering {
    let (pa, ta) = keys(a);
    let (pb, tb) = keys(b);
    pa.cmp(&pb).then_with(|| ta.cmp(&tb))
}

/// `compareUnicodeCodePoints`.
pub fn code_point_order(a: &str, b: &str) -> Ordering {
    a.chars().cmp(b.chars())
}

/// Default JavaScript string order (UTF-16 code units), as `Array.prototype.sort()` uses.
pub fn utf16_order(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_node_icu_pairs() {
        let raw = include_str!("../../../../fixtures/firmware/collate_pairs.json");
        let pairs: serde_json::Value = serde_json::from_str(raw).unwrap();
        let mut checked = 0;
        for pair in pairs.as_array().unwrap() {
            let (a, b, expected) = (pair[0].as_str().unwrap(), pair[1].as_str().unwrap(), pair[2].as_i64().unwrap());
            let actual = match locale_compare(a, b) {
                Ordering::Less => -1,
                Ordering::Equal => 0,
                Ordering::Greater => 1,
            };
            // The fixture includes non-ASCII samples; only ASCII is claimed exact.
            if a.is_ascii() && b.is_ascii() {
                assert_eq!(actual, expected, "{a:?} vs {b:?}");
                checked += 1;
            }
        }
        assert!(checked > 400, "only {checked} ASCII pairs checked");
    }
}
