use std::cmp::Ordering;

/// Lexicographic compare by Unicode scalar values (matches REA `compareUnicodeCodePoints`).
pub fn compare_unicode_code_points(left: &str, right: &str) -> Ordering {
    let mut left_chars = left.chars();
    let mut right_chars = right.chars();
    loop {
        match (left_chars.next(), right_chars.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(l), Some(r)) => match l.cmp(&r) {
                Ordering::Equal => {}
                other => return other,
            },
        }
    }
}

pub fn unique_sorted(strings: &[String]) -> Vec<String> {
    let mut out: Vec<String> = strings.to_vec();
    out.sort_by(|a, b| compare_unicode_code_points(a, b));
    out.dedup();
    out
}
