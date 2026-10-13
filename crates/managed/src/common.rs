//! Shared failure types and JavaScript/Node compatibility helpers.
//!
//! REA runs on Node: bounded `Buffer` reads throw `RangeError` with fixed
//! messages, numbers print with `Number#toString`, and `Array#sort` orders by
//! UTF-16 code units. A few of those strings leak into results (for example a
//! truncated CIL operand becomes the body `issue`), so they are reproduced.

use serde_json::{json, Value};

/// `ManagedParseIssue`: a bounded format failure retained as coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub code: &'static str,
    pub scope: String,
    pub offset: Option<i64>,
    pub detail: String,
}

impl Issue {
    pub fn to_json(&self) -> Value {
        json!({
            "code": self.code,
            "scope": self.scope,
            "offset": self.offset,
            "detail": self.detail,
        })
    }
}

/// Everything a reader can throw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// `ManagedReaderFailure`.
    Reader(Issue),
    /// Node `RangeError` (bounded `Buffer` read, explicit `new RangeError`).
    Range(String),
}

impl Failure {
    pub fn message(&self) -> &str {
        match self {
            Failure::Reader(issue) => &issue.detail,
            Failure::Range(message) => message,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Failure {}

pub type R<T> = Result<T, Failure>;

/// `managedFailure(code, scope, detail, offset)`.
pub fn failure(code: &'static str, scope: impl Into<String>, detail: impl Into<String>, offset: Option<i64>) -> Failure {
    Failure::Reader(Issue { code, scope: scope.into(), offset, detail: detail.into() })
}

/// `readManagedValue`: keep one malformed item's location and continue.
pub fn read_value<T>(op: impl FnOnce() -> R<T>, issues: &mut Vec<Issue>) -> R<Option<T>> {
    match op() {
        Ok(value) => Ok(Some(value)),
        Err(Failure::Reader(issue)) if issue.code != "resource-limit" => {
            issues.push(issue);
            Ok(None)
        }
        Err(other) => Err(other),
    }
}

/// `uniqueManagedParseIssues`: first occurrence wins, order preserved.
pub fn unique_issues(issues: &[Issue]) -> Vec<Issue> {
    let mut out: Vec<Issue> = Vec::new();
    for issue in issues {
        if !out.contains(issue) {
            out.push(issue.clone());
        }
    }
    out
}

pub fn issues_json(issues: &[Issue]) -> Value {
    Value::Array(issues.iter().map(Issue::to_json).collect())
}

/// Node `Buffer` view with bounds-checked little-endian reads that throw the
/// same `RangeError` messages as Node 22.
#[derive(Clone, Copy)]
pub struct Buf<'a>(pub &'a [u8]);

fn group_digits(value: &str) -> String {
    let (sign, digits) = match value.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", value),
    };
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push('_');
        }
        out.push(ch);
    }
    format!("{sign}{out}")
}

/// Node `boundsError(offset, length)` for an integer offset.
pub fn bounds_error(offset: i64, length: i64) -> Failure {
    if length < 0 {
        return Failure::Range("Attempt to access memory outside buffer bounds".to_string());
    }
    let received = if offset.unsigned_abs() > (1u64 << 32) {
        group_digits(&offset.to_string())
    } else {
        offset.to_string()
    };
    Failure::Range(format!(
        "The value of \"offset\" is out of range. It must be >= 0 and <= {length}. Received {received}"
    ))
}

impl<'a> Buf<'a> {
    pub fn len(&self) -> i64 {
        self.0.len() as i64
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `this[offset]` (undefined when out of range).
    pub fn at(&self, offset: i64) -> Option<u8> {
        if offset < 0 {
            None
        } else {
            self.0.get(offset as usize).copied()
        }
    }

    fn check(&self, offset: i64, width: i64) -> R<usize> {
        if offset < 0 || offset > self.len() - width {
            return Err(bounds_error(offset, self.len() - width));
        }
        Ok(offset as usize)
    }

    pub fn u8(&self, offset: i64) -> R<u8> {
        let o = self.check(offset, 1)?;
        Ok(self.0[o])
    }

    pub fn i8(&self, offset: i64) -> R<i8> {
        Ok(self.u8(offset)? as i8)
    }

    pub fn u16(&self, offset: i64) -> R<u16> {
        let o = self.check(offset, 2)?;
        Ok(u16::from_le_bytes([self.0[o], self.0[o + 1]]))
    }

    pub fn u32(&self, offset: i64) -> R<u32> {
        let o = self.check(offset, 4)?;
        Ok(u32::from_le_bytes([self.0[o], self.0[o + 1], self.0[o + 2], self.0[o + 3]]))
    }

    pub fn i32(&self, offset: i64) -> R<i32> {
        Ok(self.u32(offset)? as i32)
    }

    pub fn u64(&self, offset: i64) -> R<u64> {
        let o = self.check(offset, 8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&self.0[o..o + 8]);
        Ok(u64::from_le_bytes(raw))
    }

    pub fn i64(&self, offset: i64) -> R<i64> {
        Ok(self.u64(offset)? as i64)
    }

    pub fn f32(&self, offset: i64) -> R<f32> {
        Ok(f32::from_bits(self.u32(offset)?))
    }

    pub fn f64(&self, offset: i64) -> R<f64> {
        Ok(f64::from_bits(self.u64(offset)?))
    }

    /// `subarray(start, end)` with Node clamping.
    pub fn sub(&self, start: i64, end: i64) -> Buf<'a> {
        let len = self.len();
        let clamp = |v: i64| -> i64 {
            if v < 0 {
                (len + v).max(0)
            } else {
                v.min(len)
            }
        };
        let s = clamp(start);
        let e = clamp(end);
        if e <= s {
            Buf(&self.0[0..0])
        } else {
            Buf(&self.0[s as usize..e as usize])
        }
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// `requireRange` shared shape: (offset, length) must lie inside `len`.
pub fn in_range(len: i64, offset: i64, length: i64) -> bool {
    !(offset < 0 || length < 0 || offset > len - length)
}

/// JavaScript `Number#toString` for a double.
pub fn js_number_to_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value == 0.0 {
        return "0".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    let negative = value < 0.0;
    // Rust's `{:e}` yields the shortest round-trip digits, like JS.
    let sci = format!("{:e}", value.abs());
    let (mantissa, exponent) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exponent + 1;
    let body = if k <= n && n <= 21 {
        format!("{}{}", digits, "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        if k == 1 {
            format!("{}e{}{}", digits, sign, e.abs())
        } else {
            format!("{}.{}e{}{}", &digits[..1], &digits[1..], sign, e.abs())
        }
    };
    if negative {
        format!("-{body}")
    } else {
        body
    }
}

/// UTF-16 length, as JavaScript `String#length`.
pub fn js_len(value: &str) -> u64 {
    value.encode_utf16().count() as u64
}

/// Default `Array#sort` on strings (UTF-16 code unit order).
pub fn js_sort(values: &mut [String]) {
    values.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
}

pub fn hex_u32(value: u32) -> String {
    format!("0x{value:08x}")
}

/// Catch a non-resource-limit reader failure into `issues` (the `readManagedValue` contract).
pub fn swallow<T>(result: R<T>, issues: &mut Vec<Issue>) -> R<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Failure::Reader(issue)) if issue.code != "resource-limit" => {
            issues.push(issue);
            Ok(None)
        }
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_to_string_matches_js() {
        assert_eq!(js_number_to_string(1.0), "1");
        assert_eq!(js_number_to_string(1.5), "1.5");
        assert_eq!(js_number_to_string(f64::from(1.1f32)), "1.100000023841858");
        assert_eq!(js_number_to_string(1e21), "1e+21");
        assert_eq!(js_number_to_string(1e-7), "1e-7");
        assert_eq!(js_number_to_string(0.000001), "0.000001");
        assert_eq!(js_number_to_string(-0.0), "0");
        assert_eq!(js_number_to_string(123456789012345680000.0), "123456789012345680000");
        assert_eq!(js_number_to_string(3.4028234663852886e38), "3.4028234663852886e+38");
    }

    #[test]
    fn buffer_errors_match_node() {
        let b = Buf(&[1, 2, 3]);
        assert_eq!(b.u32(0).unwrap_err().message(), "Attempt to access memory outside buffer bounds");
        let b = Buf(&[1, 2, 3, 4, 5]);
        assert_eq!(
            b.u32(2).unwrap_err().message(),
            "The value of \"offset\" is out of range. It must be >= 0 and <= 1. Received 2"
        );
    }
}

