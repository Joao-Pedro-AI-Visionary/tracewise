//! Property-list decoding that reproduces the `plist` 5.0.0 JavaScript package
//! REA uses (XML via a DOM, binary via `parse-binary.js`), together with REA's
//! projection of the decoded value into JSON (`plistValue.ts`,
//! `propertyListKeys.ts`, `propertyListXmlText.ts`, `PlistNumberLiterals.ts`,
//! `plistNumbers.ts`).
//!
//! Behaviour is deliberately JavaScript-shaped: integers are IEEE doubles,
//! dictionaries are insertion ordered, and decoding errors carry the message
//! the JavaScript runtime would raise.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use base64::Engine;
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{json, Map, Value};

/// A decoded plist value, as the JavaScript decoder returns it.
#[derive(Clone, Debug)]
pub enum PVal {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Data(Vec<u8>),
    /// Milliseconds since the Unix epoch; NaN is an invalid date.
    Date(f64),
    Array(Vec<PVal>),
    Dict(IndexMap<String, PVal>),
}

/// JavaScript error class of a decoding failure (`RangeError` vs everything else).
#[derive(Clone, Debug, PartialEq)]
pub struct PlistError {
    pub range: bool,
    pub message: String,
}

impl PlistError {
    pub fn type_error(message: impl Into<String>) -> Self {
        Self {
            range: false,
            message: message.into(),
        }
    }
    pub fn range_error(message: impl Into<String>) -> Self {
        Self {
            range: true,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PlistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub type PlistResult<T> = Result<T, PlistError>;

const OOB: &str = "Offset is outside the bounds of the DataView";

// ---------------------------------------------------------------------------
// JavaScript number helpers
// ---------------------------------------------------------------------------

/// `JSON.stringify` of a double: integral values print as integers, NaN/Infinity as null.
pub fn js_number(x: f64) -> Value {
    if !x.is_finite() {
        return Value::Null;
    }
    if x == 0.0 {
        return json!(0);
    }
    if x.fract() == 0.0 && x.abs() < 9.0e18 {
        return json!(x as i64);
    }
    serde_json::Number::from_f64(x).map(Value::Number).unwrap_or(Value::Null)
}

pub fn value_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

pub fn is_safe_integer(x: f64) -> bool {
    x.is_finite() && x.fract() == 0.0 && x.abs() <= MAX_SAFE
}

fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{9}' | '\u{a}' | '\u{b}' | '\u{c}' | '\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// `parseInt(text, 10)`.
pub fn js_parse_int(text: &str) -> f64 {
    let trimmed = text.trim_start_matches(is_js_whitespace);
    let (negative, rest) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return f64::NAN;
    }
    let value: f64 = digits.parse().unwrap_or(f64::NAN);
    if negative {
        -value
    } else {
        value
    }
}

/// `parseFloat(text)`.
pub fn js_parse_float(text: &str) -> f64 {
    let trimmed = text.trim_start_matches(is_js_whitespace);
    let (negative, rest) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let sign = if negative { -1.0 } else { 1.0 };
    if rest.starts_with("Infinity") {
        return sign * f64::INFINITY;
    }
    let bytes = rest.as_bytes();
    let mut end = 0usize;
    let mut digits = 0usize;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
        digits += 1;
    }
    if end < bytes.len() && bytes[end] == b'.' {
        let mut fraction_end = end + 1;
        let mut fraction_digits = 0usize;
        while fraction_end < bytes.len() && bytes[fraction_end].is_ascii_digit() {
            fraction_end += 1;
            fraction_digits += 1;
        }
        if digits > 0 || fraction_digits > 0 {
            end = fraction_end;
            digits += fraction_digits;
        }
    }
    if digits == 0 {
        return f64::NAN;
    }
    if end < bytes.len() && (bytes[end] == b'e' || bytes[end] == b'E') {
        let mut exp_end = end + 1;
        if exp_end < bytes.len() && (bytes[exp_end] == b'+' || bytes[exp_end] == b'-') {
            exp_end += 1;
        }
        let exp_start = exp_end;
        while exp_end < bytes.len() && bytes[exp_end].is_ascii_digit() {
            exp_end += 1;
        }
        if exp_end > exp_start {
            end = exp_end;
        }
    }
    let literal = &rest[..end];
    let literal = if literal.starts_with('.') {
        format!("0{literal}")
    } else {
        literal.to_string()
    };
    let literal = literal.replace(".e", ".0e").replace(".E", ".0E");
    let literal = if literal.ends_with('.') {
        format!("{literal}0")
    } else {
        literal
    };
    sign * literal.parse::<f64>().unwrap_or(f64::NAN)
}

// ---------------------------------------------------------------------------
// XML text decoding (propertyListXmlText.ts)
// ---------------------------------------------------------------------------

/// BOM-aware XML plist text with fatal byte validation.
pub fn decode_xml_plist_text(bytes: &[u8]) -> PlistResult<String> {
    let encoding = if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe {
        "utf-16le"
    } else if bytes.len() >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff {
        "utf-16be"
    } else {
        "utf-8"
    };
    let text = match encoding {
        "utf-8" => {
            let body = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
            String::from_utf8(body.to_vec())
                .map_err(|_| PlistError::type_error("The encoded data was not valid for encoding utf-8"))?
        }
        other => {
            let body = &bytes[2..];
            if !body.len().is_multiple_of(2) {
                return Err(PlistError::type_error(format!(
                    "The encoded data was not valid for encoding {other}"
                )));
            }
            #[allow(clippy::chunks_exact_to_as_chunks)]
            let units: Vec<u16> = body
                .chunks_exact(2)
                .map(|pair| {
                    if other == "utf-16le" {
                        u16::from_le_bytes([pair[0], pair[1]])
                    } else {
                        u16::from_be_bytes([pair[0], pair[1]])
                    }
                })
                .collect();
            String::from_utf16(&units)
                .map_err(|_| PlistError::type_error(format!("The encoded data was not valid for encoding {other}")))?
        }
    };
    let declaration = Regex::new(r#"^<\?xml\s[^?]*\bencoding\s*=\s*["']([^"']+)["']"#)
        .ok()
        .and_then(|re| re.captures(&text).map(|c| c[1].to_string()));
    if let Some(declaration) = declaration {
        let declared = declaration.to_lowercase();
        if !["utf-8", "utf-16", "utf-16le", "utf-16be"].contains(&declared.as_str()) {
            return Err(PlistError::type_error(format!(
                "Unsupported XML encoding declaration: {declaration}. Supported encodings are UTF-8 and BOM-marked UTF-16 in either byte order."
            )));
        }
        if declared != encoding && !(encoding != "utf-8" && declared == "utf-16") {
            return Err(PlistError::type_error("XML encoding declaration disagrees with its bytes"));
        }
    }
    Ok(text)
}

/// Expand XML character and predefined entity references (`decodeXmlText`).
pub fn decode_xml_text(text: &str) -> String {
    let re = Regex::new(r"(?i)&(?:#x([\da-f]+)|#(\d+)|([a-z]+));").expect("static regex");
    re.replace_all(text, |caps: &regex::Captures<'_>| {
        let entity = caps[0].to_string();
        let code_point = if let Some(hex) = caps.get(1) {
            u32::from_str_radix(hex.as_str(), 16).ok().or(Some(u32::MAX))
        } else if let Some(decimal) = caps.get(2) {
            decimal.as_str().parse::<u32>().ok().or(Some(u32::MAX))
        } else {
            None
        };
        if let Some(code_point) = code_point {
            return if code_point <= 0x10ffff {
                char::from_u32(code_point).map(|c| c.to_string()).unwrap_or(entity)
            } else {
                entity
            };
        }
        match caps.get(3).map(|m| m.as_str()) {
            Some("amp") => "&".to_string(),
            Some("apos") => "'".to_string(),
            Some("gt") => ">".to_string(),
            Some("lt") => "<".to_string(),
            Some("quot") => "\"".to_string(),
            _ => entity,
        }
    })
    .into_owned()
}

pub fn omitted_prototype_keys_limitation(count: usize) -> String {
    format!(
        "{count} dictionary {} keyed __proto__ {} omitted because REA results cannot represent that key.",
        if count == 1 { "entry" } else { "entries" },
        if count == 1 { "was" } else { "were" }
    )
}

// ---------------------------------------------------------------------------
// XML decoding
// ---------------------------------------------------------------------------

fn xml_children<'a, 'b>(node: roxmltree::Node<'a, 'b>) -> impl Iterator<Item = roxmltree::Node<'a, 'b>> {
    node.children().filter(|child| {
        !matches!(
            child.node_type(),
            roxmltree::NodeType::Text | roxmltree::NodeType::Comment
        )
    })
}

struct XmlDecoder {
    omitted: usize,
}

fn first_child_text(node: roxmltree::Node<'_, '_>) -> Option<String> {
    let child = node.first_child()?;
    match child.node_type() {
        roxmltree::NodeType::Text => Some(child.text().unwrap_or("").to_string()),
        roxmltree::NodeType::Comment => Some(child.text().unwrap_or("").to_string()),
        _ => None,
    }
}

fn node_is_empty(node: roxmltree::Node<'_, '_>) -> bool {
    node.first_child().is_none()
}

impl XmlDecoder {
    fn element(&mut self, node: roxmltree::Node<'_, '_>, depth: usize) -> PlistResult<PVal> {
        if depth > 4000 {
            return Err(PlistError::range_error("Maximum call stack size exceeded"));
        }
        if node.node_type() == roxmltree::NodeType::PI {
            let target = node.pi().map(|pi| pi.target).unwrap_or("");
            return Err(PlistError::type_error(format!("Invalid PLIST tag {target}")));
        }
        let name = node.tag_name().name();
        match name {
            "plist" => {
                let mut items = Vec::new();
                if node_is_empty(node) {
                    return Ok(PVal::Array(items));
                }
                for child in xml_children(node) {
                    items.push(self.element(child, depth + 1)?);
                }
                Ok(PVal::Array(items))
            }
            "dict" => {
                let mut dict: IndexMap<String, PVal> = IndexMap::new();
                if node_is_empty(node) {
                    return Ok(PVal::Dict(dict));
                }
                let mut key: Option<String> = None;
                let mut counter = 0usize;
                for child in xml_children(node) {
                    let is_key = child.node_type() == roxmltree::NodeType::Element
                        && child.tag_name().name() == "key";
                    if counter.is_multiple_of(2) {
                        if !is_key {
                            return Err(PlistError::type_error("Missing key while parsing <dict/>."));
                        }
                        let PVal::Str(text) = self.element(child, depth + 1)? else {
                            return Err(PlistError::type_error("Missing key while parsing <dict/>."));
                        };
                        key = Some(text);
                    } else {
                        if is_key {
                            return Err(PlistError::type_error(
                                "Unexpected <key> while parsing <dict/>. Keys and values must alternate.",
                            ));
                        }
                        let before = self.omitted;
                        let value = self.element(child, depth + 1)?;
                        let key_text = key.clone().unwrap_or_default();
                        if key_text == "__proto__" {
                            // The entry (and anything nested in it) is dropped, only the entry counts.
                            self.omitted = before + 1;
                        } else {
                            dict.insert(key_text, value);
                        }
                    }
                    counter += 1;
                }
                if counter % 2 == 1 {
                    let key_text = key.unwrap_or_default();
                    if key_text == "__proto__" {
                        self.omitted += 1;
                    } else {
                        dict.insert(key_text, PVal::Str(String::new()));
                    }
                }
                Ok(PVal::Dict(dict))
            }
            "array" => {
                let mut items = Vec::new();
                if node_is_empty(node) {
                    return Ok(PVal::Array(items));
                }
                for child in xml_children(node) {
                    let value = self.element(child, depth + 1)?;
                    if !matches!(value, PVal::Null) {
                        items.push(value);
                    }
                }
                Ok(PVal::Array(items))
            }
            "key" => {
                if node_is_empty(node) {
                    return Ok(PVal::Str(String::new()));
                }
                Ok(PVal::Str(first_child_text(node).unwrap_or_else(|| "null".to_string())))
            }
            "string" => {
                let mut result = String::new();
                for child in node.children() {
                    if child.node_type() == roxmltree::NodeType::Text {
                        result.push_str(child.text().unwrap_or(""));
                    }
                }
                Ok(PVal::Str(result))
            }
            "integer" => {
                if node_is_empty(node) {
                    return Err(PlistError::type_error("Cannot parse \"\" as integer."));
                }
                Ok(PVal::Num(js_parse_int(&first_child_text(node).unwrap_or_default())))
            }
            "real" => {
                if node_is_empty(node) {
                    return Err(PlistError::type_error("Cannot parse \"\" as real."));
                }
                let mut text = String::new();
                for child in node.children() {
                    if child.node_type() == roxmltree::NodeType::Text {
                        text.push_str(child.text().unwrap_or(""));
                    }
                }
                Ok(PVal::Num(js_parse_float(&text)))
            }
            "data" => {
                let mut text = String::new();
                for child in node.children() {
                    if child.node_type() == roxmltree::NodeType::Text {
                        text.extend(child.text().unwrap_or("").chars().filter(|c| !c.is_whitespace()));
                    }
                }
                Ok(PVal::Data(atob(&text)?))
            }
            "date" => {
                if node_is_empty(node) {
                    return Err(PlistError::type_error("Cannot parse \"\" as Date."));
                }
                Ok(PVal::Date(js_parse_date(&first_child_text(node).unwrap_or_default())))
            }
            "null" => Ok(PVal::Null),
            "true" => Ok(PVal::Bool(true)),
            "false" => Ok(PVal::Bool(false)),
            other => Err(PlistError::type_error(format!("Invalid PLIST tag {other}"))),
        }
    }
}

fn atob(text: &str) -> PlistResult<Vec<u8>> {
    let trimmed = text.trim_end_matches('=');
    if trimmed.len() % 4 == 1 || trimmed.chars().any(|c| !c.is_ascii_alphanumeric() && c != '+' && c != '/') {
        return Err(PlistError::type_error("The string to be decoded is not correctly encoded."));
    }
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| {
            // Non-canonical trailing bits are accepted by atob.
            base64::engine::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::GeneralPurposeConfig::new()
                    .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
                    .with_decode_allow_trailing_bits(true),
            )
            .decode(trimmed)
        })
        .map_err(|_| PlistError::type_error("The string to be decoded is not correctly encoded."))
}

/// Milliseconds since the epoch, NaN when the text is not a date.
pub fn js_parse_date(text: &str) -> f64 {
    let text = text.trim();
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(text) {
        return parsed.timestamp_millis() as f64;
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(parsed) = chrono::NaiveDateTime::parse_from_str(text, format) {
            return parsed.and_utc().timestamp_millis() as f64;
        }
    }
    if let Ok(parsed) = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        if let Some(datetime) = parsed.and_hms_opt(0, 0, 0) {
            return datetime.and_utc().timestamp_millis() as f64;
        }
    }
    f64::NAN
}

/// Decode an XML plist whose dictionaries may use the legal key `__proto__`.
/// Returns the value and the count of omitted `__proto__` entries.
pub fn parse_xml_property_list(text: &str) -> PlistResult<(PVal, usize)> {
    // OpenStep detection of the JavaScript decoder.
    let trimmed = text.trim_start();
    if (trimmed.starts_with('{') || trimmed.starts_with('('))
        && !trimmed.starts_with("<?xml")
        && !trimmed.starts_with("<!DOCTYPE")
        && !trimmed.starts_with("<plist")
    {
        return Err(PlistError::type_error("OpenStep property lists are not supported"));
    }
    let options = roxmltree::ParsingOptions {
        allow_dtd: true,
        nodes_limit: u32::MAX,
    };
    let document = roxmltree::Document::parse_with_options(text, options)
        .map_err(|error| {
            if !text.contains('<') || matches!(error, roxmltree::Error::NoRootNode) {
                PlistError::type_error("missing root element")
            } else {
                PlistError::type_error(format!("malformed document: {error}"))
            }
        })?;
    let root = document.root_element();
    if root.tag_name().name() != "plist" {
        return Err(PlistError::type_error("malformed document. First element should be <plist>"));
    }
    let mut decoder = XmlDecoder { omitted: 0 };
    let mut value = decoder.element(root, 0)?;
    if let PVal::Array(items) = &value {
        if items.len() == 1 {
            value = items[0].clone();
        }
    }
    Ok((value, decoder.omitted))
}

// ---------------------------------------------------------------------------
// Binary decoding (parse-binary.js)
// ---------------------------------------------------------------------------

struct BinaryView<'a> {
    data: &'a [u8],
}

impl<'a> BinaryView<'a> {
    fn u8(&self, offset: f64) -> PlistResult<u8> {
        self.slice(offset, 1).map(|s| s[0])
    }

    fn slice(&self, offset: f64, length: usize) -> PlistResult<&'a [u8]> {
        if offset.is_nan() || offset < 0.0 || offset.fract() != 0.0 {
            return Err(PlistError::range_error(OOB));
        }
        let start = offset as usize;
        match start.checked_add(length) {
            Some(end) if end <= self.data.len() => Ok(&self.data[start..end]),
            _ => Err(PlistError::range_error(OOB)),
        }
    }

    fn u16(&self, offset: f64) -> PlistResult<u16> {
        let s = self.slice(offset, 2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn u32(&self, offset: f64) -> PlistResult<u32> {
        let s = self.slice(offset, 4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn i32(&self, offset: f64) -> PlistResult<i32> {
        Ok(self.u32(offset)? as i32)
    }

    fn sized_int(&self, offset: f64, size: usize) -> PlistResult<f64> {
        match size {
            1 => Ok(f64::from(self.u8(offset)?)),
            2 => Ok(f64::from(self.u16(offset)?)),
            4 => Ok(f64::from(self.u32(offset)?)),
            8 => {
                let hi = self.u32(offset)?;
                let lo = self.u32(offset + 4.0)?;
                Ok(f64::from(hi) * 4_294_967_296.0 + f64::from(lo))
            }
            _ => Err(PlistError::type_error(format!("Unsupported int size: {size}"))),
        }
    }
}

const EPOCH_2001_MS: f64 = 978_307_200_000.0;

/// `parseBinary` of the pinned `plist` package.
pub fn parse_binary(data: &[u8]) -> PlistResult<PVal> {
    if data.len() < 8 || &data[..8] != b"bplist00" {
        return Err(PlistError::type_error("Invalid binary plist: bad magic"));
    }
    if data.len() < 32 {
        return Err(PlistError::range_error(OOB));
    }
    // Refuse expansion bombs, cycles and absurd nesting from the size of the FILE (linear in objects
    // and references, shared subtrees are costed once), before decoding anything.
    if data.len() >= 40 {
        estimate_binary_plist_expansion(data, PLIST_DECODE_BUDGET_BYTES, "the plist decode budget", Bounds::Decoder)
            .map_err(expansion_to_error)?;
    }
    parse_binary_unguarded(data)
}

/// The decoder proper. It has its own object budget, ancestor-cycle check and depth limit as a
/// second line of defence behind the preflight in [`parse_binary`].
fn parse_binary_unguarded(data: &[u8]) -> PlistResult<PVal> {
    let view = BinaryView { data };
    if data.len() < 8 || &data[..8] != b"bplist00" {
        return Err(PlistError::type_error("Invalid binary plist: bad magic"));
    }
    if data.len() < 32 {
        return Err(PlistError::range_error(OOB));
    }
    let trailer = (data.len() - 32) as f64;
    let offset_size = view.u8(trailer + 6.0)? as usize;
    let ref_size = view.u8(trailer + 7.0)? as usize;
    let num_objects = view.sized_int(trailer + 8.0, 8)?;
    let top_object = view.sized_int(trailer + 16.0, 8)?;
    let table_offset = view.sized_int(trailer + 24.0, 8)?;
    let mut offsets: Vec<f64> = Vec::new();
    let mut index = 0f64;
    while index < num_objects {
        offsets.push(view.sized_int(table_offset + index * offset_size as f64, offset_size)?);
        index += 1.0;
    }
    let ctx = BinaryContext {
        view: &view,
        offsets: &offsets,
        ref_size,
        active: std::cell::RefCell::new(HashSet::new()),
        decoded: std::cell::Cell::new(0),
    };
    ctx.object(top_object, 0)
}

/// Nesting limit of the native binary decoder (the JavaScript original recurses to its call-stack
/// limit; a property list deeper than this is not a real document).
const MAX_BINARY_DEPTH: usize = 512;
/// Objects the decoder materializes per document. A reference DAG expands into a tree, so a few
/// hundred bytes of shared references could otherwise request 2^50 objects.
const MAX_BINARY_OBJECTS: usize = 2_000_000;

struct BinaryContext<'a, 'b> {
    view: &'b BinaryView<'a>,
    offsets: &'b [f64],
    ref_size: usize,
    /// Object indexes on the current path: a reference to an ancestor is a cycle.
    active: std::cell::RefCell<HashSet<usize>>,
    decoded: std::cell::Cell<usize>,
}

impl BinaryContext<'_, '_> {
    fn object(&self, index: f64, depth: usize) -> PlistResult<PVal> {
        if depth > MAX_BINARY_DEPTH {
            return Err(PlistError::range_error("Maximum call stack size exceeded"));
        }
        let count = self.decoded.get() + 1;
        if count > MAX_BINARY_OBJECTS {
            return Err(PlistError::range_error("binary plist expands beyond the decoder object budget"));
        }
        self.decoded.set(count);
        if count.is_multiple_of(1024) && crate::cancel::cancelled() {
            return Err(PlistError::range_error("cancelled"));
        }
        let key = if index >= 0.0 && index.fract() == 0.0 { Some(index as usize) } else { None };
        if let Some(key) = key {
            if !self.active.borrow_mut().insert(key) {
                return Err(PlistError::type_error(
                    "binary plist object references form a cycle, which a property list cannot represent",
                ));
            }
        }
        let result = self.object_inner(index, depth);
        if let Some(key) = key {
            self.active.borrow_mut().remove(&key);
        }
        result
    }

    fn object_inner(&self, index: f64, depth: usize) -> PlistResult<PVal> {
        let view = self.view;
        let Some(offset) = (if index >= 0.0 && index.fract() == 0.0 {
            self.offsets.get(index as usize).copied()
        } else {
            None
        }) else {
            return Err(PlistError::type_error("Cannot read properties of undefined"));
        };
        let marker = view.u8(offset)?;
        let kind = marker >> 4;
        let mut size = f64::from(marker & 0x0f);
        let mut offset = offset + 1.0;
        if kind != 0 && kind != 8 && size == 15.0 {
            let ext_marker = view.u8(offset)?;
            offset += 1.0;
            let ext_size = 1usize << (ext_marker & 0x0f).min(31);
            size = view.sized_int(offset, ext_size)?;
            offset += ext_size as f64;
        }
        match kind {
            0xa => self.array(view, offset, size, depth),
            0xd => self.dictionary(view, offset, size, depth),
            _ => Self::scalar(view, kind, marker, offset, size),
        }
    }

    #[inline(never)]
    fn array(&self, view: &BinaryView<'_>, offset: f64, size: f64, depth: usize) -> PlistResult<PVal> {
        let mut items = Vec::new();
        let mut i = 0f64;
        while i < size {
            let reference = view.sized_int(offset + i * self.ref_size as f64, self.ref_size)?;
            items.push(self.object(reference, depth + 1)?);
            i += 1.0;
        }
        Ok(PVal::Array(items))
    }

    #[inline(never)]
    fn dictionary(&self, view: &BinaryView<'_>, offset: f64, size: f64, depth: usize) -> PlistResult<PVal> {
        let mut dict: IndexMap<String, PVal> = IndexMap::new();
        let mut i = 0f64;
        while i < size {
            let key_ref = view.sized_int(offset + i * self.ref_size as f64, self.ref_size)?;
            let value_ref = view.sized_int(offset + (size + i) * self.ref_size as f64, self.ref_size)?;
            let key = self.object(key_ref, depth + 1)?;
            let value = self.object(value_ref, depth + 1)?;
            let key = pval_key(&key);
            // `dict["__proto__"] = ...` sets a prototype in JavaScript, never an own entry.
            if key != "__proto__" {
                dict.insert(key, value);
            }
            i += 1.0;
        }
        Ok(PVal::Dict(dict))
    }

    /// Non-container objects: no recursion, so their locals never sit on the recursive path.
    #[inline(never)]
    fn scalar(view: &BinaryView<'_>, kind: u8, marker: u8, offset: f64, size: f64) -> PlistResult<PVal> {
        match kind {
            0x0 => match marker {
                0x00 => Ok(PVal::Null),
                0x08 => Ok(PVal::Bool(false)),
                0x09 => Ok(PVal::Bool(true)),
                other => Err(PlistError::type_error(format!("Unknown singleton: 0x{other:x}"))),
            },
            0x1 => {
                let byte_count = 1usize << (size as u32).min(31);
                if byte_count <= 4 {
                    return Ok(PVal::Num(view.sized_int(offset, byte_count)?));
                }
                let hi = view.i32(offset)?;
                let lo = view.u32(offset + 4.0)?;
                Ok(PVal::Num(f64::from(hi) * 4_294_967_296.0 + f64::from(lo)))
            }
            0x2 => {
                let byte_count = 1usize << (size as u32).min(31);
                match byte_count {
                    4 => Ok(PVal::Num(f64::from(f32::from_bits(view.u32(offset)?)))),
                    8 => {
                        let s = view.slice(offset, 8)?;
                        let mut word = [0u8; 8];
                        word.copy_from_slice(s);
                        Ok(PVal::Num(f64::from_be_bytes(word)))
                    }
                    other => Err(PlistError::type_error(format!("Unsupported real size: {other}"))),
                }
            }
            0x3 => {
                let s = view.slice(offset, 8)?;
                let mut word = [0u8; 8];
                word.copy_from_slice(s);
                let timestamp = f64::from_be_bytes(word);
                Ok(PVal::Date(timestamp * 1000.0 + EPOCH_2001_MS))
            }
            0x4 => Ok(PVal::Data(view.slice(offset, size as usize)?.to_vec())),
            0x5 => {
                let s = view.slice(offset, size as usize)?;
                Ok(PVal::Str(s.iter().map(|b| char::from(*b)).collect()))
            }
            0x6 => {
                let s = view.slice(offset, (size as usize).saturating_mul(2))?;
                #[allow(clippy::chunks_exact_to_as_chunks)]
                let units: Vec<u16> = s.chunks_exact(2).map(|p| u16::from_be_bytes([p[0], p[1]])).collect();
                Ok(PVal::Str(String::from_utf16_lossy(&units)))
            }
            0x8 => {
                let byte_count = size as usize + 1;
                let mut dict = IndexMap::new();
                dict.insert("UID".to_string(), PVal::Num(view.sized_int(offset, byte_count)?));
                Ok(PVal::Dict(dict))
            }
            other => Err(PlistError::type_error(format!("Unknown object type: 0x{other:x}"))),
        }
    }
}

fn pval_key(value: &PVal) -> String {
    match value {
        PVal::Str(text) => text.clone(),
        PVal::Num(n) => match js_number(*n) {
            Value::Number(number) => number.to_string(),
            _ => "null".to_string(),
        },
        PVal::Bool(b) => b.to_string(),
        PVal::Null => "null".to_string(),
        PVal::Array(_) => String::new(),
        _ => "[object Object]".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Projection (plistValue.ts)
// ---------------------------------------------------------------------------

const MAX_PLIST_DEPTH: usize = 128;

pub struct Projected {
    pub value: Value,
    pub unknown_real_count: usize,
}

fn iso8601(ms: f64) -> PlistResult<String> {
    if !ms.is_finite() {
        return Err(PlistError::range_error("Invalid time value"));
    }
    let seconds = (ms / 1000.0).floor();
    let millis = (ms - seconds * 1000.0).round() as u32;
    let datetime = chrono::DateTime::from_timestamp(seconds as i64, millis * 1_000_000)
        .ok_or_else(|| PlistError::range_error("Invalid time value"))?;
    Ok(datetime.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
}

pub fn project_plist_value(value: &PVal) -> PlistResult<Projected> {
    let mut unknown = 0usize;
    fn project(item: &PVal, depth: usize, unknown: &mut usize) -> PlistResult<Value> {
        if depth > MAX_PLIST_DEPTH {
            return Err(PlistError::range_error(format!(
                "Plist exceeds {MAX_PLIST_DEPTH} nesting levels"
            )));
        }
        Ok(match item {
            PVal::Null => Value::Null,
            PVal::Bool(b) => Value::Bool(*b),
            PVal::Num(n) => {
                if !n.is_finite() {
                    *unknown += 1;
                    json!({"$plist_type": "real", "value": null})
                } else {
                    js_number(*n)
                }
            }
            PVal::Str(s) => Value::String(s.clone()),
            PVal::Data(bytes) => json!({
                "$plist_type": "data",
                "base64": base64::engine::general_purpose::STANDARD.encode(bytes),
            }),
            PVal::Date(ms) => json!({"$plist_type": "date", "iso8601": iso8601(*ms)?}),
            PVal::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|entry| project(entry, depth + 1, unknown))
                    .collect::<PlistResult<Vec<_>>>()?,
            ),
            PVal::Dict(map) => {
                let mut out = Map::new();
                for (key, entry) in js_order(map) {
                    out.insert(key.clone(), project(entry, depth + 1, unknown)?);
                }
                Value::Object(out)
            }
        })
    }
    let projected = project(value, 0, &mut unknown)?;
    Ok(Projected {
        value: projected,
        unknown_real_count: unknown,
    })
}

/// Canonical array-index keys sort first, ascending, as in a JavaScript object.
fn is_array_index(key: &str) -> Option<u32> {
    if key.is_empty() || key.len() > 10 {
        return None;
    }
    if key.len() > 1 && key.starts_with('0') {
        return None;
    }
    if !key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u64 = key.parse().ok()?;
    if value < 4_294_967_295 {
        Some(value as u32)
    } else {
        None
    }
}

/// Entries in `Object.entries` order.
pub fn js_order<V>(map: &IndexMap<String, V>) -> Vec<(&String, &V)> {
    let mut indexed: Vec<(u32, &String, &V)> = Vec::new();
    let mut others: Vec<(&String, &V)> = Vec::new();
    for (key, value) in map {
        match is_array_index(key) {
            Some(index) => indexed.push((index, key, value)),
            None => others.push((key, value)),
        }
    }
    indexed.sort_by_key(|entry| entry.0);
    indexed
        .into_iter()
        .map(|(_, key, value)| (key, value))
        .chain(others)
        .collect()
}

/// `Object.entries` order for a JSON object whose keys are already in insertion order.
pub fn js_order_map(map: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut indexed: Vec<(u32, &String, &Value)> = Vec::new();
    let mut others: Vec<(&String, &Value)> = Vec::new();
    for (key, value) in map {
        match is_array_index(key) {
            Some(index) => indexed.push((index, key, value)),
            None => others.push((key, value)),
        }
    }
    indexed.sort_by_key(|entry| entry.0);
    indexed
        .into_iter()
        .map(|(_, key, value)| (key, value))
        .chain(others)
        .collect()
}

// ---------------------------------------------------------------------------
// Number literals (PlistNumberLiterals.ts, plistNumbers.ts)
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
pub struct PlistNumberLiterals {
    /// Rounded double (as ordered bits) to the exact decimal literals that produce it.
    pub integers: BTreeMap<u64, BTreeSet<String>>,
    pub reals: HashSet<u64>,
    pub unsafe_integer_literals: usize,
    pub incomplete: bool,
}

fn key_of(x: f64) -> u64 {
    // Normalize -0.
    if x == 0.0 {
        0
    } else {
        x.to_bits()
    }
}

struct Collector {
    out: PlistNumberLiterals,
    incomplete_metadata: bool,
}

impl Collector {
    fn new() -> Self {
        Self {
            out: PlistNumberLiterals::default(),
            incomplete_metadata: false,
        }
    }

    fn integer(&mut self, literal: &str) {
        let valid = {
            let body = literal.strip_prefix(['+', '-']).unwrap_or(literal);
            !body.is_empty() && body.chars().all(|c| c.is_ascii_digit())
        };
        if !valid {
            self.incomplete_metadata = true;
            return;
        }
        let Ok(exact) = literal.trim_start_matches('+').parse::<i128>() else {
            self.out.unsafe_integer_literals += 1;
            let rounded = literal.parse::<f64>().unwrap_or(f64::NAN);
            self.out
                .integers
                .entry(key_of(rounded))
                .or_default()
                .insert(literal.trim_start_matches('+').trim_start_matches('0').to_string());
            return;
        };
        if (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&exact) {
            return;
        }
        self.out.unsafe_integer_literals += 1;
        let rounded = exact as f64;
        self.out
            .integers
            .entry(key_of(rounded))
            .or_default()
            .insert(exact.to_string());
    }

    fn real(&mut self, value: f64) {
        self.out.reals.insert(key_of(value));
    }

    fn finish(mut self, incomplete: bool) -> PlistNumberLiterals {
        self.out.incomplete = incomplete || self.incomplete_metadata;
        self.out
    }
}

pub fn xml_plist_number_literals(xml: &str) -> PlistNumberLiterals {
    let token_re = Regex::new(r#"<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<(?:[^>"']|"[^"]*"|'[^']*')*>"#).expect("static regex");
    let tag_re = Regex::new(r"^<\s*(/?)\s*([\w:-]+)").expect("static regex");
    let self_closing = Regex::new(r"/\s*>$").expect("static regex");
    let opaque = ["string", "key", "data", "date"];
    let mut collector = Collector::new();
    let mut elements: Vec<String> = Vec::new();
    struct Number {
        kind: String,
        text: String,
        depth: usize,
        plain_text: bool,
    }
    let mut number: Option<Number> = None;
    let mut cursor = 0usize;
    for token_match in token_re.find_iter(xml) {
        let index = token_match.start();
        if let Some(number) = number.as_mut() {
            number.text.push_str(&xml[cursor..index]);
        }
        let token = token_match.as_str();
        cursor = index + token.len();
        if token.starts_with("<!--") || token.starts_with("<![CDATA[") {
            if let Some(number) = number.as_mut() {
                number.plain_text = false;
                collector.incomplete_metadata = true;
            }
            continue;
        }
        let Some(tag) = tag_re.captures(token) else {
            if let Some(number) = number.as_mut() {
                number.plain_text = false;
                collector.incomplete_metadata = true;
            }
            continue;
        };
        let closing = &tag[1] == "/";
        let name = tag[2].to_string();
        if closing {
            let finished = match number.as_ref() {
                Some(n) => n.kind == name && n.depth == elements.len(),
                None => false,
            };
            if finished {
                if let Some(n) = number.take() {
                    if n.plain_text {
                        let text = decode_xml_text(&n.text).trim().to_string();
                        if n.kind == "integer" {
                            collector.integer(&text);
                        } else {
                            collector.real(js_parse_float(&text));
                        }
                    }
                }
            }
            elements.pop();
            continue;
        }
        if let Some(number) = number.as_mut() {
            number.plain_text = false;
            collector.incomplete_metadata = true;
        }
        if self_closing.is_match(token) {
            continue;
        }
        if number.is_none()
            && (name == "integer" || name == "real")
            && !elements.iter().any(|parent| opaque.contains(&parent.as_str()))
        {
            number = Some(Number {
                kind: name.clone(),
                text: String::new(),
                depth: elements.len() + 1,
                plain_text: true,
            });
        }
        elements.push(name);
    }
    collector.finish(false)
}

pub fn binary_plist_number_literals(bytes: &[u8]) -> PlistNumberLiterals {
    let mut collector = Collector::new();
    if bytes.len() < 40 || &bytes[..8] != b"bplist00" {
        return collector.finish(true);
    }
    let trailer = bytes.len() - 32;
    let offset_width = bytes[trailer + 6] as usize;
    if ![1, 2, 4, 8].contains(&offset_width) {
        return collector.finish(true);
    }
    let be64 = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
    let count_raw = be64(trailer + 8);
    let table_raw = be64(trailer + 24);
    let safe = 9_007_199_254_740_991u64;
    if count_raw == 0 || count_raw > safe || table_raw > safe {
        return collector.finish(true);
    }
    if table_raw < 8 || table_raw >= trailer as u64 {
        return collector.finish(true);
    }
    let offset_table = table_raw as usize;
    let capacity = (trailer - offset_table) / offset_width;
    if count_raw > capacity as u64 {
        return collector.finish(true);
    }
    let count = count_raw as usize;
    let unsigned = |offset: usize| -> Option<usize> {
        if offset < offset_table || offset + offset_width > trailer {
            return None;
        }
        let slice = &bytes[offset..offset + offset_width];
        let mut value = 0u64;
        for byte in slice {
            value = (value << 8) | u64::from(*byte);
        }
        if value > safe {
            None
        } else {
            Some(value as usize)
        }
    };
    for index in 0..count {
        let Some(offset) = unsigned(offset_table + index * offset_width) else {
            return collector.finish(true);
        };
        if offset < 8 || offset >= offset_table {
            return collector.finish(true);
        }
        let marker = bytes[offset];
        let kind = marker >> 4;
        if kind != 1 && kind != 2 {
            continue;
        }
        let width = 1usize << (marker & 0xf).min(20);
        if offset + 1 + width > offset_table {
            return collector.finish(true);
        }
        if kind == 1 && width == 8 {
            let value = i64::from_be_bytes(bytes[offset + 1..offset + 9].try_into().expect("8 bytes"));
            collector.integer(&value.to_string());
        } else if kind == 1 && width > 4 {
            return collector.finish(true);
        } else if kind == 2 && width == 4 {
            let value = f32::from_be_bytes(bytes[offset + 1..offset + 5].try_into().expect("4 bytes"));
            collector.real(f64::from(value));
        } else if kind == 2 && width == 8 {
            let value = f64::from_be_bytes(bytes[offset + 1..offset + 9].try_into().expect("8 bytes"));
            collector.real(value);
        } else if kind == 2 {
            return collector.finish(true);
        }
    }
    collector.finish(false)
}

/// `createPlistNumberProjection`: preserve unambiguous exact integers; disclose the rest.
pub struct PlistNumberProjection<'a> {
    literals: &'a PlistNumberLiterals,
    exact_integer_count: usize,
    ambiguous_number_count: usize,
}

impl<'a> PlistNumberProjection<'a> {
    pub fn new(literals: &'a PlistNumberLiterals) -> Self {
        Self {
            literals,
            exact_integer_count: 0,
            ambiguous_number_count: 0,
        }
    }

    fn map_number(&mut self, value: &Value) -> Value {
        let Some(item) = value_f64(value) else {
            return value.clone();
        };
        if is_safe_integer(item) || item.fract() != 0.0 || !item.is_finite() {
            return value.clone();
        }
        if self.literals.incomplete {
            self.ambiguous_number_count += 1;
            return value.clone();
        }
        let key = key_of(item);
        let Some(decimals) = self.literals.integers.get(&key) else {
            if !self.literals.reals.contains(&key) {
                self.ambiguous_number_count += 1;
            }
            return value.clone();
        };
        if decimals.len() != 1 || self.literals.reals.contains(&key) {
            self.ambiguous_number_count += 1;
            return value.clone();
        }
        self.exact_integer_count += 1;
        json!({"$plist_type": "integer", "decimal": decimals.iter().next().cloned().unwrap_or_default()})
    }

    pub fn project(&mut self, item: &Value) -> Value {
        match item {
            Value::Number(_) => self.map_number(item),
            Value::Array(items) => Value::Array(items.iter().map(|child| self.project(child)).collect()),
            Value::Object(map) => {
                let mut keys = map.keys();
                let first = keys.next();
                let single = first.is_some() && keys.next().is_none();
                if single {
                    let key = first.expect("one key");
                    if key == "UID" || key == "CF$UID" {
                        if let Some(marker) = map.get(key).and_then(value_f64) {
                            if !is_safe_integer(marker) {
                                let k = key_of(marker);
                                if self.literals.integers.contains_key(&k) || !self.literals.reals.contains(&k) {
                                    self.ambiguous_number_count += 1;
                                }
                            }
                            return item.clone();
                        }
                    }
                }
                let mut out = Map::new();
                for (key, child) in map {
                    out.insert(key.clone(), self.project(child));
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }

    pub fn exact_integer_count(&self) -> usize {
        self.exact_integer_count
    }

    pub fn ambiguous_number_count(&self) -> usize {
        self.ambiguous_number_count
    }

    pub fn limitations(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.literals.incomplete {
            out.push("Original archive number metadata could not be completely observed; decoded numbers may lose integer precision and exact integer/real association is unavailable.".to_string());
        }
        if self.literals.unsafe_integer_literals != 0 {
            out.push(format!(
                "{} observed integer literal(s) in the original archive exceed the exact range of a JSON number. Decoded numbers may lose integer precision unless represented as {{ \"$plist_type\": \"integer\", \"decimal\": \"<exact digits>\" }}; the original archive bytes retain those literals.",
                self.literals.unsafe_integer_literals
            ));
        }
        if self.exact_integer_count != 0 {
            out.push(format!(
                "{} unambiguous integer value(s) are reported with exact decimal text as {{ \"$plist_type\": \"integer\", \"decimal\": \"<exact digits>\" }}.",
                self.exact_integer_count
            ));
        }
        if self.ambiguous_number_count != 0 {
            out.push(format!(
                "{} number(s) beyond the exact integer range remain as decoded because their source integer/real type or reference marker cannot be associated unambiguously; integer precision loss remains possible.",
                self.ambiguous_number_count
            ));
        }
        out
    }
}

/// Largest decoded representation the single-document tools accept.
pub const PLIST_DECODE_BUDGET_BYTES: f64 = 128.0 * 1024.0 * 1024.0;

fn expansion_to_error(failure: ExpansionFailure) -> PlistError {
    match failure {
        ExpansionFailure::Budget { kind: ExpansionKind::Cycle, .. } => PlistError::type_error(
            "binary plist object references form a cycle, which a property list cannot represent",
        ),
        ExpansionFailure::Budget { message, .. } => PlistError::range_error(message),
        ExpansionFailure::Malformed(message) => PlistError::type_error(message),
    }
}

/// `parse_binary` after the expansion preflight (depth, cycles, reference fan-out, byte budget).
pub fn parse_binary_checked(data: &[u8]) -> PlistResult<PVal> {
    if data.len() >= 8 && &data[..8] == b"bplist00" {
        estimate_binary_plist_expansion(data, PLIST_DECODE_BUDGET_BYTES, "the plist decode budget", Bounds::Decoder)
            .map_err(expansion_to_error)?;
    }
    parse_binary(data)
}

/// `parse_xml_property_list` after the nesting and size preflight.
pub fn parse_xml_checked(text: &str) -> PlistResult<(PVal, usize)> {
    match estimate_xml_plist_expansion(text, PLIST_DECODE_BUDGET_BYTES) {
        Ok(estimate) if estimate <= PLIST_DECODE_BUDGET_BYTES => {}
        Ok(_) => return Err(PlistError::range_error("XML plist exceeds the plist decode budget")),
        Err(failure) => return Err(expansion_to_error(failure)),
    }
    parse_xml_property_list(text)
}

// ---------------------------------------------------------------------------
// Decode budget and binary expansion preflight (InterfaceBuilderDecodeBudget.ts)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpansionKind {
    Cycle,
    Depth,
    Expansion,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExpansionFailure {
    /// A budget, depth or cycle failure (`fail(kind, message)` in the original).
    Budget { kind: ExpansionKind, message: String },
    /// Structural problem reported as a TypeError.
    Malformed(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Bounds {
    Strict,
    Decoder,
}

fn malformed(message: &str) -> ExpansionFailure {
    ExpansionFailure::Malformed(message.to_string())
}

/// Count every expanded binary-plist reference before decoding.
pub fn estimate_binary_plist_expansion(
    bytes: &[u8],
    max_bytes: f64,
    budget: &str,
    bounds: Bounds,
) -> Result<f64, ExpansionFailure> {
    if bytes.len() < 40 {
        return Err(malformed("binary plist trailer is truncated"));
    }
    let trailer = bytes.len() - 32;
    let offset_size = bytes[trailer + 6] as usize;
    let reference_size = bytes[trailer + 7] as usize;
    if ![1, 2, 4, 8].contains(&offset_size) || ![1, 2, 4, 8].contains(&reference_size) {
        return Err(malformed("binary plist trailer integer sizes are invalid"));
    }
    let read_integer = |offset: i64, size: usize| -> i64 {
        if offset < 0 || size < 1 || (offset as usize).saturating_add(size) > bytes.len() {
            return -1;
        }
        let mut value = 0f64;
        for index in 0..size {
            value = value * 256.0 + f64::from(bytes[offset as usize + index]);
        }
        if is_safe_integer(value) {
            value as i64
        } else {
            -1
        }
    };
    let object_count = read_integer((trailer + 8) as i64, 8);
    let top_object = read_integer((trailer + 16) as i64, 8);
    let offset_table = read_integer((trailer + 24) as i64, 8);
    let table_end = if bounds == Bounds::Strict { trailer as i64 } else { bytes.len() as i64 };
    let objects_end = if bounds == Bounds::Strict { offset_table } else { bytes.len() as i64 };
    if object_count < 1
        || top_object < 0
        || top_object >= object_count
        || offset_table < 8
        || offset_table + object_count * offset_size as i64 > table_end
    {
        return Err(malformed("binary plist trailer or object table is invalid"));
    }
    let mut estimate = bytes.len() as f64 * 2.0 + object_count as f64 * 16.0;
    let fail = |kind: ExpansionKind, message: String| ExpansionFailure::Budget { kind, message };
    if estimate > max_bytes {
        return Err(fail(
            ExpansionKind::Expansion,
            format!("binary plist object table exceeds {budget}"),
        ));
    }
    struct Entry {
        object: i64,
        depth: usize,
        exit: bool,
    }
    /// What a completely visited subtree contributes, so that a shared object is costed once.
    #[derive(Clone, Copy)]
    struct Settled {
        /// Estimate added by one full expansion of the subtree (saturated at the budget).
        cost: f64,
        /// Levels below the object (0 for a scalar).
        height: usize,
    }
    let mut settled: std::collections::HashMap<i64, Settled> = std::collections::HashMap::new();
    let mut active: HashSet<i64> = HashSet::new();
    let mut children_of: std::collections::HashMap<i64, Vec<i64>> = std::collections::HashMap::new();
    let mut scalar_cost: std::collections::HashMap<i64, f64> = std::collections::HashMap::new();
    let mut pending: Vec<Entry> = vec![Entry {
        object: top_object,
        depth: 0,
        exit: false,
    }];
    let mut pending_object_count: f64 = 1.0;
    while let Some(entry) = pending.pop() {
        if entry.exit {
            active.remove(&entry.object);
            // Every child has been settled by now: the subtree's cost and height follow from them.
            let children = children_of.remove(&entry.object).unwrap_or_default();
            let mut cost = 96.0f64;
            let mut height = 0usize;
            for child in &children {
                if let Some(child) = settled.get(child) {
                    cost = (cost + child.cost).min(max_bytes + 1.0);
                    height = height.max(child.height + 1);
                }
            }
            settled.insert(entry.object, Settled { cost, height });
            continue;
        }
        pending_object_count -= 1.0;
        if entry.depth > 128 {
            return Err(fail(ExpansionKind::Depth, format!("binary plist nesting exceeds {budget}")));
        }
        if active.contains(&entry.object) {
            return Err(fail(
                ExpansionKind::Cycle,
                format!("binary plist reference cycle exceeds {budget}"),
            ));
        }
        if let Some(known) = settled.get(&entry.object).copied() {
            // Already expanded once without error: charge its cost again without walking it.
            if entry.depth + known.height > 128 {
                return Err(fail(ExpansionKind::Depth, format!("binary plist nesting exceeds {budget}")));
            }
            estimate += known.cost;
            if estimate > max_bytes {
                return Err(fail(
                    ExpansionKind::Expansion,
                    format!("binary plist reference expansion exceeds {budget}"),
                ));
            }
            continue;
        }
        estimate += 96.0;
        if estimate > max_bytes {
            return Err(fail(
                ExpansionKind::Expansion,
                format!("binary plist reference expansion exceeds {budget}"),
            ));
        }
        let offset = read_integer(offset_table + entry.object * offset_size as i64, offset_size);
        if offset < 8 || offset >= objects_end {
            return Err(malformed("binary plist object offset is invalid"));
        }
        let marker = bytes[offset as usize];
        let kind = marker >> 4;
        let mut size = i64::from(marker & 0x0f);
        let mut cursor = offset + 1;
        if size == 0x0f && kind != 0 && kind != 8 {
            let ext_marker = bytes.get(cursor as usize).copied().unwrap_or(0);
            if ext_marker >> 4 != 1 || (ext_marker & 0x0f) > 3 {
                return Err(malformed("binary plist extended object size is invalid"));
            }
            cursor += 1;
            let integer_size = 1usize << (ext_marker & 0x0f);
            size = read_integer(cursor, integer_size);
            cursor += integer_size as i64;
            if size < 0 || cursor > objects_end {
                return Err(malformed("binary plist extended object size is invalid"));
            }
        }
        if kind == 4 || kind == 5 || kind == 6 {
            let byte_length = if kind == 6 { size * 2 } else { size };
            if cursor + byte_length > objects_end {
                return Err(malformed("binary plist scalar object is truncated"));
            }
            let extra = if kind == 4 {
                size as f64 + 4.0 * (size as f64 / 3.0).ceil()
            } else {
                byte_length as f64 * 2.0
            };
            estimate += extra;
            if estimate > max_bytes {
                return Err(fail(
                    ExpansionKind::Expansion,
                    format!("binary plist scalar expansion exceeds {budget}"),
                ));
            }
            scalar_cost.insert(entry.object, extra);
            settled.insert(entry.object, Settled { cost: (96.0 + extra).min(max_bytes + 1.0), height: 0 });
            continue;
        }
        if kind != 10 && kind != 13 {
            settled.insert(entry.object, Settled { cost: 96.0, height: 0 });
            continue;
        }
        let child_count = if kind == 13 { size * 2 } else { size };
        let refs_end = cursor + child_count * reference_size as i64;
        if refs_end > objects_end {
            return Err(malformed("binary plist reference table is truncated"));
        }
        let available_nodes = ((max_bytes - estimate) / 96.0).floor();
        if child_count as f64 > available_nodes - pending_object_count {
            return Err(fail(
                ExpansionKind::Expansion,
                format!("binary plist reference expansion exceeds {budget}"),
            ));
        }
        active.insert(entry.object);
        pending.push(Entry {
            object: entry.object,
            depth: entry.depth,
            exit: true,
        });
        let mut references: Vec<i64> = Vec::with_capacity(child_count as usize);
        let mut index = child_count - 1;
        while index >= 0 {
            let reference = read_integer(cursor + index * reference_size as i64, reference_size);
            if reference < 0 || reference >= object_count {
                return Err(malformed("binary plist reference is invalid"));
            }
            references.push(reference);
            pending.push(Entry {
                object: reference,
                depth: entry.depth + 1,
                exit: false,
            });
            index -= 1;
        }
        children_of.insert(entry.object, references);
        pending_object_count += child_count as f64;
    }
    let _ = scalar_cost;
    Ok(estimate)
}

/// Preflight of the XML plist representation (`estimateXmlPlistExpansion`).
pub fn estimate_xml_plist_expansion(xml: &str, max_bytes: f64) -> Result<f64, ExpansionFailure> {
    let budget_error = |message: &str| ExpansionFailure::Budget {
        kind: ExpansionKind::Expansion,
        message: message.to_string(),
    };
    let doctype_internal = Regex::new(r"(?i)<!DOCTYPE\b[^>]*\[").expect("static regex");
    if doctype_internal.is_match(xml) {
        return Err(budget_error(
            "XML plist internal entity expansion exceeds the aggregate Interface Builder decode budget",
        ));
    }
    let element_pattern = Regex::new(r"(?i)<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<!DOCTYPE[^>]*>|<\?[\s\S]*?\?>|</?[A-Za-z][^>]*>").expect("static regex");
    let decoded_source_bytes = xml.encode_utf16().count() as f64 * 2.0;
    let mut element_count = 0f64;
    let mut xml_depth = 0i64;
    for token in element_pattern.find_iter(xml) {
        let token = token.as_str();
        if token.starts_with("<!--")
            || token.starts_with("<![CDATA[")
            || token.to_ascii_uppercase().starts_with("<!DOCTYPE")
            || token.starts_with("<?")
        {
            continue;
        }
        element_count += 1.0;
        if token.starts_with("</") {
            xml_depth -= 1;
        } else if !token.ends_with("/>") {
            xml_depth += 1;
            if xml_depth > 128 {
                return Err(budget_error(
                    "XML plist nesting exceeds the aggregate Interface Builder decode budget",
                ));
            }
        }
        if decoded_source_bytes * 2.0 + element_count * 128.0 > max_bytes {
            return Ok(max_bytes + 1.0);
        }
    }
    Ok(decoded_source_bytes * 2.0 + element_count * 128.0)
}

/// Shared byte budget for decoder records and projected archive data.
#[derive(Clone, Debug)]
pub struct DecodeBudget {
    initial: f64,
    remaining: f64,
}

impl DecodeBudget {
    pub fn new(max_bytes: f64) -> Self {
        Self {
            initial: max_bytes,
            remaining: max_bytes,
        }
    }

    pub fn remaining_bytes(&self) -> f64 {
        self.remaining
    }

    pub fn used_bytes(&self) -> f64 {
        self.initial - self.remaining
    }

    pub fn reserve(&mut self, bytes: f64, message: &str) -> Result<(), BudgetExceeded> {
        if !bytes.is_finite() || bytes < 0.0 || bytes > self.remaining {
            return Err(BudgetExceeded {
                reason: "aggregate_decode_budget_exhausted",
                message: message.to_string(),
            });
        }
        self.remaining -= bytes;
        Ok(())
    }

    pub fn try_reserve(&mut self, bytes: f64) -> bool {
        if !bytes.is_finite() || bytes < 0.0 || bytes > self.remaining {
            return false;
        }
        self.remaining -= bytes;
        true
    }

    pub fn reserve_json_string_occurrence(&mut self, value: &str) -> Result<(), BudgetExceeded> {
        self.reserve(
            value.encode_utf16().count() as f64 * 6.0 + 2.0,
            "projected JSON strings exceed the aggregate Interface Builder decode budget",
        )
    }

    pub fn reserve_base64_json_string_occurrence(&mut self, value: &str) -> Result<(), BudgetExceeded> {
        self.reserve(
            value.encode_utf16().count() as f64 + 2.0,
            "projected NIB base64 values exceed the aggregate Interface Builder decode budget",
        )
    }

    pub fn reserve_json_property_name_occurrence(&mut self, value: &str) -> Result<(), BudgetExceeded> {
        self.reserve(
            value.encode_utf16().count() as f64 * 6.0 + 3.0,
            "projected JSON property names exceed the aggregate Interface Builder decode budget",
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BudgetExceeded {
    pub reason: &'static str,
    pub message: String,
}

/// `estimatePropertyListDecodeBytes`.
pub fn estimate_property_list_decode_bytes(
    bytes: &[u8],
    max_bytes: f64,
    xml_text: Option<&str>,
) -> Result<f64, ExpansionFailure> {
    let estimate = if bytes.len() >= 8 && &bytes[..8] == b"bplist00" {
        estimate_binary_plist_expansion(
            bytes,
            max_bytes,
            "the aggregate Interface Builder decode budget",
            Bounds::Strict,
        )?
    } else {
        let owned;
        let xml = match xml_text {
            Some(text) => text,
            None => {
                owned = decode_xml_plist_text(bytes).map_err(|e| ExpansionFailure::Malformed(e.message))?;
                &owned
            }
        };
        estimate_xml_plist_expansion(xml, max_bytes)?
    };
    if estimate > max_bytes {
        return Err(ExpansionFailure::Budget {
            kind: ExpansionKind::Expansion,
            message: "plist representation exceeds the aggregate Interface Builder decode budget".to_string(),
        });
    }
    Ok(estimate)
}

#[cfg(test)]
mod bplist_bomb_tests {
    use super::*;

    /// Assemble a binary plist from raw object encodings (offset size 2, reference size 1).
    fn bplist(objects: &[Vec<u8>], top: u8) -> Vec<u8> {
        bplist_with_ref_size(objects, top, 1)
    }

    fn bplist_with_ref_size(objects: &[Vec<u8>], top: u8, ref_size: u8) -> Vec<u8> {
        let mut out = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for object in objects {
            offsets.push(out.len() as u16);
            out.extend_from_slice(object);
        }
        let table_offset = out.len() as u64;
        for offset in &offsets {
            out.extend_from_slice(&offset.to_be_bytes());
        }
        out.extend_from_slice(&[0u8; 6]);
        out.push(2); // offset size
        out.push(ref_size);
        out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        out.extend_from_slice(&u64::from(top).to_be_bytes());
        out.extend_from_slice(&table_offset.to_be_bytes());
        out
    }

    fn within_five_seconds<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver.recv_timeout(std::time::Duration::from_secs(5)).expect("the decoder did not terminate")
    }

    /// 50 nested arrays whose two elements reference the next level: 2^50 expanded objects from ~250 bytes.
    fn exponential() -> Vec<u8> {
        let mut objects: Vec<Vec<u8>> = (0..50u8).map(|level| vec![0xa2, level + 1, level + 1]).collect();
        objects.push(vec![0x10, 0x00]);
        bplist(&objects, 0)
    }

    /// `[ref 0, ref 0]` as the only object: an array that contains itself.
    fn self_referencing() -> Vec<u8> {
        bplist(&[vec![0xa2, 0x00, 0x00]], 0)
    }

    #[test]
    fn two_to_the_fifty_expansion_is_refused_by_the_checked_and_the_raw_decoder() {
        let data = exponential();
        let for_raw = data.clone();
        // The decoder's own object budget (second line of defence) ...
        let raw = within_five_seconds(move || parse_binary_unguarded(&for_raw));
        assert!(raw.unwrap_err().message.contains("object budget"), "raw decoder must stop at its object budget");
        // ... and the public entry points, which refuse from the size of the file in milliseconds.
        let for_public = data.clone();
        for decode in [parse_binary as fn(&[u8]) -> PlistResult<PVal>, parse_binary_checked] {
            let started = std::time::Instant::now();
            let refused = decode(&for_public);
            let elapsed = started.elapsed();
            println!("2^50 bplist ({} bytes) refused in {elapsed:?}", for_public.len());
            assert!(refused.unwrap_err().message.contains("expansion"));
            assert!(elapsed < std::time::Duration::from_millis(250), "refusal took {elapsed:?}");
        }
        let _ = data;
    }

    #[test]
    fn a_self_referencing_array_is_refused_by_the_checked_and_the_raw_decoder() {
        let data = self_referencing();
        let for_raw = data.clone();
        let raw = within_five_seconds(move || parse_binary_unguarded(&for_raw));
        assert!(raw.unwrap_err().message.contains("cycle"));
        assert!(parse_binary(&data).unwrap_err().message.contains("cycle"));
        let checked = within_five_seconds(move || parse_binary_checked(&data));
        assert!(checked.unwrap_err().message.contains("cycle"));
    }

    #[test]
    fn a_cancelled_request_stops_the_decoder_long_before_its_object_budget() {
        let token = crate::cancel::CancelToken::new();
        token.cancel();
        let data = exponential();
        let started = std::time::Instant::now();
        let result = crate::cancel::scope(token, || parse_binary_unguarded(&data));
        assert_eq!(result.unwrap_err().message, "cancelled");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    /// top = [A, chain[0]]; chain[i] = [chain[i + 1]]; the last chain element = [A]; A = [leaf].
    /// A is first reached shallow, then again `chain_length + 2` levels down.
    fn shared_subtree_reached_twice(chain_length: usize) -> Vec<u8> {
        let mut objects: Vec<Vec<u8>> = vec![vec![0xa2, 1, 4], vec![0xa1, 2], vec![0x10, 0x00], vec![]];
        objects.remove(3);
        // indexes: 0 top, 1 A, 2 leaf, 3.. chain
        objects[0] = vec![0xa2, 1, 3];
        for i in 0..chain_length {
            let target = if i + 1 == chain_length { 1 } else { 3 + i as u8 + 1 };
            objects.push(vec![0xa1, target]);
        }
        bplist(&objects, 0)
    }

    #[test]
    fn a_shared_subtree_is_charged_at_the_depth_of_every_place_it_is_reached() {
        // A sits at depth 1 and at depth chain_length + 1; its leaf one level lower. The limit is 128.
        assert!(parse_binary(&shared_subtree_reached_twice(126)).is_ok());
        let error = parse_binary(&shared_subtree_reached_twice(127)).unwrap_err();
        assert!(error.message.contains("nesting"), "{}", error.message);
    }

    #[test]
    fn a_legitimate_shared_dag_still_decodes() {
        // 10 levels, two references each: 2^10 expanded leaves from 11 objects.
        let mut objects: Vec<Vec<u8>> = (0..10u8).map(|level| vec![0xa2, level + 1, level + 1]).collect();
        objects.push(vec![0x10, 0x07]);
        match parse_binary(&bplist(&objects, 0)).unwrap() {
            PVal::Array(items) => assert_eq!(items.len(), 2),
            other => panic!("expected an array, got {other:?}"),
        }
    }

    #[test]
    fn a_reference_to_an_ancestor_further_up_is_a_cycle() {
        // 0 -> 1 -> 2 -> 0
        let objects = [vec![0xa1, 1], vec![0xa1, 2], vec![0xa1, 0]];
        let data = bplist(&objects, 0);
        let for_guarded = data.clone();
        assert!(within_five_seconds(move || parse_binary_unguarded(&data)).unwrap_err().message.contains("cycle"));
        assert!(parse_binary(&for_guarded).unwrap_err().message.contains("cycle"));
    }

    #[test]
    fn nesting_beyond_the_depth_limits_is_refused_without_overflowing_the_stack() {
        // 700 nested one-element arrays need 2-byte references.
        let mut objects: Vec<Vec<u8>> = Vec::new();
        for level in 0..700u16 {
            let mut object = vec![0xa1];
            object.extend_from_slice(&(level + 1).to_be_bytes());
            objects.push(object);
        }
        objects.push(vec![0x10, 0x00]);
        let data = bplist_with_ref_size(&objects, 0, 2);
        let for_raw = data.clone();
        // The raw decoder stops at its own depth limit (512)...
        let raw = within_five_seconds(move || parse_binary_unguarded(&for_raw));
        assert!(raw.unwrap_err().message.contains("call stack"));
        assert!(parse_binary(&data).unwrap_err().message.contains("nesting"));
        // ...and the preflight (128) refuses it before decoding.
        assert!(within_five_seconds(move || parse_binary_checked(&data)).is_err());
    }
}
