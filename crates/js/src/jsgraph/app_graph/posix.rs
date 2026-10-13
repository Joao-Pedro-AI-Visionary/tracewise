//! Node `path.posix` (`join`, `dirname`, `normalize`, `extname`) and the URL-text helpers REA's
//! artifact path resolution shares (`artifactPathSyntax.ts`, `artifactIdentity.ts`).

use unicode_normalization::UnicodeNormalization;

fn normalize_string(path: &str, allow_above_root: bool) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.last().is_some_and(|last| *last != "..") {
                    segments.pop();
                } else if allow_above_root {
                    segments.push("..");
                }
            }
            other => segments.push(other),
        }
    }
    segments.join("/")
}

/// `path.posix.normalize`.
pub fn normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let is_absolute = path.starts_with('/');
    let trailing_separator = path.ends_with('/');
    let mut normalized = normalize_string(path, !is_absolute);
    if normalized.is_empty() {
        if is_absolute {
            return "/".into();
        }
        return if trailing_separator { "./".into() } else { ".".into() };
    }
    if trailing_separator {
        normalized.push('/');
    }
    if is_absolute {
        format!("/{normalized}")
    } else {
        normalized
    }
}

/// `path.posix.join`.
pub fn join(parts: &[&str]) -> String {
    let joined: Vec<&str> = parts.iter().copied().filter(|part| !part.is_empty()).collect();
    if joined.is_empty() {
        return ".".into();
    }
    normalize(&joined.join("/"))
}

/// `path.posix.dirname`.
pub fn dirname(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let bytes = path.as_bytes();
    let has_root = bytes[0] == b'/';
    let mut end: Option<usize> = None;
    let mut matched_slash = true;
    let mut i = bytes.len();
    while i > 1 {
        i -= 1;
        if bytes[i] == b'/' {
            if !matched_slash {
                end = Some(i);
                break;
            }
        } else {
            matched_slash = false;
        }
    }
    match end {
        None => {
            if has_root {
                "/".into()
            } else {
                ".".into()
            }
        }
        Some(1) if has_root => "//".into(),
        Some(end) => path[..end].to_string(),
    }
}

/// `path.posix.extname`.
pub fn extname(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut start_dot: isize = -1;
    let mut start_part: isize = 0;
    let mut end: isize = -1;
    let mut matched_slash = true;
    let mut pre_dot_state: i32 = 0;
    let mut i = bytes.len() as isize - 1;
    while i >= 0 {
        let code = bytes[i as usize];
        if code == b'/' {
            if !matched_slash {
                start_part = i + 1;
                break;
            }
            i -= 1;
            continue;
        }
        if end == -1 {
            matched_slash = false;
            end = i + 1;
        }
        if code == b'.' {
            if start_dot == -1 {
                start_dot = i;
            } else if pre_dot_state != 1 {
                pre_dot_state = 1;
            }
        } else if start_dot != -1 {
            pre_dot_state = -1;
        }
        i -= 1;
    }
    if start_dot == -1
        || end == -1
        || pre_dot_state == 0
        || (pre_dot_state == 1 && start_dot == end - 1 && start_dot == start_part + 1)
    {
        return String::new();
    }
    path[start_dot as usize..end as usize].to_string()
}

/// `normalizeJoinedLogicalPath`: lexical join against an inventoried logical path (NFC).
pub fn normalize_joined_logical_path(value: &str) -> String {
    if value.contains('\0') {
        return value.to_string();
    }
    let normalized = normalize(&value.replace('\\', "/"));
    let stripped = normalized.strip_prefix("./").unwrap_or(&normalized);
    stripped.nfc().collect()
}

/// `logicalPathEscapesRoot`.
pub fn logical_path_escapes_root(path: &str) -> bool {
    path.contains('\0') || path == ".." || path.starts_with("../") || path.starts_with('/')
}

// ---- artifactPathSyntax.ts ---------------------------------------------------------------

/// Whether a reference carries a URI scheme (`https:`, `file:`, ...).
pub fn has_scheme(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    for ch in chars {
        if ch == ':' {
            return true;
        }
        if !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')) {
            return false;
        }
    }
    false
}

/// Whether a reference is scheme-qualified or protocol-relative.
pub fn looks_external(value: &str) -> bool {
    has_scheme(value) || value.starts_with("//")
}

/// Drop any query string and fragment from a declared reference.
pub fn strip_query_and_fragment(value: &str) -> String {
    let before_fragment = value.split('#').next().unwrap_or("");
    before_fragment.split('?').next().unwrap_or("").to_string()
}

fn contains_encoded_dot_or_separator(value: &str) -> bool {
    value.as_bytes().windows(3).any(|w| {
        w[0] == b'%' && matches!([w[1].to_ascii_lowercase(), w[2].to_ascii_lowercase()], [b'2', b'e'] | [b'2', b'f'] | [b'5', b'c'])
    })
}

/// Path syntax admitted for a canonical artifact path.
pub fn admits_canonical_path_syntax(value: &str) -> bool {
    !value.contains('\0') && !value.contains('\\') && !contains_encoded_dot_or_separator(value)
}

/// The URL text a browser parses from an HTML URL attribute.
pub fn html_url_text(value: &str) -> String {
    let trimmed = value.trim_matches(|c: char| (c as u32) <= 0x20);
    trimmed.chars().filter(|c| !matches!(c, '\t' | '\n' | '\r')).collect()
}

fn hex_pair(a: u8, b: u8) -> Option<u8> {
    let hi = (a as char).to_digit(16)?;
    let lo = (b as char).to_digit(16)?;
    Some((hi * 16 + lo) as u8)
}

/// Percent-decode a URL path as the URL standard does: valid `%XX` become bytes, any other `%`
/// stays literal. `None` when the bytes are not UTF-8 or include NUL.
pub fn percent_decode_url_path(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let has_escape = bytes
        .windows(3)
        .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit());
    if !has_escape {
        return Some(value.to_string());
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(byte) = hex_pair(bytes[i + 1], bytes[i + 2]) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    let decoded = String::from_utf8(out).ok()?;
    if decoded.contains('\0') {
        None
    } else {
        Some(decoded)
    }
}

/// `decodeURIComponent`; `None` for malformed input (`URIError`).
pub fn decode_uri_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if !bytes.contains(&b'%') {
        return Some(value.to_string());
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        if i + 2 >= bytes.len() {
            return None;
        }
        let first = hex_pair(*bytes.get(i + 1)?, *bytes.get(i + 2)?)?;
        i += 3;
        if first < 0x80 {
            out.push(first);
            continue;
        }
        let extra = if first & 0xE0 == 0xC0 {
            1
        } else if first & 0xF0 == 0xE0 {
            2
        } else if first & 0xF8 == 0xF0 {
            3
        } else {
            return None;
        };
        out.push(first);
        for _ in 0..extra {
            if *bytes.get(i)? != b'%' {
                return None;
            }
            let next = hex_pair(*bytes.get(i + 1)?, *bytes.get(i + 2)?)?;
            if next & 0xC0 != 0x80 {
                return None;
            }
            out.push(next);
            i += 3;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_matches_node() {
        assert_eq!(join(&["a", "../b"]), "b");
        assert_eq!(join(&[".", "x"]), "x");
        assert_eq!(join(&["a/b", "..", ".."]), ".");
        assert_eq!(join(&["a", "../../c"]), "../c");
        assert_eq!(dirname("a/b/c.js"), "a/b");
        assert_eq!(dirname("c.js"), ".");
        assert_eq!(dirname("/c.js"), "/");
        assert_eq!(dirname("a/b/"), "a");
        assert_eq!(extname("a/b.JS"), ".JS");
        assert_eq!(extname(".bashrc"), "");
        assert_eq!(extname("a.b.c"), ".c");
        assert_eq!(extname("a."), ".");
        assert_eq!(normalize("a//b/./c/.."), "a/b");
        assert_eq!(normalize("./"), "./");
        assert_eq!(normalize_joined_logical_path("./a/../b"), "b");
        assert!(logical_path_escapes_root("../x"));
        assert!(!logical_path_escapes_root("..x"));
    }

    #[test]
    fn url_text_helpers() {
        assert!(has_scheme("https://x"));
        assert!(!has_scheme("./x:y"));
        assert!(looks_external("//cdn/x.js"));
        assert_eq!(strip_query_and_fragment("a.js?x=1#h"), "a.js");
        assert!(!admits_canonical_path_syntax("a%2Fb"));
        assert!(!admits_canonical_path_syntax("a%2e"));
        assert!(admits_canonical_path_syntax("a%20b"));
        assert_eq!(percent_decode_url_path("a%20b%"), Some("a b%".into()));
        assert_eq!(percent_decode_url_path("%ff"), None);
        assert_eq!(percent_decode_url_path("%00"), None);
        assert_eq!(decode_uri_component("a%20b").as_deref(), Some("a b"));
        assert_eq!(decode_uri_component("%E2%82%AC").as_deref(), Some("\u{20ac}"));
        assert_eq!(decode_uri_component("%E2%82"), None);
        assert_eq!(decode_uri_component("%"), None);
        assert_eq!(html_url_text("  \tfoo\nbar "), "foobar");
    }
}
