//! Node.js URL helpers the static analysis relies on: `decodeURIComponent` and
//! `fileURLToPath(url, { windows: false })`.

use url::Url;

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_byte(bytes: &[u8], at: usize) -> Option<u8> {
    if bytes.get(at) != Some(&b'%') {
        return None;
    }
    Some(hex_value(*bytes.get(at + 1)?)? << 4 | hex_value(*bytes.get(at + 2)?)?)
}

/// ECMAScript `decodeURIComponent`: `None` where it throws `URIError`.
pub fn decode_uri_component(text: &str) -> Option<String> {
    if !text.contains('%') {
        return Some(text.to_string());
    }
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let first = percent_byte(bytes, i)?;
        i += 3;
        if first < 0x80 {
            out.push(first);
            continue;
        }
        let extra = match first {
            0xC0..=0xDF => 1,
            0xE0..=0xEF => 2,
            0xF0..=0xF7 => 3,
            _ => return None,
        };
        let mut sequence = vec![first];
        for _ in 0..extra {
            let next = percent_byte(bytes, i)?;
            if next & 0xC0 != 0x80 {
                return None;
            }
            sequence.push(next);
            i += 3;
        }
        // Rejects overlong forms, surrogates and code points above U+10FFFF, as JS does.
        std::str::from_utf8(&sequence).ok()?;
        out.extend(sequence);
    }
    String::from_utf8(out).ok()
}

/// `fileURLToPath(url, { windows: false })` for a `file:` URL: `None` where Node throws.
pub fn file_url_to_path_posix(url: &Url) -> Option<String> {
    if url.scheme() != "file" {
        return None;
    }
    if url.host_str().is_some_and(|host| !host.is_empty()) {
        return None;
    }
    let pathname = url.path();
    let bytes = pathname.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%' && bytes.get(index + 1) == Some(&b'2') {
            if let Some(third) = bytes.get(index + 2) {
                if third | 0x20 == b'f' {
                    return None;
                }
            }
        }
    }
    decode_uri_component(pathname)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_like_ecmascript() {
        assert_eq!(decode_uri_component("a%20b").as_deref(), Some("a b"));
        assert_eq!(decode_uri_component("%C3%A9").as_deref(), Some("\u{e9}"));
        assert_eq!(decode_uri_component("%E0%A4%A"), None);
        assert_eq!(decode_uri_component("%FF"), None);
        assert_eq!(decode_uri_component("%C0%80"), None);
        assert_eq!(decode_uri_component("%ED%A0%80"), None);
        assert_eq!(decode_uri_component("%zz"), None);
        assert_eq!(decode_uri_component("100%"), None);
    }
}
