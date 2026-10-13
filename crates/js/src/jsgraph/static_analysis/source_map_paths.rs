//! Port of `javascriptSourceMapPaths.ts`: interpret a source-map `sources[]` declaration once at
//! the ingestion boundary.
//!
//! The TypeScript leans on Node's `path.posix`, WHATWG `URL`, `domainToASCII`, `fileURLToPath` and
//! `pathToFileURL`. The posix functions are ports (`posix.rs`); URLs use the `url` crate (WHATWG
//! parser); `pathToFileURL` follows Node 22's escaping table.
//!
//! Deviation (documented, never reached by well-formed maps): a Windows drive prefix whose letter
//! is not ASCII (`/^[a-z]:\//iu` also folds U+017F and U+212A) makes Node call `process.cwd()`;
//! this port declines such a declaration as an invalid path instead.

use serde::{Deserialize, Serialize};
use url::Url;

use super::posix;
use super::uri;

/// Resolution outcome of a source-map source declaration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SourceMapResolution {
    ArtifactRelative { path: String },
    Suffix { path: String },
    Unresolved { reason: String },
}

/// Map-scoped source declaration and its path interpretation for matching
/// (`JavaScriptSourceMapReference`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SourceMapReference {
    pub source_name: String,
    pub source_root: Option<String>,
    pub map_path: String,
    pub resolution: SourceMapResolution,
}

/// `resolveJavaScriptSourceMapReference`: interpret a declaration once at the ingestion boundary.
pub fn resolve_source_map_reference(
    source_name: &str,
    source_root: Option<&str>,
    map_path: &str,
) -> SourceMapReference {
    // TraceMap's producer prefixes sourceRoot before resolving the URL reference.
    let reference = match source_root {
        Some(root) if !root.is_empty() => format!("{root}/{source_name}"),
        _ => source_name.to_string(),
    };
    SourceMapReference {
        source_name: source_name.to_string(),
        source_root: source_root.map(str::to_string),
        map_path: map_path.to_string(),
        resolution: resolve_source_map_path(&reference, map_path),
    }
}

fn unresolved(reason: &str) -> SourceMapResolution {
    SourceMapResolution::Unresolved { reason: reason.to_string() }
}

/// `/^[a-z]:\//iu` (the class also folds U+017F and U+212A under `/iu`).
fn has_drive_prefix(portable: &str) -> bool {
    let mut chars = portable.chars();
    let letter = chars.next();
    letter.is_some_and(|c| c.is_ascii_alphabetic() || c == '\u{17f}' || c == '\u{212a}')
        && chars.next() == Some(':')
        && chars.next() == Some('/')
}

/// Resolve a source-map URL reference without changing its recorded identity.
fn resolve_source_map_path(source: &str, map_path: &str) -> SourceMapResolution {
    let portable = source.replace('\\', "/");
    let windows_path = has_drive_prefix(&portable) || source.starts_with("\\\\");
    // Preserve parent traversal rather than letting URL resolution clamp at '/'.
    let anchor = format!("/{}", "source/".repeat(portable.split('/').count() + 1));
    let directory = posix::join(&[&anchor, &posix::dirname(&map_path.replace('\\', "/"))]);
    let base = path_to_file_url_posix(&format!("{directory}/"));
    let absolute: Option<Url> = if windows_path { windows_file_url(source) } else { parse_absolute(source) };
    let resolved: Option<Url> = if windows_path {
        absolute.clone()
    } else {
        base.and_then(|base| parse_relative(&base, source))
    };
    let Some(resolved) = resolved else {
        return unresolved("Source reference is not a valid URL or filesystem path.");
    };
    let pathname = resolved.path();
    if !pathname.starts_with('/') {
        return unresolved("Source reference uses a non-hierarchical URL without a file pathname.");
    }
    if pathname.ends_with('/') {
        return unresolved("Source reference names a directory rather than a file.");
    }
    // Encoded separators must not manufacture a different filesystem hierarchy.
    if has_encoded_separator(pathname) {
        return unresolved("Source reference contains an encoded path separator.");
    }
    let relative = match &absolute {
        None => !portable.starts_with('/'),
        Some(absolute) => absolute.as_str() != resolved.as_str(),
    };
    let Some(path) = decoded_url_path(&resolved) else {
        return unresolved("Source reference has malformed URL encoding or an invalid file URL.");
    };
    let value = if relative {
        posix::relative(&anchor, &path)
    } else {
        path.trim_start_matches('/').to_string()
    };
    if value.is_empty() || value == ".." || value.starts_with("../") {
        return unresolved("Source reference resolves outside the inventoried artifact.");
    }
    if relative {
        SourceMapResolution::ArtifactRelative { path: value }
    } else {
        SourceMapResolution::Suffix { path: value }
    }
}

/// The `url` crate ends a port at a backslash for every scheme, while the WHATWG parser (and
/// therefore Node) only does so for special schemes: `ng://host:\x` is a failure there. Report
/// that case so the caller can reject it.
fn has_invalid_non_special_port(input: &str) -> bool {
    let trimmed = input.trim_matches(|c: char| c <= ' ');
    let Some(colon) = trimmed.find(':') else { return false };
    let scheme = &trimmed[..colon];
    let mut chars = scheme.chars();
    let valid_scheme = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !valid_scheme {
        return false;
    }
    let lower = scheme.to_ascii_lowercase();
    if matches!(lower.as_str(), "http" | "https" | "ws" | "wss" | "ftp" | "file") {
        return false;
    }
    let Some(rest) = trimmed[colon + 1..].strip_prefix("//") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    let port_part = if let Some(close) = host_port.rfind(']') {
        host_port[close + 1..].strip_prefix(':')
    } else {
        host_port.rfind(':').map(|index| &host_port[index + 1..])
    };
    port_part.is_some_and(|port| !port.chars().all(|c| c.is_ascii_digit() || matches!(c, '\t' | '\n' | '\r')))
}

/// `URL.parse(input)` with the non-special-scheme port rule above.
fn parse_absolute(input: &str) -> Option<Url> {
    if has_invalid_non_special_port(input) {
        return None;
    }
    Url::parse(input).ok()
}

/// `URL.parse(input, base)` with the same rule.
fn parse_relative(base: &Url, input: &str) -> Option<Url> {
    if has_invalid_non_special_port(input) {
        return None;
    }
    base.join(input).ok()
}

/// `/%(?:2f|5c)/iu`.
fn has_encoded_separator(text: &str) -> bool {
    text.as_bytes().windows(3).any(|window| {
        window[0] == b'%'
            && matches!((window[1], window[2].to_ascii_lowercase()), (b'2', b'f') | (b'5', b'c'))
    })
}

/// `/[\0\t\n\r #/:<>?@[\\\]^|%]/u`: delimiters and escapes rejected before IDNA can truncate or
/// decode the host.
fn has_unusable_host_char(host: &str) -> bool {
    host.chars().any(|c| {
        matches!(
            c,
            '\0' | '\t' | '\n' | '\r' | ' ' | '#' | '/' | ':' | '<' | '>' | '?' | '@' | '[' | '\\' | ']' | '^' | '|' | '%'
        )
    })
}

/// Node's `domainToASCII`: set the hostname of a throwaway `ws://x` URL; failure yields `""`.
fn domain_to_ascii(host: &str) -> String {
    let Ok(mut url) = Url::parse("ws://x") else { return String::new() };
    if url.set_host(Some(host)).is_err() {
        return String::new();
    }
    url.host_str().unwrap_or("").to_string()
}

/// URL validation also rejects Unicode hosts that normalize to empty.
fn carries_usable_host(host: &str) -> bool {
    !has_unusable_host_char(host) && !domain_to_ascii(host).is_empty()
}

/// Characters Node's `pathToFileURL` percent-encodes before the URL path setter runs, plus every
/// control character (the URL parser would trim or drop some of them at the edges of the whole
/// href, whereas a path setter encodes them).
fn encode_file_url_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '\0'..='\u{1f}' | '\u{7f}' | ' ' | '"' | '#' | '%' | '?' | '[' | ']' | '^' | '|' | '~' | '<' | '>'
            | '`' | '{' | '}' | '\\' => {
                let mut buffer = [0u8; 4];
                for byte in c.encode_utf8(&mut buffer).as_bytes() {
                    out.push_str(&format!("%{byte:02X}"));
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// `pathToFileURL(path, { windows: false })` for an absolute POSIX path.
fn path_to_file_url_posix(filepath: &str) -> Option<Url> {
    let resolved_units = {
        // `path.posix.resolve(filepath)` for an absolute input.
        let normalized = posix::normalize(filepath);
        let mut resolved = normalized.trim_end_matches('/').to_string();
        if resolved.is_empty() {
            resolved.push('/');
        }
        resolved
    };
    let mut resolved = resolved_units;
    // path.resolve strips trailing slashes so we must add them back.
    if filepath.ends_with('/') && !resolved.ends_with('/') {
        resolved.push('/');
    }
    Url::parse(&format!("file://{}", encode_file_url_path(&resolved))).ok()
}

/// `windowsFileUrl`: `pathToFileURL(path, { windows: true })`, `None` where Node throws a
/// `TypeError`.
fn windows_file_url(path: &str) -> Option<Url> {
    // A malformed UNC host aborts pathToFileURL() on the Node builds this package admits, so
    // decline the reference before handing the path over.
    if path.starts_with("\\\\") && !carries_usable_host(path[2..].split('\\').next().unwrap_or("")) {
        return None;
    }
    if let Some(unc) = path.strip_prefix("\\\\") {
        // UNC: the path is not resolved; the host is everything up to the next backslash.
        let host_end = unc.find('\\')? + 2;
        if host_end == 2 {
            return None;
        }
        let hostname = &path[2..host_end];
        let rest = path[host_end..].replace('\\', "/");
        return Url::parse(&format!("file://{hostname}{}", encode_file_url_path(&rest))).ok();
    }
    let resolved = win32_resolve_drive_absolute(path)?;
    let mut resolved = resolved;
    // path.resolve strips trailing slashes so we must add them back. `path.sep` is the host's
    // separator ('/'), so a trailing backslash left by `resolve` still gets one more slash.
    if (path.ends_with('/') || path.ends_with('\\')) && !resolved.ends_with('/') {
        resolved.push('/');
    }
    let slashed = resolved.replace('\\', "/");
    Url::parse(&format!("file:///{}", encode_file_url_path(&slashed))).ok()
}

/// `path.win32.resolve(path)` for a path that starts with `X:` followed by a separator.
fn win32_resolve_drive_absolute(path: &str) -> Option<String> {
    let mut chars = path.chars();
    let letter = chars.next()?;
    if !letter.is_ascii_alphabetic() || chars.next() != Some(':') {
        return None;
    }
    let separator = chars.next()?;
    if separator != '/' && separator != '\\' {
        return None;
    }
    let device = &path[..2];
    let tail = format!("{}\\", &path[3..]);
    let normalized = win32_normalize_string(&tail);
    Some(format!("{device}\\{normalized}"))
}

/// `normalizeString(path, false, '\\', isWindowsPathSeparator)`.
fn win32_normalize_string(path: &str) -> String {
    const BACKSLASH: u16 = b'\\' as u16;
    const SLASH: u16 = b'/' as u16;
    const DOT: u16 = b'.' as u16;
    let path: Vec<u16> = path.encode_utf16().collect();
    let is_separator = |unit: u16| unit == BACKSLASH || unit == SLASH;
    let mut res: Vec<u16> = Vec::new();
    let mut last_segment_length: i64 = 0;
    let mut last_slash: i64 = -1;
    let mut dots: i64 = 0;
    let mut code: u16 = 0;
    for i in 0..=path.len() {
        if i < path.len() {
            code = path[i];
        } else if is_separator(code) {
            break;
        } else {
            code = SLASH;
        }
        let at = i as i64;
        if is_separator(code) {
            if last_slash == at - 1 || dots == 1 {
                // nothing
            } else if dots == 2 {
                let tail_is_dotdot = res.len() >= 2
                    && last_segment_length == 2
                    && res[res.len() - 1] == DOT
                    && res[res.len() - 2] == DOT;
                if !tail_is_dotdot {
                    if res.len() > 2 {
                        match res.iter().rposition(|unit| *unit == BACKSLASH) {
                            None => {
                                res.clear();
                                last_segment_length = 0;
                            }
                            Some(index) => {
                                res.truncate(index);
                                let previous = res.iter().rposition(|unit| *unit == BACKSLASH);
                                last_segment_length =
                                    res.len() as i64 - 1 - previous.map_or(-1, |value| value as i64);
                            }
                        }
                        last_slash = at;
                        dots = 0;
                        continue;
                    } else if !res.is_empty() {
                        res.clear();
                        last_segment_length = 0;
                        last_slash = at;
                        dots = 0;
                        continue;
                    }
                }
                // allowAboveRoot is false for an absolute path: `..` above the root is dropped.
            } else {
                let segment = &path[(last_slash + 1) as usize..i];
                if !res.is_empty() {
                    res.push(BACKSLASH);
                }
                res.extend_from_slice(segment);
                last_segment_length = at - last_slash - 1;
            }
            last_slash = at;
            dots = 0;
        } else if code == DOT && dots != -1 {
            dots += 1;
        } else {
            dots = -1;
        }
    }
    String::from_utf16_lossy(&res)
}

/// `decodedUrlPath`: `None` where Node throws `URIError` or `TypeError`.
fn decoded_url_path(url: &Url) -> Option<String> {
    if url.scheme() == "file" {
        let hostname = url.host_str().unwrap_or("");
        let windows = !hostname.is_empty() && hostname != "localhost";
        let path = if windows { file_url_to_path_windows(url)? } else { uri::file_url_to_path_posix(url)? };
        return Some(path.replace('\\', "/"));
    }
    let host = match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        (None, _) => String::new(),
    };
    Some(format!("{host}{}", uri::decode_uri_component(url.path())?))
}

/// `fileURLToPath(url, { windows: true })` for a URL with a non-empty host (a UNC path).
fn file_url_to_path_windows(url: &Url) -> Option<String> {
    let hostname = url.host_str().unwrap_or("");
    let pathname = url.path();
    let bytes = pathname.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%' {
            let third = bytes.get(index + 2).map_or(0, |value| value | 0x20);
            if (bytes.get(index + 1) == Some(&b'2') && third == b'f')
                || (bytes.get(index + 1) == Some(&b'5') && third == b'c')
            {
                return None;
            }
        }
    }
    let pathname = pathname.replace('/', "\\");
    let decoded = uri::decode_uri_component(&pathname)?;
    if hostname.is_empty() {
        // A local path needs a drive letter; the caller only reaches this with a host set.
        return None;
    }
    Some(format!("\\\\{}{decoded}", url::quirks::domain_to_unicode(hostname)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(source: &str, root: Option<&str>, map: &str) -> SourceMapResolution {
        resolve_source_map_reference(source, root, map).resolution
    }

    #[test]
    fn relative_and_suffix_forms() {
        assert_eq!(
            resolve("../src/a.ts", None, "dist/app.js.map"),
            SourceMapResolution::ArtifactRelative { path: "src/a.ts".into() }
        );
        assert_eq!(
            resolve("webpack:///./src/a.ts", None, "app.js.map"),
            SourceMapResolution::Suffix { path: "src/a.ts".into() }
        );
        assert!(matches!(resolve("../../x.ts", None, "app.js.map"), SourceMapResolution::Unresolved { .. }));
    }
}
