//! Node `path`/`URL` semantics used by runtime location mapping (port of the
//! path helpers in REA javascriptRuntimeStaticCandidates.ts and
//! domain/artifactIdentity.ts).

use url::Url;

use crate::identity::logical_path_nfc;

/// Node `path.posix.normalize`.
pub fn posix_normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if joined.is_empty() {
        return if absolute {
            "/".to_string()
        } else if trailing {
            "./".to_string()
        } else {
            ".".to_string()
        };
    }
    let joined = if trailing { format!("{joined}/") } else { joined };
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Node `path.resolve` for one POSIX path against the process working directory.
pub fn posix_resolve(path: &str) -> String {
    let joined = if path.starts_with('/') {
        path.to_string()
    } else {
        let cwd = std::env::current_dir()
            .map(|dir| dir.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/".to_string());
        format!("{cwd}/{path}")
    };
    let normalized = posix_normalize(&joined);
    if normalized.len() > 1 {
        normalized.trim_end_matches('/').to_string()
    } else {
        normalized
    }
}

/// POSIX root, Windows drive, or UNC share path.
pub fn is_portable_absolute_path(path: &str) -> bool {
    path.starts_with('/') || is_windows_drive_path(path) || is_unc_path(path)
}

fn is_windows_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/')
}

fn is_unc_path(path: &str) -> bool {
    let rest = match path.get(..2) {
        Some("\\\\") | Some("//") => &path[2..],
        _ => return false,
    };
    let mut parts = rest.split(['\\', '/']);
    matches!((parts.next(), parts.next()), (Some(server), Some(share)) if !server.is_empty() && !share.is_empty())
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum PathStyle {
    Posix,
    Windows,
}

fn absolute_file_path_style(path: &str) -> Option<PathStyle> {
    if is_windows_drive_path(path) || is_unc_path(path) {
        Some(PathStyle::Windows)
    } else if path.starts_with('/') {
        Some(PathStyle::Posix)
    } else {
        None
    }
}

fn relative_components(root: &[String], value: &[String], equal: impl Fn(&str, &str) -> bool) -> String {
    let common = root
        .iter()
        .zip(value.iter())
        .take_while(|(left, right)| equal(left, right))
        .count();
    let mut parts: Vec<&str> = vec![".."; root.len() - common];
    parts.extend(value[common..].iter().map(String::as_str));
    parts.join("/")
}

fn posix_components(path: &str) -> Vec<String> {
    posix_normalize(path)
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn windows_components(path: &str) -> Vec<String> {
    let normalized = path.replace('\\', "/");
    posix_components(&normalized)
}

/// Artifact path of `value` below `root`, or `None` when it escapes.
pub fn path_below_root(root: &str, value: &str) -> Option<String> {
    let style = absolute_file_path_style(root)?;
    if absolute_file_path_style(value) != Some(style) {
        return None;
    }
    let remainder = match style {
        PathStyle::Posix => relative_components(&posix_components(root), &posix_components(value), |l, r| l == r),
        PathStyle::Windows => relative_components(&windows_components(root), &windows_components(value), |l, r| {
            l.eq_ignore_ascii_case(r)
        }),
    };
    if remainder.is_empty() || remainder == ".." || remainder.starts_with("../") {
        return None;
    }
    relative_logical_path(&remainder)
}

/// Artifact path of `value` below an HTTP(S) URL prefix.
pub fn path_below_url_prefix(prefix: &str, value: &str) -> Option<String> {
    let base = Url::parse(prefix).ok()?;
    let candidate = Url::parse(value).ok()?;
    if base.origin() != candidate.origin() || !candidate.path().starts_with(base.path()) {
        return None;
    }
    relative_logical_path(&decode_uri_component(&candidate.path()[base.path().len()..])?)
}

/// JavaScript `decodeURIComponent`: malformed escapes or invalid UTF-8 fail.
fn decode_uri_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = value.get(index + 1..index + 3)?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// REA `normalizeJoinedLogicalPath`.
fn normalize_joined_logical_path(value: &str) -> String {
    if value.contains('\0') {
        return value.to_string();
    }
    let normalized = posix_normalize(&value.replace('\\', "/"));
    logical_path_nfc(normalized.strip_prefix("./").unwrap_or(&normalized))
}

fn logical_path_escapes_root(path: &str) -> bool {
    path.contains('\0') || path == ".." || path.starts_with("../") || path.starts_with('/')
}

/// Safe relative logical path, or `None`.
pub fn relative_logical_path(value: &str) -> Option<String> {
    let normalized = normalize_joined_logical_path(value);
    (!normalized.is_empty() && normalized != "." && !logical_path_escapes_root(&normalized)).then_some(normalized)
}

pub fn safe_artifact_path(prefix: &str, suffix: &str) -> Option<String> {
    if prefix.is_empty() {
        relative_logical_path(suffix)
    } else {
        relative_logical_path(&posix_normalize(&format!("{prefix}/{suffix}")))
    }
}

pub fn path_within_prefix(path: &str, prefix: &str) -> bool {
    prefix.is_empty() || path == prefix || path.starts_with(&format!("{prefix}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_matches_node_posix() {
        assert_eq!(posix_normalize(""), ".");
        assert_eq!(posix_normalize("./"), "./");
        assert_eq!(posix_normalize("a//b/../c/"), "a/c/");
        assert_eq!(posix_normalize("../a"), "../a");
        assert_eq!(posix_normalize("/../a"), "/a");
    }

    #[test]
    fn paths_below_roots_and_prefixes() {
        assert_eq!(path_below_root("/app", "/app/src/main.js").as_deref(), Some("src/main.js"));
        assert_eq!(path_below_root("/app", "/application/x.js"), None);
        assert_eq!(path_below_root("/app", "/app"), None);
        assert_eq!(path_below_root("/app", "C:\\app\\x.js"), None);
        assert_eq!(
            path_below_url_prefix("https://example.com/static/", "https://example.com/static/a%20b.js").as_deref(),
            Some("a b.js")
        );
        assert_eq!(path_below_url_prefix("https://example.com/static/", "https://example.com/static/%E0"), None);
        assert_eq!(path_below_url_prefix("https://example.com/static/", "https://other.com/static/a.js"), None);
        assert_eq!(safe_artifact_path("runtime", "keepalive.cjs").as_deref(), Some("runtime/keepalive.cjs"));
    }
}
