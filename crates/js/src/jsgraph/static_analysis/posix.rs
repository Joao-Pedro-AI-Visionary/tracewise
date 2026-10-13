//! Port of the Node.js `path.posix` functions REA uses (`join`, `normalize`, `isAbsolute`,
//! `dirname`, `relative`).
//!
//! Node works on UTF-16 strings and compares `.length` values, so the port works on UTF-16
//! code units as well; separators and dots are ASCII, so every cut stays on a character
//! boundary and the result converts back losslessly.

const SLASH: u16 = b'/' as u16;
const DOT: u16 = b'.' as u16;

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn text(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

/// `path.posix.isAbsolute`.
pub fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// `normalizeString(path, allowAboveRoot, '/', isPosixPathSeparator)`.
fn normalize_string(path: &[u16], allow_above_root: bool) -> Vec<u16> {
    let mut res: Vec<u16> = Vec::new();
    let mut last_segment_length: i64 = 0;
    let mut last_slash: i64 = -1;
    let mut dots: i64 = 0;
    let mut code: u16 = 0;
    let len = path.len();
    for i in 0..=len {
        if i < len {
            code = path[i];
        } else if code == SLASH {
            break;
        } else {
            code = SLASH;
        }
        let at = i as i64;
        if code == SLASH {
            if last_slash == at - 1 || dots == 1 {
                // nothing
            } else if dots == 2 {
                let tail_is_dotdot = res.len() >= 2
                    && last_segment_length == 2
                    && res[res.len() - 1] == DOT
                    && res[res.len() - 2] == DOT;
                if !tail_is_dotdot {
                    if res.len() > 2 {
                        match res.iter().rposition(|unit| *unit == SLASH) {
                            None => {
                                res.clear();
                                last_segment_length = 0;
                            }
                            Some(last_slash_index) => {
                                res.truncate(last_slash_index);
                                let previous = res.iter().rposition(|unit| *unit == SLASH);
                                last_segment_length = res.len() as i64
                                    - 1
                                    - previous.map_or(-1, |index| index as i64);
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
                if allow_above_root {
                    if !res.is_empty() {
                        res.push(SLASH);
                    }
                    res.push(DOT);
                    res.push(DOT);
                    last_segment_length = 2;
                }
            } else {
                let segment = &path[(last_slash + 1) as usize..i];
                if !res.is_empty() {
                    res.push(SLASH);
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
    res
}

/// `path.posix.normalize`.
pub fn normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let path = units(path);
    let absolute = path[0] == SLASH;
    let trailing_separator = path[path.len() - 1] == SLASH;
    let mut normalized = normalize_string(&path, !absolute);
    if normalized.is_empty() {
        if absolute {
            return "/".into();
        }
        return if trailing_separator { "./".into() } else { ".".into() };
    }
    if trailing_separator {
        normalized.push(SLASH);
    }
    if absolute {
        let mut out = vec![SLASH];
        out.extend(normalized);
        text(&out)
    } else {
        text(&normalized)
    }
}

/// `path.posix.join(...parts)`.
pub fn join(parts: &[&str]) -> String {
    let mut joined: Option<String> = None;
    for part in parts {
        if part.is_empty() {
            continue;
        }
        match joined.as_mut() {
            None => joined = Some((*part).to_string()),
            Some(existing) => {
                existing.push('/');
                existing.push_str(part);
            }
        }
    }
    match joined {
        None => ".".into(),
        Some(joined) => normalize(&joined),
    }
}

/// `path.posix.dirname`.
pub fn dirname(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let path = units(path);
    let has_root = path[0] == SLASH;
    let mut end: i64 = -1;
    let mut matched_slash = true;
    let mut i = path.len() as i64 - 1;
    while i >= 1 {
        if path[i as usize] == SLASH {
            if !matched_slash {
                end = i;
                break;
            }
        } else {
            matched_slash = false;
        }
        i -= 1;
    }
    if end == -1 {
        return if has_root { "/".into() } else { ".".into() };
    }
    if has_root && end == 1 {
        return "//".into();
    }
    text(&path[..end as usize])
}

/// `path.posix.resolve` for absolute inputs (the only form REA reaches): the process working
/// directory is never consulted. A relative input is resolved against `/`.
fn resolve_absolute(path: &str) -> Vec<u16> {
    let source = if is_absolute(path) { path.to_string() } else { format!("/{path}") };
    let normalized = normalize_string(&units(&source), false);
    let mut out = vec![SLASH];
    out.extend(normalized);
    out
}

/// `path.posix.relative(from, to)`.
pub fn relative(from: &str, to: &str) -> String {
    if from == to {
        return String::new();
    }
    let from = resolve_absolute(from);
    let to = resolve_absolute(to);
    if from == to {
        return String::new();
    }
    let from_start = 1usize;
    let from_end = from.len();
    let from_len = from_end - from_start;
    let to_start = 1usize;
    let to_len = to.len() - to_start;
    let length = from_len.min(to_len);
    let mut last_common_sep: i64 = -1;
    let mut i = 0usize;
    while i < length {
        let from_code = from[from_start + i];
        if from_code != to[to_start + i] {
            break;
        } else if from_code == SLASH {
            last_common_sep = i as i64;
        }
        i += 1;
    }
    if i == length {
        if to_len > length {
            if to[to_start + i] == SLASH {
                return text(&to[to_start + i + 1..]);
            }
            if i == 0 {
                return text(&to[to_start + i..]);
            }
        } else if from_len > length {
            if from[from_start + i] == SLASH {
                last_common_sep = i as i64;
            } else if i == 0 {
                last_common_sep = 0;
            }
        }
    }
    let mut out: Vec<u16> = Vec::new();
    let mut index = from_start as i64 + last_common_sep + 1;
    while index <= from_end as i64 {
        if index == from_end as i64 || from[index as usize] == SLASH {
            if out.is_empty() {
                out.extend([DOT, DOT]);
            } else {
                out.extend([SLASH, DOT, DOT]);
            }
        }
        index += 1;
    }
    out.extend_from_slice(&to[(to_start as i64 + last_common_sep) as usize..]);
    text(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_node_examples() {
        assert_eq!(join(&["/foo", "bar", "baz/asdf", "quux", ".."]), "/foo/bar/baz/asdf");
        assert_eq!(join(&[]), ".");
        assert_eq!(join(&["", ""]), ".");
        assert_eq!(normalize("/foo/bar//baz/asdf/quux/.."), "/foo/bar/baz/asdf");
        assert_eq!(normalize("../../a/./b/"), "../../a/b/");
        assert_eq!(dirname("/a/b/c"), "/a/b");
        assert_eq!(dirname("a"), ".");
        assert_eq!(dirname("/a"), "/");
        assert_eq!(relative("/data/orandea/test/aaa", "/data/orandea/impl/bbb"), "../../impl/bbb");
        assert_eq!(relative("/a/b/", "/a/b/c/d"), "c/d");
        assert_eq!(relative("/a/b/c", "/a"), "../..");
    }
}
