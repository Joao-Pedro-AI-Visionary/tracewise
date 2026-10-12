//! Local `file://` authorization for Electron CDP targets
//! (port of REA browser/ElectronFileScope.ts).
//!
//! A URL authorizes a path only when it is a credential-free, host-free
//! `file:` URL without encoded separators whose path is either a regular
//! host file (returned canonicalized) or a regular member of an ASAR archive
//! (`<archive>.asar/<member>`, resolved through the archive's JSON header the
//! way Electron's file protocol does).
//!
//! Not ported: REA's process-wide LRU cache of decoded ASAR headers. Each
//! lookup re-reads the header; the result is identical.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::Value;
use url::Url;

/// Shared resource budget for the eagerly decoded ASAR header (REA `MAX_ASAR_HEADER_BYTES`).
pub const MAX_ASAR_HEADER_BYTES: u64 = 16 * 1024 * 1024;

/// Resolve one local file URL; returns the canonical path when allowed.
pub fn authorized_electron_file(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if url.scheme() != "file"
        || url.host_str().is_some_and(|host| !host.is_empty())
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let path = url.to_file_path().ok()?;
    let text = path.to_str()?;
    if !path.is_absolute() || text.contains('\0') {
        return None;
    }
    if std::fs::metadata(&path).is_ok_and(|m| m.is_file()) {
        if let Ok(real) = std::fs::canonicalize(&path) {
            return real.to_str().map(str::to_string);
        }
    }
    authorized_asar_member(text)
}

/// Resolve `<archive>.asar/<member>`: the first `.asar` component that is a
/// regular file is the archive and the remainder must name a regular file in
/// its header (packed or unpacked).
fn authorized_asar_member(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.split('/').collect();
    for index in 1..segments.len().saturating_sub(1) {
        if !segments[index].to_lowercase().ends_with(".asar") {
            continue;
        }
        let archive = segments[..=index].join("/");
        let member = &segments[index + 1..];
        if member.iter().any(|part| part.is_empty() || *part == "." || *part == "..") {
            return None;
        }
        // Any stat/read/parse failure rejects the URL (REA returns undefined).
        let metadata = std::fs::metadata(&archive).ok()?;
        if !metadata.is_file() {
            continue;
        }
        let canonical = std::fs::canonicalize(&archive).ok()?;
        let files = asar_files(&canonical)?;
        if !is_asar_regular_file(&files, member) {
            return None;
        }
        let mut joined = canonical;
        for part in member {
            joined.push(part);
        }
        return joined.to_str().map(str::to_string);
    }
    None
}

/// Read the two Chromium pickle headers and decode the JSON file tree.
fn asar_files(archive: &Path) -> Option<Value> {
    let mut handle = File::open(archive).ok()?;
    let size = handle.metadata().ok()?.len();
    let mut prefix = [0u8; 16];
    handle.read_exact(&mut prefix).ok()?;
    let word = |offset: usize| {
        u64::from(u32::from_le_bytes([
            prefix[offset],
            prefix[offset + 1],
            prefix[offset + 2],
            prefix[offset + 3],
        ]))
    };
    let (size_pickle, header_bytes, payload_bytes, json_bytes) = (word(0), word(4), word(8), word(12));
    if size_pickle != 4
        || header_bytes < 8
        || header_bytes > size.saturating_sub(8)
        || payload_bytes != header_bytes - 4
        || json_bytes > payload_bytes.saturating_sub(4)
        || header_bytes > MAX_ASAR_HEADER_BYTES
    {
        return None;
    }
    let mut json = vec![0u8; usize::try_from(json_bytes).ok()?];
    handle.seek(SeekFrom::Start(16)).ok()?;
    handle.read_exact(&mut json).ok()?;
    let text = std::str::from_utf8(&json).ok()?;
    let parsed: Value = serde_json::from_str(text).ok()?;
    let files = parsed.get("files")?;
    files.is_object().then(|| files.clone())
}

fn is_asar_regular_file(files: &Value, member: &[&str]) -> bool {
    let mut children = files;
    let mut node: Option<&Value> = None;
    for part in member {
        if let Some(current) = node {
            match current.get("files") {
                Some(next) if next.is_object() => children = next,
                _ => return false,
            }
        }
        match children.as_object().and_then(|map| map.get(*part)) {
            Some(next) => node = Some(next),
            None => return false,
        }
    }
    node.and_then(Value::as_object).is_some_and(|entry| {
        entry.get("size").is_some_and(Value::is_number)
            && !entry.contains_key("files")
            && !entry.contains_key("link")
    })
}

/// Test helper: canonical path of an existing file as a `file://` URL.
pub fn file_url(path: &Path) -> Option<String> {
    let path: PathBuf = std::fs::canonicalize(path).ok()?;
    Url::from_file_path(path).ok().map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_asar(dir: &Path, header: &Value) -> PathBuf {
        let json = serde_json::to_vec(header).unwrap();
        let json_len = json.len() as u32;
        let padded = (json_len + 3) & !3;
        let payload = padded + 4;
        let header_bytes = payload + 4;
        let mut bytes = Vec::new();
        for word in [4u32, header_bytes, payload, json_len] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&json);
        bytes.resize(8 + header_bytes as usize, 0);
        bytes.extend_from_slice(b"console.log(1)\n");
        let path = dir.join("app.asar");
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tracewise-electron-scope-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(dir).unwrap()
    }

    #[test]
    fn rejects_remote_hosts_credentials_and_encoded_separators() {
        let dir = temp_dir("reject");
        let file = dir.join("index.html");
        std::fs::write(&file, "<p>").unwrap();
        let url = file_url(&file).unwrap();
        assert_eq!(authorized_electron_file(&url).as_deref(), file.to_str());
        assert_eq!(
            authorized_electron_file(&url.replace("file:///", "file://localhost/")).as_deref(),
            file.to_str()
        );
        for bad in [
            url.replace("file:///", "file://example.com/"),
            url.replace("file:///", "https://example.com/"),
            url.replace("index.html", "a%2Findex.html"),
            url.replace("index.html", "a%5cindex.html"),
            url.replace("index.html", "missing.html"),
            "not a url".to_string(),
            "about:blank".to_string(),
        ] {
            assert_eq!(authorized_electron_file(&bad), None, "{bad}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resolves_regular_asar_members_only() {
        let dir = temp_dir("asar");
        let archive = write_asar(
            &dir,
            &serde_json::json!({ "files": {
                "index.html": { "size": 3, "offset": "0" },
                "lib": { "files": { "main.js": { "size": 15, "offset": "0" } } },
                "link.js": { "link": "lib/main.js" },
            }}),
        );
        let base = Url::from_file_path(&archive).unwrap().to_string();
        assert_eq!(
            authorized_electron_file(&format!("{base}/lib/main.js")),
            Some(format!("{}/lib/main.js", archive.display()))
        );
        assert_eq!(
            authorized_electron_file(&format!("{base}/index.html")),
            Some(format!("{}/index.html", archive.display()))
        );
        for bad in ["lib", "link.js", "missing.js", "lib//main.js", "index.html/x"] {
            assert_eq!(authorized_electron_file(&format!("{base}/{bad}")), None, "{bad}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
