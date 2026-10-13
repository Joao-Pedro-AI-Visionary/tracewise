//! Filesystem helpers mirroring the Node primitives the REA adb provider uses
//! (`path.resolve`, `path.join`, `path.posix.basename`, `hashStableFile`).

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use sha2::{Digest, Sha256};

fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("/{}", parts.join("/"))
}

/// `path.resolve(path)` on POSIX.
pub fn resolve(path: &str) -> String {
    if path.starts_with('/') {
        return normalize(path);
    }
    let cwd = std::env::current_dir()
        .map(|dir| dir.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/".to_string());
    normalize(&format!("{cwd}/{path}"))
}

/// `path.join(base, name)` on POSIX for an absolute `base`.
pub fn join(base: &str, name: &str) -> String {
    normalize(&format!("{base}/{name}"))
}

/// `path.isAbsolute(path)` on POSIX.
pub fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// `path.relative(from, to)` on POSIX (both resolved first).
pub fn relative(from: &str, to: &str) -> String {
    let from = resolve(from);
    let to = resolve(to);
    if from == to {
        return String::new();
    }
    let split = |p: &str| -> Vec<String> { p.split('/').filter(|s| !s.is_empty()).map(str::to_string).collect() };
    let (a, b) = (split(&from), split(&to));
    let common = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let mut parts: Vec<String> = vec!["..".to_string(); a.len() - common];
    parts.extend(b[common..].iter().cloned());
    parts.join("/")
}

/// Node's `error.message` for a failed filesystem call:
/// `ENOENT: no such file or directory, realpath '/x'`.
pub fn node_io_error(error: &std::io::Error, syscall: &str, path: &str) -> String {
    let (code, text) = match error.raw_os_error() {
        Some(1) => ("EPERM", "operation not permitted"),
        Some(2) => ("ENOENT", "no such file or directory"),
        Some(13) => ("EACCES", "permission denied"),
        Some(17) => ("EEXIST", "file already exists"),
        Some(20) => ("ENOTDIR", "not a directory"),
        Some(21) => ("EISDIR", "illegal operation on a directory"),
        Some(24) => ("EMFILE", "too many open files"),
        Some(28) => ("ENOSPC", "no space left on device"),
        Some(30) => ("EROFS", "read-only file system"),
        Some(36) => ("ENAMETOOLONG", "name too long"),
        Some(39) => ("ENOTEMPTY", "directory not empty"),
        Some(40) => ("ELOOP", "too many symbolic links encountered"),
        _ => return error.to_string(),
    };
    format!("{code}: {text}, {syscall} '{path}'")
}

/// Whether the error carries the given errno (`ENOENT` and friends).
pub fn is_not_found(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

/// `path.posix.basename(path)`.
pub fn basename(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or("").to_string()
}

/// `hashStableFile`: SHA-256 of one regular file, failing when its identity or
/// extent changes while it is read.
pub fn hash_stable_file(path: &str) -> Result<(String, u64), String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let initial = file.metadata().map_err(|error| error.to_string())?;
    if !initial.is_file() {
        return Err(format!("Selected input must be a regular file: {path}"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut position: u64 = 0;
    while position <= initial.len() {
        let wanted = std::cmp::min(buffer.len() as u64, initial.len() - position + 1) as usize;
        let read = file.read(&mut buffer[..wanted]).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        position += read as u64;
        if position > initial.len() {
            return Err(format!("Selected input changed while being read: {path}"));
        }
    }
    let opened = file.metadata().map_err(|error| error.to_string())?;
    let current = std::fs::metadata(Path::new(path)).map_err(|error| error.to_string())?;
    let same = |a: &std::fs::Metadata, b: &std::fs::Metadata| {
        b.is_file()
            && a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.size() == b.size()
            && a.mode() == b.mode()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    };
    if position != initial.len() || !same(&initial, &opened) || !same(&initial, &current) {
        return Err(format!("Selected input changed while being read: {path}"));
    }
    Ok((hex::encode(hasher.finalize()), position))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_helpers_follow_node() {
        assert_eq!(join("/a/b", "c.apk"), "/a/b/c.apk");
        assert_eq!(join("/a/b", ".."), "/a");
        assert_eq!(basename("/data/local/tmp/"), "tmp");
        assert_eq!(basename("/"), "");
        assert_eq!(resolve("/x//y/./z/.."), "/x/y");
    }
}
