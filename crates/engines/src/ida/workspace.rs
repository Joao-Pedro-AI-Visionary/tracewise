//! The private input copy of a headless session (port of `IdaWorkspace.ts`).
//!
//! The upstream database and its sidecar files are written next to the opened input, so a
//! headless session opens a verified private copy and never the user's file.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::target::BinaryTarget;

use super::connection::IdaFault;

/// Read a file digest with bounded memory rather than retaining the bytes.
pub fn file_digest(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// `path.normalize` of Node on a POSIX host: resolve `.`, `..` and repeated separators,
/// keeping a trailing separator.
pub fn normalize_posix(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if matches!(stack.last(), Some(last) if *last != "..") {
                    stack.pop();
                } else if !absolute {
                    stack.push("..");
                }
            }
            other => stack.push(other),
        }
    }
    let mut out = stack.join("/");
    if out.is_empty() {
        if absolute {
            return "/".to_string();
        }
        out.push('.');
    }
    if trailing && !out.ends_with('/') {
        out.push('/');
    }
    if absolute {
        out.insert(0, '/');
    }
    out
}

/// Compare host-local paths.
pub fn same_host_path(left: &str, right: &str) -> bool {
    normalize_posix(left) == normalize_posix(right)
}

use crate::process::{random_hex, random_uuid};

/// Private input copy isolating upstream database and sidecar writes from the original.
pub struct IdaWorkspace {
    directory: PathBuf,
    pub input_path: String,
    pub session_id: String,
    target_path: String,
    target_sha256: String,
}

impl IdaWorkspace {
    /// Allocate a protected workspace so its owner can retain it before input preparation.
    pub fn allocate(target: &BinaryTarget, root: Option<&str>) -> std::io::Result<Self> {
        // Upstream reports canonical paths, so the private input path must already be
        // canonical for identity checks.
        let parent = match root {
            Some(root) => std::fs::canonicalize(normalize_posix(root))?,
            None => std::fs::canonicalize(std::env::temp_dir())?,
        };
        let mut directory = None;
        for _ in 0..16 {
            let candidate = parent.join(format!("rea-ida-{}", random_hex(6)));
            match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => {
                    directory = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let directory = directory
            .ok_or_else(|| std::io::Error::other("could not allocate a private IDA workspace"))?;
        let name = Path::new(&target.path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "target".to_string());
        let input_path = directory.join(name).to_string_lossy().to_string();
        Ok(Self {
            directory,
            input_path,
            session_id: format!("rea-{}", random_uuid()),
            target_path: target.path.clone(),
            target_sha256: target.sha256.clone(),
        })
    }

    /// Filesystem root owned exclusively by this headless session.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Copy and verify admitted bytes after the session owns this workspace's cleanup.
    pub fn copy_input(&self) -> Result<(), IdaFault> {
        let copy = || -> std::io::Result<String> {
            let mut source = std::fs::File::open(&self.target_path)?;
            let mode = source.metadata()?.permissions().mode() & 0o777;
            let mut destination = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode | 0o600)
                .open(&self.input_path)?;
            let mut buffer = vec![0u8; 1 << 20];
            loop {
                let n = source.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                destination.write_all(&buffer[..n])?;
            }
            destination.flush()?;
            file_digest(Path::new(&self.input_path))
        };
        let digest = copy().map_err(|e| {
            IdaFault::Other(format!("Cannot prepare the private IDA input copy: {e}"))
        })?;
        if digest != self.target_sha256 {
            return Err(IdaFault::protocol(
                "IDA target changed between admission and the private input copy; reopen the target.",
            ));
        }
        Ok(())
    }

    /// Delete only this object's privately allocated directory after worker cleanup.
    pub fn remove(&self) -> std::io::Result<()> {
        match std::fs::remove_dir_all(&self.directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_matches_node_path_normalize() {
        assert_eq!(normalize_posix("/a/./b//c/../d"), "/a/b/d");
        assert_eq!(normalize_posix("/a/b/"), "/a/b/");
        assert_eq!(normalize_posix("a/../.."), "..");
        assert_eq!(normalize_posix("/.."), "/");
        assert_eq!(normalize_posix(""), ".");
        assert!(same_host_path("/tmp/x/./y", "/tmp/x/y"));
        assert!(!same_host_path("/tmp/x/y", "/tmp/x/z"));
    }
}
