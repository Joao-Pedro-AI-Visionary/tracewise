//! Publication of a verified extraction (port of REA `FirmwarePublication.ts`
//! and the part of `SafeOutputTree.ts` it relies on).
//!
//! The caller's output directory must be absent; it is created exclusively
//! (mode 0700), regular files are written exclusively (mode 0600, no execute
//! bits) with exact size and digest verification plus a durable read-back, and
//! any failure rolls the whole tree back.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::error::ToolError;
use crate::firmware::files::{hash_file, FirmwareEntry};
use crate::firmware::reports::Normalized;
use crate::firmware::FwFailure;
use crate::fsutil::{basename, is_absolute, join, node_io_error, resolve};

const OP: &str = "extract_firmware";

/// `normalizeArtifactPath`: an untrusted logical path, without touching the filesystem.
fn normalize_artifact_path(input: &str) -> Result<String, String> {
    let drive_or_unc = {
        let bytes = input.as_bytes();
        (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
            || input.starts_with('\\')
            || input.starts_with("//")
    };
    if input.contains('\0') || input.contains('\\') || input.starts_with('/') || drive_or_unc {
        return Err(format!(
            "Artifact path is absolute or unsafe: {}",
            serde_json::to_string(input).unwrap_or_default()
        ));
    }
    let nfc: String = input.nfc().collect();
    let normalized = nfc.trim_end_matches('/').to_string();
    let bad = normalized.is_empty() || normalized.split('/').any(|p| p.is_empty() || p == "." || p == "..");
    if bad {
        return Err(format!(
            "Artifact path is not normalized: {}",
            serde_json::to_string(input).unwrap_or_default()
        ));
    }
    Ok(normalized)
}

/// Device and inode of a directory or file this call created (REA `DirectoryIdentity`).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
}

fn replaced_directory(path: &str) -> String {
    format!("Extraction directory identity changed: {path}")
}

fn replaced_file(path: &str) -> String {
    format!("Extraction file identity changed: {path}")
}

/// `readDirectoryIdentity`.
fn directory_identity(path: &str) -> Result<Identity, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| node_io_error(&e, "lstat", path))?;
    if !meta.is_dir() {
        return Err(replaced_directory(path));
    }
    Ok(Identity { dev: meta.dev(), ino: meta.ino() })
}

/// `assertPathIdentity`: the path is still the directory this call made.
fn assert_directory(path: &str, expected: Identity) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| node_io_error(&e, "lstat", path))?;
    if !meta.is_dir() || meta.dev() != expected.dev || meta.ino() != expected.ino {
        return Err(replaced_directory(path));
    }
    Ok(())
}

/// `assertFilePathIdentity`: the path is still the file this call created.
fn assert_file(path: &str, expected: Identity) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| node_io_error(&e, "lstat", path))?;
    if !meta.is_file() || meta.dev() != expected.dev || meta.ino() != expected.ino {
        return Err(replaced_file(path));
    }
    Ok(())
}

/// `destinationCaseCollisionMessage`: name the directory entry that differs from
/// the requested segment only by English (en-US) case.
fn destination_case_collision(requested_path: &str, existing_names: &[String]) -> Option<String> {
    let slash = requested_path.rfind('/');
    let segment = slash.map(|s| &requested_path[s + 1..]).unwrap_or(requested_path);
    if existing_names.iter().any(|name| name == segment) {
        return None;
    }
    let folded = segment.to_lowercase();
    let mut matches: Vec<&String> = existing_names.iter().filter(|name| name.to_lowercase() == folded).collect();
    matches.sort_by(|a, b| a.chars().cmp(b.chars()));
    let existing = matches.first()?;
    let parent = slash.map(|s| &requested_path[..=s]).unwrap_or("");
    Some(format!(
        "Destination filesystem cannot store both {requested_path} and {parent}{existing}; inventory retains both logical names."
    ))
}

/// `throwIfDestinationCaseCollision`.
fn check_case_collision(parent_directory: &str, logical_path: &str) -> Result<(), String> {
    let Ok(listing) = std::fs::read_dir(parent_directory) else { return Ok(()) };
    let names: Vec<String> = listing.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    match destination_case_collision(logical_path, &names) {
        Some(message) => Err(message),
        None => Ok(()),
    }
}

struct Tree {
    root: String,
    root_identity: Identity,
    /// Directories created under the root, in creation order.
    nested: Vec<(String, Identity)>,
    /// Files created, in creation order.
    files: Vec<(String, Identity)>,
    registry: HashSet<String>,
    directories: HashSet<String>,
}

impl Tree {
    fn create(output_root: &str) -> Result<Tree, String> {
        if !is_absolute(output_root) {
            return Err("Extraction output root must be absolute".to_string());
        }
        let requested = resolve(output_root);
        let name = basename(&requested);
        if name == "." || name == ".." {
            return Err("Invalid extraction output root".to_string());
        }
        let parent_of = Path::new(&requested).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| "/".to_string());
        let parent = std::fs::canonicalize(&parent_of)
            .map_err(|_| "Extraction output parent is unavailable".to_string())?
            .to_string_lossy()
            .into_owned();
        let canonical = join(&parent, &name);
        match std::fs::DirBuilder::new().mode(0o700).create(&canonical) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err("Extraction output root already exists".to_string())
            }
            Err(error) => return Err(node_io_error(&error, "mkdir", &canonical)),
        }
        let setup = || -> Result<Tree, String> {
            let root_identity = directory_identity(&canonical)?;
            std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| node_io_error(&e, "chmod", &canonical))?;
            assert_directory(&canonical, root_identity)?;
            Ok(Tree {
                root: canonical.clone(),
                root_identity,
                nested: Vec::new(),
                files: Vec::new(),
                registry: HashSet::new(),
                directories: HashSet::new(),
            })
        };
        match setup() {
            Ok(tree) => Ok(tree),
            Err(cause) => {
                // Only an empty root that still has the identity this call made is removed.
                let _ = std::fs::remove_dir(&canonical);
                Err(cause)
            }
        }
    }

    fn nested_identity(&self, path: &str) -> Option<Identity> {
        self.nested.iter().find(|(p, _)| p == path).map(|(_, id)| *id)
    }

    /// `#assertOwnedDirectories`.
    fn assert_owned(&self) -> Result<(), String> {
        assert_directory(&self.root, self.root_identity)?;
        for (path, identity) in &self.nested {
            assert_directory(path, *identity)?;
        }
        Ok(())
    }

    /// `#assertLineage`.
    fn assert_lineage(lineage: &[(String, Identity)]) -> Result<(), String> {
        for (path, identity) in lineage {
            assert_directory(path, *identity)?;
        }
        Ok(())
    }

    fn register(&mut self, path: &str) -> Result<(), String> {
        let parts: Vec<&str> = path.split('/').collect();
        let mut prefix = String::new();
        for (index, part) in parts.iter().enumerate() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            if index + 1 < parts.len() {
                if self.registry.contains(&prefix) {
                    return Err(format!("Artifact prefix conflict: {path}"));
                }
                self.directories.insert(prefix.clone());
            }
        }
        if self.registry.contains(path) {
            return Err(format!("Artifact path collision: {path}"));
        }
        if self.directories.contains(path) {
            return Err(format!("Artifact prefix conflict: {path}"));
        }
        self.registry.insert(path.to_string());
        Ok(())
    }

    /// `#prepareParent`: create the parent directories, returning the lineage
    /// (root first) with the identity of every directory.
    fn prepare_parent(&mut self, relative: &str) -> Result<Vec<(String, Identity)>, String> {
        let mut parts: Vec<&str> = relative.split('/').collect();
        parts.pop();
        let mut current = self.root.clone();
        let mut logical_parent = String::new();
        let mut lineage: Vec<(String, Identity)> = vec![(self.root.clone(), self.root_identity)];
        if parts.is_empty() {
            assert_directory(&self.root, self.root_identity)?;
        }
        for part in parts {
            let (parent_path, parent_identity) = lineage.last().cloned().ok_or_else(|| replaced_directory(&self.root))?;
            let logical = if logical_parent.is_empty() { part.to_string() } else { format!("{logical_parent}/{part}") };
            current = format!("{current}/{part}");
            assert_directory(&parent_path, parent_identity)?;
            let created = match std::fs::DirBuilder::new().mode(0o700).create(&current) {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(error) => return Err(node_io_error(&error, "mkdir", &current)),
            };
            if created {
                let identity = directory_identity(&current)?;
                self.nested.push((current.clone(), identity));
            } else {
                check_case_collision(&parent_path, &logical)?;
                let identity = self.nested_identity(&current).ok_or_else(|| replaced_directory(&current))?;
                assert_directory(&current, identity)?;
            }
            assert_directory(&parent_path, parent_identity)?;
            let identity = self.nested_identity(&current).ok_or_else(|| replaced_directory(&current))?;
            assert_directory(&current, identity)?;
            lineage.push((current.clone(), identity));
            logical_parent = logical;
        }
        Ok(lineage)
    }

    /// Stream one regular file with exact byte and digest verification.
    fn write(&mut self, relative: &str, source: &str, expected_sha: &str, expected_bytes: u64) -> Result<String, String> {
        let path = normalize_artifact_path(relative)?;
        self.register(&path)?;
        let lineage = self.prepare_parent(&path)?;
        let parent = lineage.last().map(|(p, _)| p.clone()).ok_or_else(|| replaced_directory(&self.root))?;
        let name = path.rsplit('/').next().unwrap_or(&path);
        let destination = format!("{parent}/{name}");
        let mut handle = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&destination)
        {
            Ok(handle) => handle,
            Err(_) => {
                check_case_collision(&parent, &path)?;
                return Err(format!("Could not exclusively create extraction path: {path}"));
            }
        };
        let file_meta = handle.metadata().map_err(|e| node_io_error(&e, "fstat", &destination))?;
        if !file_meta.is_file() {
            return Err(replaced_file(&destination));
        }
        let identity = Identity { dev: file_meta.dev(), ino: file_meta.ino() };
        self.files.push((destination.clone(), identity));
        Self::assert_lineage(&lineage)?;
        let mut input = std::fs::File::open(source).map_err(|e| node_io_error(&e, "open", source))?;
        let mut hasher = Sha256::new();
        let mut bytes: u64 = 0;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer).map_err(|e| node_io_error(&e, "read", source))?;
            if read == 0 {
                break;
            }
            if read as u64 > expected_bytes - bytes {
                return Err(format!("Extracted content exceeds the inventoried size: {path}"));
            }
            bytes += read as u64;
            hasher.update(&buffer[..read]);
            handle.write_all(&buffer[..read]).map_err(|_| "Extraction output stopped accepting bytes".to_string())?;
        }
        if bytes != expected_bytes {
            return Err(format!("Extracted content size disagrees with inventory: {path}"));
        }
        let sha256 = hex::encode(hasher.finalize());
        if sha256 != expected_sha {
            return Err(format!("Extracted content disagrees with inventory: {path}"));
        }
        Self::assert_lineage(&lineage)?;
        assert_file(&destination, identity)?;
        handle.sync_all().map_err(|e| node_io_error(&e, "fsync", &destination))?;
        drop(handle);
        let readback = hash_file(&destination)?;
        let size = std::fs::metadata(&destination).map(|m| m.len()).unwrap_or(0);
        Self::assert_lineage(&lineage)?;
        assert_file(&destination, identity)?;
        if readback != sha256 || size != bytes {
            return Err(format!("Durable readback verification failed: {path}"));
        }
        Ok(path)
    }

    /// Sync the owned output tree.
    fn commit(&self) -> Result<(), String> {
        self.assert_owned()?;
        let sync = || -> std::io::Result<()> {
            let root = std::fs::File::open(&self.root)?;
            root.sync_all()?;
            if let Some(parent) = Path::new(&self.root).parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        };
        sync().map_err(|_| "Could not durably sync extraction output".to_string())
    }

    /// `removeOwnedTree`: remove only the files and directories this call
    /// created, each re-verified by identity, and require every directory to be
    /// empty before it is removed. Anything unowned is left in place.
    fn remove_owned_tree(&mut self) -> Result<(), String> {
        let depth = |path: &str| path[self.root.len()..].split('/').count();
        let mut postorder: Vec<(String, Identity)> = self.nested.clone();
        postorder.sort_by_key(|(path, _)| std::cmp::Reverse(depth(path)));
        let files = self.files.clone();
        let files_in = |directory: &str| -> Vec<(String, Identity)> {
            files
                .iter()
                .filter(|(path, _)| Path::new(path).parent().map(|p| p.to_string_lossy() == directory).unwrap_or(false))
                .cloned()
                .collect()
        };
        let remove_files = |directory: &str, identity: Identity, owned: Vec<(String, Identity)>| -> Result<(), String> {
            for (path, file_identity) in owned {
                assert_directory(directory, identity)?;
                assert_file(&path, file_identity)?;
                std::fs::remove_file(&path).map_err(|e| node_io_error(&e, "unlink", &path))?;
            }
            Ok(())
        };
        let require_empty = |directory: &str| -> Result<(), String> {
            let count = std::fs::read_dir(directory).map_err(|e| node_io_error(&e, "scandir", directory))?.count();
            if count > 0 {
                return Err(format!("Unowned entries remain in extraction directory: {directory}"));
            }
            Ok(())
        };
        for (path, identity) in postorder {
            remove_files(&path, identity, files_in(&path))?;
            let parent_path = Path::new(&path).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
            let parent_identity = if parent_path == self.root {
                self.root_identity
            } else {
                self.nested_identity(&parent_path).ok_or_else(|| replaced_directory(&parent_path))?
            };
            assert_directory(&parent_path, parent_identity)?;
            assert_directory(&path, identity)?;
            require_empty(&path)?;
            std::fs::remove_dir(&path).map_err(|e| node_io_error(&e, "rmdir", &path))?;
            self.nested.retain(|(p, _)| p != &path);
        }
        remove_files(&self.root, self.root_identity, files_in(&self.root))?;
        assert_directory(&self.root, self.root_identity)?;
        require_empty(&self.root)?;
        std::fs::remove_dir(&self.root).map_err(|e| node_io_error(&e, "rmdir", &self.root))
    }

    /// Remove only this operation's unsealed tree and verify absence.
    fn rollback(&mut self) -> Result<(), String> {
        let removal = (|| -> Result<(), String> {
            self.assert_owned()?;
            self.remove_owned_tree()
        })();
        let absent = removal.is_ok() && std::fs::symlink_metadata(&self.root).is_err();
        if absent {
            return Ok(());
        }
        Err(format!(
            "Extraction output cleanup could not be verified{}",
            match removal {
                Err(reason) => format!(": {reason}"),
                Ok(()) => String::new(),
            }
        ))
    }
}

/// Publish verified regular files; links and special files stay metadata.
pub fn publish_extraction(
    output_directory: &str,
    entries: &[FirmwareEntry],
    normalized: &Normalized,
    selection: (u64, u64, &str),
    engine: &Value,
) -> Result<Value, FwFailure> {
    let materialized: HashSet<String> =
        entries.iter().filter(|e| e.kind == "file").map(|e| format!("$output/{}", e.relative_path)).collect();
    for path in normalized.files.keys() {
        if path != "$input" && !materialized.contains(path) {
            return Err(FwFailure::Typed(ToolError::Output {
                operation: OP.to_string(),
                reason: format!("Reported regular file is absent from materialized output: {path}"),
            }));
        }
    }
    let mut tree = Tree::create(output_directory).map_err(FwFailure::Other)?;
    let outcome = (|| -> Result<Value, FwFailure> {
        let mut files: Vec<Value> = Vec::new();
        let mut unpublished: Vec<Value> = Vec::new();
        for entry in entries {
            if entry.kind != "file" {
                unpublished.push(json!({
                    "relative_path": entry.relative_path,
                    "kind": entry.kind,
                    "link_target": entry.link_target,
                }));
                continue;
            }
            let logical = format!("$output/{}", entry.relative_path);
            let reported = normalized.files.get(&logical);
            let sha256 = hash_file(&entry.path).map_err(FwFailure::Other)?;
            let reported_mismatch = reported.and_then(|r| r.sha256.as_deref()).map(|s| s != sha256).unwrap_or(false);
            let size_mismatch = normalized.sizes.get(&logical).map(|s| *s != entry.size).unwrap_or(false);
            if reported_mismatch || size_mismatch {
                return Err(FwFailure::Typed(ToolError::Output {
                    operation: OP.to_string(),
                    reason: format!("Extracted bytes disagree with provider report: {}", entry.relative_path),
                }));
            }
            tree.write(&entry.relative_path, &entry.path, &sha256, entry.size).map_err(FwFailure::Other)?;
            files.push(json!({
                "relative_path": entry.relative_path,
                "path": join(&tree.root, &entry.relative_path),
                "size": entry.size,
                "sha256": sha256,
                "reported_sha256": reported.and_then(|r| r.sha256.clone()),
                "mime_type": reported.and_then(|r| r.mime_type.clone()),
                "analysis_depth": reported.map(|r| r.depth),
                "runtime_address": Value::Null,
                "original_file_range": Value::Null,
            }));
        }
        let published_bytes: u64 = files.iter().map(|f| f["size"].as_u64().unwrap_or(0)).sum();
        let coverage = if unpublished.is_empty() { normalized.coverage } else { "partial" };
        let result = json!({
            "engine": engine,
            "selection": { "offset": selection.0, "length": selection.1, "sha256": selection.2 },
            "output_directory": tree.root,
            "coverage": coverage,
            "files": files,
            "unpublished_entries": unpublished,
            "chunks": normalized.chunks.iter().map(|c| c.to_json()).collect::<Vec<_>>(),
            "derivations": normalized.derivations,
            "depth_limited_paths": normalized.depth_limited_paths,
            "diagnostics": normalized.diagnostics,
            "published_bytes": published_bytes,
        });
        tree.commit().map_err(FwFailure::Other)?;
        Ok(result)
    })();
    match outcome {
        Ok(result) => Ok(result),
        Err(cause) => match tree.rollback() {
            Ok(()) => Err(cause),
            Err(cleanup) => Err(FwFailure::Typed(ToolError::Cleanup {
                provider_id: "unblob".to_string(),
                operation: "close_binary".to_string(),
                resources: vec![output_directory.to_string()],
                diagnostics: json!({
                    "reason": cleanup,
                    "previous_error": match &cause {
                        FwFailure::Typed(error) => error.message(),
                        FwFailure::Other(message) => message.clone(),
                        FwFailure::Protocol => "Tool report violated the pinned producer protocol".to_string(),
                    },
                }),
                partial: None,
            })),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_normalization_matches_artifact_rules() {
        assert_eq!(normalize_artifact_path("a/b.txt").unwrap(), "a/b.txt");
        assert!(normalize_artifact_path("/etc/passwd").is_err());
        assert!(normalize_artifact_path("a/../b").is_err());
        assert!(normalize_artifact_path("a\\b").is_err());
        assert!(normalize_artifact_path("C:x").is_err());
        assert_eq!(normalize_artifact_path("e\u{301}/x").unwrap(), "\u{e9}/x");
    }

    #[test]
    fn case_collisions_name_the_existing_spelling() {
        let names = vec!["Readme.TXT".to_string(), "other".to_string()];
        assert_eq!(
            destination_case_collision("docs/readme.txt", &names).as_deref(),
            Some("Destination filesystem cannot store both docs/readme.txt and docs/Readme.TXT; inventory retains both logical names.")
        );
        assert_eq!(destination_case_collision("Readme.TXT", &names), None, "an exact match is the same logical name");
        assert_eq!(destination_case_collision("fresh", &names), None);
    }

    fn scratch(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("tw-publish-{name}-{}", crate::firmware::runner::random_uuid()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    fn write_source(dir: &str, name: &str, content: &[u8]) -> (String, String) {
        let path = format!("{dir}/{name}");
        std::fs::write(&path, content).unwrap();
        (path, hex::encode(Sha256::digest(content)))
    }

    #[test]
    fn rollback_removes_only_what_this_tree_created() {
        let scratch_dir = scratch("rollback");
        let (source, sha) = write_source(&scratch_dir, "payload", b"payload");
        let output = format!("{scratch_dir}/out");
        let mut tree = Tree::create(&output).unwrap();
        tree.write("a/b/file.bin", &source, &sha, 7).unwrap();
        tree.write("top.bin", &source, &sha, 7).unwrap();
        // An entry this call did not create appears inside an owned directory.
        std::fs::write(format!("{output}/a/foreign.txt"), b"not ours").unwrap();
        let error = tree.rollback().unwrap_err();
        assert!(error.contains("Unowned entries remain in extraction directory"), "{error}");
        assert!(std::path::Path::new(&format!("{output}/a/foreign.txt")).exists(), "the foreign file must survive");
        assert!(!std::path::Path::new(&format!("{output}/a/b")).exists(), "owned, now-empty directories are removed");
        // Like REA, the walk is deepest-first and the root's own files go last, so it stops here.
        let _ = std::fs::remove_dir_all(scratch_dir);
    }

    #[test]
    fn rollback_of_a_clean_tree_leaves_nothing() {
        let scratch_dir = scratch("clean");
        let (source, sha) = write_source(&scratch_dir, "payload", b"payload");
        let output = format!("{scratch_dir}/out");
        let mut tree = Tree::create(&output).unwrap();
        tree.write("x/y.bin", &source, &sha, 7).unwrap();
        tree.rollback().unwrap();
        assert!(!std::path::Path::new(&output).exists());
        let _ = std::fs::remove_dir_all(scratch_dir);
    }

    #[test]
    fn a_replaced_directory_is_detected_before_writing() {
        let scratch_dir = scratch("replaced");
        let (source, sha) = write_source(&scratch_dir, "payload", b"payload");
        let output = format!("{scratch_dir}/out");
        let mut tree = Tree::create(&output).unwrap();
        tree.write("d/one.bin", &source, &sha, 7).unwrap();
        // Swap the owned directory for another one with the same name (the original
        // is kept aside so the new directory cannot reuse its inode).
        std::fs::rename(format!("{output}/d"), format!("{output}/d.aside")).unwrap();
        std::fs::create_dir(format!("{output}/d")).unwrap();
        let error = tree.write("d/two.bin", &source, &sha, 7).unwrap_err();
        assert!(error.starts_with("Extraction directory identity changed:"), "{error}");
        let _ = std::fs::remove_dir_all(scratch_dir);
    }
}
