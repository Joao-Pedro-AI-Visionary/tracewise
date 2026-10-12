//! Port of REA `process/capture/FilesystemSnapshot.ts` and
//! `ProcessFilesystemEffects.ts`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::scenario::{errno_name, resolve_lexical, ProcessScenario};
use crate::error::JsError;

#[derive(Debug, Clone, PartialEq)]
pub struct FileState {
    pub path: String,
    pub kind: &'static str,
    pub mode: u64,
    pub size: u64,
    pub sha256: Option<String>,
    pub symlink_target: Option<String>,
}

impl FileState {
    pub fn to_value(&self) -> Value {
        json!({
            "path": self.path,
            "mode": self.mode,
            "size": self.size,
            "type": self.kind,
            "sha256": self.sha256,
            "symlink_target": self.symlink_target,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HashOmission {
    pub path: String,
    pub size_bytes: u64,
    pub remaining_budget_bytes: u64,
    pub reason: &'static str,
    pub system_code: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FilesystemCoverage {
    pub files_limit: u64,
    pub depth_limit: u64,
    pub enumeration_truncated: bool,
    pub enumeration_reasons: Vec<&'static str>,
    pub hash_budget_bytes: u64,
    pub hashed_bytes: u64,
    pub hash_omissions: Vec<HashOmission>,
}

impl FilesystemCoverage {
    pub fn to_value(&self) -> Value {
        json!({
            "files_limit": self.files_limit,
            "depth_limit": self.depth_limit,
            "enumeration_truncated": self.enumeration_truncated,
            "enumeration_reasons": self.enumeration_reasons,
            "hash_budget_bytes": self.hash_budget_bytes,
            "hashed_bytes": self.hashed_bytes,
            "hash_omissions": self.hash_omissions.iter().map(|o| json!({
                "path": o.path,
                "size_bytes": o.size_bytes,
                "remaining_budget_bytes": o.remaining_budget_bytes,
                "reason": o.reason,
                "system_code": o.system_code,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn truncated(&self) -> bool {
        self.enumeration_truncated || !self.hash_omissions.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct FilesystemSnapshot {
    pub files: Vec<FileState>,
    pub truncated: bool,
    pub complete_roots: Vec<String>,
    pub coverage: FilesystemCoverage,
}

pub fn files_value(files: &[FileState]) -> Value {
    Value::Array(files.iter().map(FileState::to_value).collect())
}

fn same_file_state(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.is_file()
        && b.is_file()
        && a.mode() == b.mode()
        && a.size() == b.size()
        && (a.mtime(), a.mtime_nsec()) == (b.mtime(), b.mtime_nsec())
        && (a.ctime(), a.ctime_nsec()) == (b.ctime(), b.ctime_nsec())
}

fn same_identity(a: &Metadata, b: &Metadata, directory: bool) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && if directory { b.is_dir() } else { b.file_type().is_symlink() }
}

fn unavailable_code(error: &std::io::Error) -> Option<String> {
    let code = error.raw_os_error()?;
    [libc::EACCES, libc::EISDIR, libc::ELOOP, libc::ENOTDIR, libc::ENOENT, libc::EPERM, libc::ESTALE]
        .contains(&code)
        .then(|| errno_name(code).to_string())
}

enum HashOutcome {
    Hashed(String),
    Omitted(&'static str, Option<String>),
}

fn hash_file(path: &Path, expected: &Metadata, max_bytes: u64) -> Result<HashOutcome, JsError> {
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) => {
            return match unavailable_code(&error) {
                Some(code) => Ok(HashOutcome::Omitted("file_unavailable", Some(code))),
                None => Err(JsError::Io(error.to_string())),
            }
        }
    };
    let read = |file: &mut File| -> std::io::Result<HashOutcome> {
        let stats = file.metadata()?;
        if !same_file_state(expected, &stats) || stats.size() > max_bytes {
            return Ok(HashOutcome::Omitted("file_changed_or_short_read", None));
        }
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; (64 * 1024).min(max_bytes.max(1) as usize)];
        let mut position = 0u64;
        while position < stats.size() {
            let want = buffer.len().min((stats.size() - position) as usize);
            let n = file.read(&mut buffer[..want])?;
            if n == 0 {
                return Ok(HashOutcome::Omitted("file_changed_or_short_read", None));
            }
            hasher.update(&buffer[..n]);
            position += n as u64;
        }
        let after = file.metadata()?;
        if !same_file_state(&stats, &after) {
            return Ok(HashOutcome::Omitted("file_changed_or_short_read", None));
        }
        Ok(HashOutcome::Hashed(hex::encode(hasher.finalize())))
    };
    match read(&mut file) {
        Ok(outcome) => Ok(outcome),
        Err(error) => match unavailable_code(&error) {
            Some(code) => Ok(HashOutcome::Omitted("file_unavailable", Some(code))),
            None => Err(JsError::Io(error.to_string())),
        },
    }
}

fn lstat_if_present(path: &Path) -> Result<Option<Metadata>, JsError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(error) => Err(JsError::Io(error.to_string())),
    }
}

struct Walk<'a> {
    scenario: &'a ProcessScenario,
    entries: Vec<FileState>,
    remaining_bytes: u64,
    pending_names: u64,
    truncated: bool,
    /// Enumeration reasons in first-insertion order (a JavaScript Set).
    reasons: Vec<&'static str>,
    omissions: Vec<HashOmission>,
}

fn relative(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) if rel.as_os_str().is_empty() => ".".into(),
        Ok(rel) => rel.to_string_lossy().into_owned(),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

impl Walk<'_> {
    fn reason(&mut self, name: &'static str) {
        if !self.reasons.contains(&name) {
            self.reasons.push(name);
        }
    }

    fn visit(&mut self, root: &Path, alias: &str, path: &Path, depth: u64) -> Result<bool, JsError> {
        let limits = &self.scenario.limits;
        if self.entries.len() as u64 >= limits.files || depth > limits.filesystem_depth {
            self.truncated = true;
            if self.entries.len() as u64 >= limits.files {
                self.reason("files_limit");
            }
            if depth > limits.filesystem_depth {
                self.reason("depth_limit");
            }
            return Ok(false);
        }
        let Some(stats) = lstat_if_present(path)? else { return Ok(true) };
        let rel = format!("{alias}:{}", relative(root, path));
        if stats.file_type().is_symlink() {
            let link = std::fs::read_link(path).map_err(|e| JsError::Io(e.to_string()))?;
            let parent = path.parent().unwrap_or(Path::new("/"));
            let target = resolve_lexical(parent, &link.to_string_lossy());
            let after = std::fs::symlink_metadata(path).map_err(|e| JsError::Io(e.to_string()))?;
            if !same_identity(&stats, &after, false) {
                self.truncated = true;
                self.reason("identity_changed");
                return Ok(false);
            }
            self.entries.push(FileState {
                path: rel,
                kind: "symlink",
                mode: stats.mode() as u64,
                size: stats.size(),
                sha256: None,
                symlink_target: Some(target.to_string_lossy().into_owned()),
            });
            return Ok(true);
        }
        if stats.is_file() {
            let mut sha256 = None;
            let mut omission = None;
            if self.remaining_bytes < stats.size() {
                omission = Some(HashOmission {
                    path: rel.clone(),
                    size_bytes: stats.size(),
                    remaining_budget_bytes: self.remaining_bytes,
                    reason: "file_bytes_budget",
                    system_code: None,
                });
            } else {
                match hash_file(path, &stats, self.remaining_bytes)? {
                    HashOutcome::Hashed(digest) => {
                        sha256 = Some(digest);
                        self.remaining_bytes -= stats.size();
                    }
                    HashOutcome::Omitted(reason, system_code) => {
                        omission = Some(HashOmission {
                            path: rel.clone(),
                            size_bytes: stats.size(),
                            remaining_budget_bytes: self.remaining_bytes,
                            reason,
                            system_code,
                        })
                    }
                }
            }
            if let Some(omission) = omission {
                self.truncated = true;
                self.omissions.push(omission);
            }
            self.entries.push(FileState {
                path: rel,
                kind: "file",
                mode: stats.mode() as u64,
                size: stats.size(),
                sha256,
                symlink_target: None,
            });
            return Ok(true);
        }
        let directory = stats.is_dir();
        self.entries.push(FileState {
            path: rel,
            kind: if directory { "directory" } else { "other" },
            mode: stats.mode() as u64,
            size: stats.size(),
            sha256: None,
            symlink_target: None,
        });
        if !directory {
            return Ok(true);
        }
        let mut children: Vec<std::ffi::OsString> = Vec::new();
        let mut complete = true;
        let remaining_entries = limits.files as i128 - self.entries.len() as i128 - self.pending_names as i128;
        let reader = std::fs::read_dir(path).map_err(|e| JsError::Io(e.to_string()))?;
        for child in reader {
            let child = child.map_err(|e| JsError::Io(e.to_string()))?;
            if children.len() as i128 >= remaining_entries || depth >= limits.filesystem_depth {
                self.truncated = true;
                complete = false;
                if children.len() as i128 >= remaining_entries {
                    self.reason("files_limit");
                }
                if depth >= limits.filesystem_depth {
                    self.reason("depth_limit");
                }
                break;
            }
            children.push(child.file_name());
            self.pending_names += 1;
        }
        let after = std::fs::symlink_metadata(path).map_err(|e| JsError::Io(e.to_string()))?;
        if !same_identity(&stats, &after, true) {
            self.pending_names -= children.len() as u64;
            self.truncated = true;
            self.reason("identity_changed");
            return Ok(false);
        }
        // JavaScript default sort compares UTF-16 code units; for the BMP this
        // equals byte order of the UTF-8 encoding except surrogate ranges.
        let mut names: Vec<String> = children.iter().map(|c| c.to_string_lossy().into_owned()).collect();
        names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        for name in names {
            self.pending_names -= 1;
            if !self.visit(root, alias, &path.join(&name), depth + 1)? {
                complete = false;
            }
        }
        Ok(complete)
    }
}

/// Capture bounded, root-aliased filesystem state without following symlinks.
pub fn snapshot_roots(scenario: &ProcessScenario) -> Result<FilesystemSnapshot, JsError> {
    let mut walk = Walk {
        scenario,
        entries: Vec::new(),
        remaining_bytes: scenario.limits.file_bytes,
        pending_names: 0,
        truncated: false,
        reasons: Vec::new(),
        omissions: Vec::new(),
    };
    let mut complete_roots = Vec::new();
    for (index, root) in scenario.filesystem_observation_paths.iter().enumerate() {
        let alias = format!("root_{index}");
        let root_path = PathBuf::from(root);
        if lstat_if_present(&root_path)?.is_none() {
            complete_roots.push(alias);
            continue;
        }
        if walk.visit(&root_path, &alias, &root_path, 0)? {
            complete_roots.push(alias);
        }
    }
    let enumeration_reasons = walk.reasons.clone();
    Ok(FilesystemSnapshot {
        coverage: FilesystemCoverage {
            files_limit: scenario.limits.files,
            depth_limit: scenario.limits.filesystem_depth,
            enumeration_truncated: complete_roots.len() != scenario.filesystem_observation_paths.len(),
            enumeration_reasons,
            hash_budget_bytes: scenario.limits.file_bytes,
            hashed_bytes: scenario.limits.file_bytes - walk.remaining_bytes,
            hash_omissions: walk.omissions,
        },
        files: walk.entries,
        truncated: walk.truncated,
        complete_roots,
    })
}

fn unobserved_absence_reason(
    path: &str,
    phase: &str,
    complete_roots: &HashSet<&str>,
    files: &HashMap<&str, &FileState>,
) -> Option<String> {
    let alias = &path[..path.find(':').unwrap_or(0)];
    if !complete_roots.contains(alias) {
        return Some(format!(
            "The {phase} snapshot did not exhaust path enumeration under {alias}; absence remains unknown."
        ));
    }
    let root_path = format!("{alias}:.");
    if path != root_path && files.get(root_path.as_str()).is_some_and(|f| f.kind == "symlink") {
        return Some(format!(
            "The {phase} snapshot did not follow the symbolic link at {root_path}; descendant absence remains unknown."
        ));
    }
    let mut index = path.rfind('/');
    while let Some(i) = index {
        if i == 0 {
            break;
        }
        let parent = &path[..i];
        if files.get(parent).is_some_and(|f| f.kind == "symlink") {
            return Some(format!(
                "The {phase} snapshot did not follow the symbolic link at {parent}; descendant absence remains unknown."
            ));
        }
        index = path[..i].rfind('/');
    }
    None
}

/// Classify effects only from observed path absence, metadata, and content hashes.
pub fn classify_effects(before: &FilesystemSnapshot, after: &FilesystemSnapshot) -> Vec<Value> {
    let before_by: HashMap<&str, &FileState> = before.files.iter().map(|f| (f.path.as_str(), f)).collect();
    let after_by: HashMap<&str, &FileState> = after.files.iter().map(|f| (f.path.as_str(), f)).collect();
    let before_complete: HashSet<&str> = before.complete_roots.iter().map(String::as_str).collect();
    let after_complete: HashSet<&str> = after.complete_roots.iter().map(String::as_str).collect();
    let mut paths: Vec<&str> = before_by.keys().chain(after_by.keys()).copied().collect::<BTreeSet<_>>().into_iter().collect();
    paths.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    paths
        .into_iter()
        .map(|path| {
            let b = before_by.get(path).copied();
            let a = after_by.get(path).copied();
            let bv = b.map_or(Value::Null, FileState::to_value);
            let av = a.map_or(Value::Null, FileState::to_value);
            let reason = if b.is_none() {
                unobserved_absence_reason(path, "before", &before_complete, &before_by)
            } else if a.is_none() {
                unobserved_absence_reason(path, "after", &after_complete, &after_by)
            } else {
                None
            };
            if let Some(reason) = reason {
                return json!({"path": path, "status": "unknown", "before": bv, "after": av, "reason": reason});
            }
            let (Some(b), Some(a)) = (b, a) else {
                let status = if b.is_none() { "created" } else { "deleted" };
                return json!({"path": path, "status": status, "before": bv, "after": av});
            };
            let metadata_changed = b.kind != a.kind || b.mode != a.mode || b.size != a.size || b.symlink_target != a.symlink_target;
            if !metadata_changed && b.kind == "file" && a.kind == "file" && (b.sha256.is_none() || a.sha256.is_none()) {
                return json!({"path": path, "status": "unknown", "before": bv, "after": av,
                    "reason": "A file content hash is unavailable in at least one snapshot; matching metadata does not establish unchanged contents."});
            }
            let status = if metadata_changed || b.sha256 != a.sha256 { "modified" } else { "unchanged" };
            json!({"path": path, "status": status, "before": bv, "after": av})
        })
        .collect()
}
