//! Read inventoried JavaScript sources from a directory application root.

use std::collections::BTreeSet;
use std::path::Path;

use crate::error::JsError;
use crate::hash::hash_bytes;

#[derive(Clone, Debug)]
pub struct ApplicationSourceFile {
    pub path: String,
    pub sha256: String,
    pub text: String,
}

/// Collect UTF-8 `.js` sources and `package.json` under a directory root.
pub fn read_directory_sources(root: &Path) -> Result<Vec<ApplicationSourceFile>, JsError> {
    let mut paths = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let rel = entry
            .path()
            .strip_prefix(root)
            .map_err(|e| JsError::InvalidInput(e.to_string()))?;
        let logical = normalize_rel_path(rel)?;
        if logical == "package.json" || logical.ends_with(".js") {
            paths.push((logical, entry.path().to_path_buf()));
        }
    }
    paths.sort_by(|a, b| crate::unicode::compare_unicode_code_points(&a.0, &b.0));
    let mut out = Vec::new();
    for (logical, absolute) in paths {
        let bytes = std::fs::read(&absolute)?;
        let digest = hash_bytes(&bytes);
        let text = String::from_utf8(bytes).map_err(|_| {
            JsError::InvalidInput(format!("{logical} is not valid UTF-8"))
        })?;
        out.push(ApplicationSourceFile {
            path: logical,
            sha256: digest.sha256,
            text,
        });
    }
    Ok(out)
}

pub fn module_path_set(files: &[ApplicationSourceFile]) -> BTreeSet<String> {
    files
        .iter()
        .filter(|f| f.path.ends_with(".js"))
        .map(|f| f.path.clone())
        .collect()
}

fn normalize_rel_path(rel: &Path) -> Result<String, JsError> {
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            std::path::Component::Normal(p) => parts.push(p.to_string_lossy().to_string()),
            std::path::Component::CurDir => {}
            _ => return Err(JsError::InvalidInput("unsupported path component".into())),
        }
    }
    Ok(parts.join("/"))
}
