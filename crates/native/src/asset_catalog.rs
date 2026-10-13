//! `inspect_asset_catalog` (REA `artifacts/apple/AppleAssetCatalogAnalysis.ts` and
//! `domain/apple/appleAssetCatalog.ts`): compiled `Assets.car` metadata of an app bundle and the
//! join of Interface Builder resource keys to catalog renditions.
//!
//! REA runs `assetutil --info` (macOS only). Here the catalog is decoded in-process by
//! [`crate::car`]; discovery, hashing, paging and the key join are ported unchanged.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::car::{read_catalog, CATALOG_LIMITATION};
use crate::error::{ArtifactReason, NativeError, NativeResult};
use crate::ib::{analyze_interface_builder_bundle, InterfaceBuilderLimits};

const OPERATION: &str = "inspect_asset_catalog";
const MAX_CATALOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const RESOURCE_KEY_FIELDS: [&str; 9] = [
    "image",
    "imageName",
    "image_name",
    "resourceName",
    "resource_name",
    "assetName",
    "asset_name",
    "UIImageName",
    "NSImageName",
];

fn artifact(reason: ArtifactReason, detail: impl Into<String>) -> NativeError {
    NativeError::artifact(OPERATION, reason, detail)
}

fn io_code(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "ENOENT",
        std::io::ErrorKind::PermissionDenied => "EACCES",
        _ => "EIO",
    }
}

enum EntryKind {
    File,
    Directory,
    Symlink,
}

struct Entry {
    path: String,
    kind: EntryKind,
    absolute: PathBuf,
    size: u64,
}

/// Entries named `*Assets.car` in the order `DirectoryArtifactReader` yields them: each
/// directory lists its entries (sorted by name, as APFS returns them) before descending into its
/// subdirectories in that same order.
fn find_catalogs(root: &Path) -> NativeResult<Vec<Entry>> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut children: Vec<_> = fs::read_dir(&directory)
            .map_err(|e| {
                artifact(ArtifactReason::Io, format!("Could not open directory at {} ({})", directory.display(), io_code(&e)))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                artifact(ArtifactReason::Io, format!("Could not read directory at {} ({})", directory.display(), io_code(&e)))
            })?;
        children.sort_by_key(|child| child.file_name());
        let mut subdirectories = Vec::new();
        for child in children {
            let absolute = child.path();
            let metadata = fs::symlink_metadata(&absolute).map_err(|e| {
                artifact(ArtifactReason::Io, format!("Could not inspect entry at {} ({})", absolute.display(), io_code(&e)))
            })?;
            let kind = if metadata.file_type().is_symlink() {
                EntryKind::Symlink
            } else if metadata.is_dir() {
                EntryKind::Directory
            } else if metadata.is_file() {
                EntryKind::File
            } else {
                continue;
            };
            let relative = absolute
                .strip_prefix(root)
                .map(|p| p.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/"))
                .unwrap_or_default();
            if relative.ends_with("Assets.car") {
                found.push(Entry { path: relative.clone(), kind: match kind {
                    EntryKind::File => EntryKind::File,
                    EntryKind::Directory => EntryKind::Directory,
                    EntryKind::Symlink => EntryKind::Symlink,
                }, absolute: absolute.clone(), size: metadata.len() });
            }
            if matches!(kind, EntryKind::Directory) {
                subdirectories.push(absolute);
            }
        }
        subdirectories.reverse();
        pending.extend(subdirectories);
    }
    Ok(found)
}

fn read_catalog_bytes(entry: &Entry) -> NativeResult<Vec<u8>> {
    if entry.size > MAX_CATALOG_BYTES {
        return Err(artifact(
            ArtifactReason::Limit,
            format!("Asset catalog exceeds {MAX_CATALOG_BYTES} bytes: {}", entry.path),
        ));
    }
    let mut file = crate::dylib::open_nofollow(&entry.absolute).map_err(|e| {
        artifact(ArtifactReason::Io, format!("Could not open entry at {} ({})", entry.absolute.display(), io_code(&e)))
    })?;
    let mut data = Vec::with_capacity(entry.size as usize);
    (&mut file).take(MAX_CATALOG_BYTES + 1).read_to_end(&mut data).map_err(|e| {
        artifact(ArtifactReason::Io, format!("Could not read entry at {} ({})", entry.absolute.display(), io_code(&e)))
    })?;
    if data.len() as u64 > MAX_CATALOG_BYTES {
        return Err(artifact(ArtifactReason::Limit, format!("Asset catalog exceeds byte limit: {}", entry.path)));
    }
    Ok(data)
}

struct ResourceReference {
    source_node_id: String,
    source_path: String,
    source_archive_sha256: String,
    field: String,
    key: String,
}

fn collect_interface_builder_resource_keys(nodes: &[Value]) -> Vec<ResourceReference> {
    let mut out = Vec::new();
    for node in nodes {
        let evidence = node.get("evidence").and_then(Value::as_array);
        let source = evidence.and_then(|items| {
            items.iter().find(|item| {
                item.get("artifact_path").map(|v| !v.is_null()).unwrap_or(false)
                    && item.get("artifact_sha256").map(|v| !v.is_null()).unwrap_or(false)
            })
        });
        let (Some(path), Some(sha)) = (
            source.and_then(|s| s.get("artifact_path")).and_then(Value::as_str),
            source.and_then(|s| s.get("artifact_sha256")).and_then(Value::as_str),
        ) else {
            continue;
        };
        let Some(attributes) = node.get("attributes").and_then(Value::as_object) else { continue };
        for (field, value) in attributes {
            if !RESOURCE_KEY_FIELDS.contains(&field.as_str()) {
                continue;
            }
            if let Some(key) = value.as_str().filter(|k| !k.is_empty()) {
                out.push(ResourceReference {
                    source_node_id: node.get("id").and_then(Value::as_str).unwrap_or("").to_string(),
                    source_path: path.to_string(),
                    source_archive_sha256: sha.to_string(),
                    field: field.clone(),
                    key: key.to_string(),
                });
            }
        }
    }
    out
}

struct Catalog {
    path: String,
    sha256: String,
    records: Vec<Value>,
}

pub struct AssetCatalogRequest<'a> {
    pub bundle_path: &'a Path,
    pub target_sha256: &'a str,
    pub offset: u64,
    pub limit: u64,
}

pub fn analyze_asset_catalogs(request: &AssetCatalogRequest<'_>) -> NativeResult<Value> {
    let root = fs::canonicalize(request.bundle_path).map_err(|e| {
        artifact(
            ArtifactReason::Io,
            format!("Could not resolve artifact root at {} ({})", request.bundle_path.display(), io_code(&e)),
        )
    })?;
    let mut catalogs: Vec<Catalog> = Vec::new();
    let mut uninspected: Vec<String> = Vec::new();
    let mut total_metadata_bytes = 0u64;
    for entry in find_catalogs(&root)? {
        match entry.kind {
            EntryKind::File => {}
            EntryKind::Directory => {
                uninspected.push(format!("{} (directory)", entry.path));
                continue;
            }
            EntryKind::Symlink => {
                uninspected.push(format!("{} (symlink)", entry.path));
                continue;
            }
        }
        let data = read_catalog_bytes(&entry)?;
        let sha256 = hex::encode(Sha256::digest(&data));
        let records = read_catalog(&data).map_err(|error| {
            artifact(ArtifactReason::Format, format!("Asset catalog could not be decoded: {} ({error})", entry.path))
        })?;
        total_metadata_bytes += serde_json::to_string(&records).map(|text| text.len() as u64).unwrap_or(0);
        if total_metadata_bytes > MAX_TOTAL_METADATA_BYTES {
            return Err(artifact(
                ArtifactReason::Limit,
                format!("Combined asset catalog metadata exceeds {MAX_TOTAL_METADATA_BYTES} bytes"),
            ));
        }
        catalogs.push(Catalog { path: entry.path, sha256, records });
    }
    if catalogs.is_empty() && !uninspected.is_empty() {
        return Err(artifact(
            ArtifactReason::Path,
            format!("Asset catalog entries are not regular files and were not inspected: {}", uninspected.join(", ")),
        ));
    }
    let interface_builder = analyze_interface_builder_bundle(&root, request.target_sha256, InterfaceBuilderLimits::default())?;
    let graph_nodes: Vec<Value> = interface_builder["graph"]["nodes"].as_array().cloned().unwrap_or_default();
    let references = collect_interface_builder_resource_keys(&graph_nodes);
    let truncated_graph = interface_builder["graph"]["truncated"] == json!(true);

    // --- projectAppleAssetCatalogPage
    struct Row {
        catalog_path: String,
        catalog_sha256: String,
        index: u64,
        kind: &'static str,
        asset_name: Option<String>,
        rendition_name: Option<String>,
        metadata: Value,
    }
    let mut all: Vec<Row> = Vec::new();
    for catalog in &catalogs {
        for (index, metadata) in catalog.records.iter().enumerate() {
            let rendition_name = metadata.get("RenditionName").and_then(Value::as_str).map(String::from);
            let asset_name = metadata.get("Name").and_then(Value::as_str).map(String::from);
            let is_rendition = rendition_name.is_some() || asset_name.is_some();
            all.push(Row {
                catalog_path: catalog.path.clone(),
                catalog_sha256: catalog.sha256.clone(),
                index: index as u64,
                kind: if is_rendition { "rendition" } else { "catalog" },
                asset_name,
                rendition_name,
                metadata: metadata.clone(),
            });
        }
    }
    let start = (request.offset as usize).min(all.len());
    let end = (start + request.limit as usize).min(all.len());
    let records: Vec<Value> = all[start..end]
        .iter()
        .map(|row| {
            json!({
                "catalog_path": row.catalog_path,
                "catalog_sha256": row.catalog_sha256,
                "index": row.index,
                "kind": row.kind,
                "asset_name": row.asset_name,
                "rendition_name": row.rendition_name,
                "metadata": row.metadata,
            })
        })
        .collect();
    let next = request.offset as usize + records.len();
    let mut by_asset_name: std::collections::HashMap<&str, Vec<&Row>> = std::collections::HashMap::new();
    for row in &all {
        if row.kind != "rendition" {
            continue;
        }
        if let Some(name) = &row.asset_name {
            by_asset_name.entry(name.as_str()).or_default().push(row);
        }
    }
    let matches: Vec<Value> = references
        .iter()
        .map(|source| {
            let hits = by_asset_name.get(source.key.as_str()).cloned().unwrap_or_default();
            json!({
                "source_node_id": source.source_node_id,
                "source_path": source.source_path,
                "source_archive_sha256": source.source_archive_sha256,
                "field": source.field,
                "key": source.key,
                "status": match hits.len() { 0 => "unmatched", 1 => "matched", _ => "ambiguous" },
                "renditions": hits.iter().map(|row| json!({
                    "catalog_path": row.catalog_path,
                    "catalog_sha256": row.catalog_sha256,
                    "record_index": row.index,
                    "rendition_name": row.rendition_name,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut limitations: Vec<String> = vec![
        "Rendition metadata follows the field names of Apple's assetutil but is decoded by the native catalog reader; private fields and platform-specific interpretations are not normalized.".to_string(),
        "Asset catalog inspection does not decode or extract rendition image bytes.".to_string(),
        CATALOG_LIMITATION.to_string(),
    ];
    if catalogs.is_empty() {
        limitations.push("No compiled Assets.car catalog was found among the app bundle's regular files (symlinks are not followed); any resource keys are reported as unmatched.".to_string());
    }
    if !uninspected.is_empty() {
        limitations.push(format!(
            "Asset catalog entries that are not regular files were not inspected, so resource keys reported as unmatched may resolve there: {}",
            uninspected.join(", ")
        ));
    }
    limitations.push("Exact resource-key joins use only recognized image or asset key fields on decoded Interface Builder resource objects; other archive resource references are not inferred.".to_string());
    if truncated_graph {
        limitations.push("Interface Builder resource-key joins may be incomplete because the decoded UI graph was truncated.".to_string());
    }
    let mut result = Map::new();
    result.insert("target_sha256".into(), json!(request.target_sha256));
    result.insert(
        "catalogs".into(),
        Value::Array(
            catalogs
                .iter()
                .map(|c| json!({"path": c.path, "sha256": c.sha256, "record_count": c.records.len()}))
                .collect(),
        ),
    );
    result.insert("total_records".into(), json!(all.len()));
    result.insert("offset".into(), json!(request.offset));
    result.insert("limit".into(), json!(request.limit));
    result.insert("records".into(), Value::Array(records));
    result.insert("resource_key_matches".into(), Value::Array(matches));
    result.insert("next_offset".into(), if next < all.len() { json!(next) } else { Value::Null });
    result.insert("truncated".into(), json!(request.offset > 0 || next < all.len()));
    result.insert("limitations".into(), json!(limitations));
    Ok(Value::Object(result))
}
