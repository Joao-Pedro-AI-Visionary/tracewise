//! Binwalk and Unblob report normalization (port of REA `FirmwareReports.ts`).
//!
//! Zod parse failures become [`FwFailure::Protocol`] ("Tool report violated the
//! pinned producer protocol"); semantic refusals are `AnalysisOutputError`s.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};

use crate::error::ToolError;
use crate::firmware::collate::utf16_order;
use crate::firmware::files::logical_path;
use crate::firmware::FwFailure;

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// A zod parse failure (the shape of the pinned report was violated).
struct Zod;

type Z<T> = Result<T, Zod>;

fn obj(value: &Value) -> Z<&Map<String, Value>> {
    value.as_object().ok_or(Zod)
}

fn field<'a>(map: &'a Map<String, Value>, key: &str) -> Z<&'a Value> {
    map.get(key).ok_or(Zod)
}

fn string(value: &Value) -> Z<&str> {
    value.as_str().ok_or(Zod)
}

fn boolean(value: &Value) -> Z<bool> {
    value.as_bool().ok_or(Zod)
}

fn array(value: &Value) -> Z<&Vec<Value>> {
    value.as_array().ok_or(Zod)
}

/// `z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)`.
fn integer(value: &Value) -> Z<u64> {
    let number = value.as_f64().filter(|_| value.is_number()).ok_or(Zod)?;
    if number.fract() != 0.0 || !number.is_finite() || !(0.0..=MAX_SAFE).contains(&number) {
        return Err(Zod);
    }
    Ok(number as u64)
}

fn bounded_int(value: &Value, max: u64) -> Z<u64> {
    let n = integer(value)?;
    if n > max {
        return Err(Zod);
    }
    Ok(n)
}

fn digest(value: &Value) -> Z<&str> {
    let text = string(value)?;
    if text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(text)
    } else {
        Err(Zod)
    }
}

fn nullable_string(value: &Value) -> Z<Option<&str>> {
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(string(value)?))
    }
}

fn output_error(operation: &str, reason: impl Into<String>) -> FwFailure {
    FwFailure::Typed(ToolError::Output { operation: operation.to_string(), reason: reason.into() })
}

fn zod(_: Zod) -> FwFailure {
    FwFailure::Protocol
}

// ------------------------------------------------------------------ binwalk --

/// `normalizeBinwalkReport`: regions as reported, lengths never validated.
pub fn normalize_binwalk(raw: &Value, input_path: &str, size: u64) -> Result<Vec<Value>, FwFailure> {
    const OP: &str = "inspect_firmware_regions";
    let records = array(raw).map_err(zod)?;
    let mut analyses: Vec<(String, Vec<Hit>, usize)> = Vec::new();
    for record in records {
        let analysis = (|| -> Z<(String, Vec<Hit>, usize)> {
            let analysis = obj(field(obj(record)?, "Analysis")?)?;
            let file_path = string(field(analysis, "file_path")?)?.to_string();
            let mut hits = Vec::new();
            for hit in array(field(analysis, "file_map")?)? {
                let hit = obj(hit)?;
                let id = string(field(hit, "id")?)?;
                if id.is_empty() {
                    return Err(Zod);
                }
                hits.push(Hit {
                    id: id.to_string(),
                    offset: integer(field(hit, "offset")?)?,
                    size: integer(field(hit, "size")?)?,
                    name: string(field(hit, "name")?)?.to_string(),
                    description: string(field(hit, "description")?)?.to_string(),
                    confidence: bounded_int(field(hit, "confidence")?, 255)?,
                });
                boolean(field(hit, "always_display")?)?;
                boolean(field(hit, "extraction_declined")?)?;
            }
            let extractions = obj(field(analysis, "extractions")?)?;
            Ok((file_path, hits, extractions.len()))
        })()
        .map_err(zod)?;
        analyses.push(analysis);
    }
    if analyses.len() != 1 || analyses[0].0 != input_path || analyses[0].2 != 0 {
        return Err(output_error(OP, "Expected one inspection-only report for the selected immutable input"));
    }
    let mut regions = Vec::new();
    for hit in &analyses[0].1 {
        if hit.offset >= size || hit.size > size - hit.offset {
            return Err(output_error(OP, "Reported region lies outside the selected file"));
        }
        regions.push(json!({
            "provider_id": hit.id,
            "offset": hit.offset,
            "reported_size": hit.size,
            "signature": hit.name,
            "description": hit.description,
            "reported_confidence": hit.confidence,
            "size_basis": "provider_reported_validation_unknown",
        }));
    }
    Ok(regions)
}

struct Hit {
    id: String,
    offset: u64,
    size: u64,
    name: String,
    description: String,
    confidence: u64,
}

// ------------------------------------------------------------------ unblob --

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub sha256: Option<String>,
    pub mime_type: Option<String>,
    pub depth: u64,
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub input_path: String,
    pub provider_id: String,
    pub offset: u64,
    pub length: u64,
    pub handler: Option<String>,
    pub encrypted: Option<bool>,
    pub root_file_range: Option<(u64, u64)>,
}

#[derive(Debug, Clone)]
pub struct Normalized {
    pub files: HashMap<String, FileInfo>,
    pub sizes: HashMap<String, u64>,
    pub chunks: Vec<Chunk>,
    pub derivations: Vec<Value>,
    pub depth_limited_paths: Vec<String>,
    pub diagnostics: Vec<Value>,
    pub coverage: &'static str,
}

impl Chunk {
    pub fn to_json(&self) -> Value {
        json!({
            "input_path": self.input_path,
            "provider_id": self.provider_id,
            "range": { "offset": self.offset, "length": self.length },
            "handler": self.handler,
            "encrypted": self.encrypted,
            "root_file_range": self.root_file_range.map(|(offset, length)| json!({"offset": offset, "length": length})),
        })
    }
}

struct Task {
    path: String,
    depth: u64,
    blob_id: String,
    is_multi_file: bool,
}

fn task(value: &Value) -> Z<Task> {
    let task = obj(value)?;
    Ok(Task {
        path: string(field(task, "path")?)?.to_string(),
        depth: integer(field(task, "depth")?)?,
        blob_id: string(field(task, "blob_id")?)?.to_string(),
        is_multi_file: boolean(field(task, "is_multi_file")?)?,
    })
}

struct Record {
    task: Task,
    reports: Vec<Map<String, Value>>,
    subtasks: Vec<Task>,
}

fn type_name(report: &Map<String, Value>) -> &str {
    report.get("__typename__").and_then(Value::as_str).unwrap_or_default()
}

const KNOWN: [&str; 8] = [
    "StatReport",
    "HashReport",
    "FileMagicReport",
    "RandomnessReport",
    "ChunkReport",
    "UnknownChunkReport",
    "CarveDirectoryReport",
    "MultiFileReport",
];

/// Context for [`normalize_unblob`].
pub struct UnblobContext<'a> {
    pub input_path: &'a str,
    pub output_root: &'a str,
    pub sha256: &'a str,
    pub length: u64,
    pub offset: u64,
    pub max_depth: u64,
}

/// `normalizeUnblobReport`: normalize Unblob's unordered task graph.
pub fn normalize_unblob(raw: &Value, context: &UnblobContext<'_>) -> Result<Normalized, FwFailure> {
    const OP: &str = "extract_firmware";
    let mut records: Vec<Record> = Vec::new();
    for item in array(raw).map_err(zod)? {
        let record = (|| -> Z<Record> {
            let item = obj(item)?;
            let mut reports = Vec::new();
            for report in array(field(item, "reports")?)? {
                let report = obj(report)?;
                string(field(report, "__typename__")?)?;
                reports.push(report.clone());
            }
            let mut subtasks = Vec::new();
            for child in array(field(item, "subtasks")?)? {
                subtasks.push(task(child)?);
            }
            Ok(Record { task: task(field(item, "task")?)?, reports, subtasks })
        })()
        .map_err(zod)?;
        records.push(record);
    }
    let logical = |path: &str| -> Result<String, FwFailure> {
        logical_path(path, context.input_path, context.output_root).map_err(|reason| output_error(OP, reason))
    };
    let roots: Vec<&Record> =
        records.iter().filter(|r| r.task.path == context.input_path && r.task.depth == 0).collect();
    if roots.len() != 1 {
        return Err(output_error(OP, "Expected exactly one selected input task"));
    }
    let root_hash = roots[0].reports.iter().find(|r| type_name(r) == "HashReport");
    let Some(root_hash) = root_hash else {
        return Err(output_error(OP, "Unblob input hash disagrees with selected snapshot"));
    };
    let root_sha = (|| -> Z<&str> { digest(field(root_hash, "sha256")?) })().map_err(zod)?;
    if root_sha != context.sha256 {
        return Err(output_error(OP, "Unblob input hash disagrees with selected snapshot"));
    }

    let mut files: HashMap<String, FileInfo> = HashMap::new();
    let mut sizes: HashMap<String, u64> = HashMap::new();
    let mut depths: Vec<String> = Vec::new();
    let mut diagnostics: Vec<Value> = Vec::new();
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut seen_order: Vec<String> = Vec::new();
    for record in &records {
        let path = logical(&record.task.path)?;
        if seen.contains(&path) {
            return Err(output_error(OP, format!("Duplicate analysis task: {path}")));
        }
        seen.insert(path.clone());
        seen_order.push(path.clone());
        if record.task.depth >= context.max_depth {
            depths.push(path.clone());
        }
        let Some(metadata) = record.reports.iter().find(|r| type_name(r) == "StatReport") else {
            return Err(output_error(OP, format!("Missing StatReport: {path}")));
        };
        let stat = (|| -> Z<(String, u64, bool, bool, bool)> {
            let path = string(field(metadata, "path")?)?.to_string();
            let size = integer(field(metadata, "size")?)?;
            let is_dir = boolean(field(metadata, "is_dir")?)?;
            let is_file = boolean(field(metadata, "is_file")?)?;
            let is_link = boolean(field(metadata, "is_link")?)?;
            nullable_string(field(metadata, "link_target")?)?;
            Ok((path, size, is_dir, is_file, is_link))
        })()
        .map_err(zod)?;
        let (stat_path, stat_size, is_dir, is_file, is_link) = stat;
        if stat_path != record.task.path {
            return Err(output_error(OP, format!("StatReport is bound to another task: {path}")));
        }
        if path == "$input" && stat_size != context.length {
            return Err(output_error(OP, "Unblob input size disagrees with selected snapshot"));
        }
        if path == "$input" && (!is_file || is_link || is_dir) {
            return Err(output_error(OP, "Selected input was not reported as a regular file"));
        }
        sizes.insert(path.clone(), stat_size);
        let hash = record.reports.iter().find(|r| type_name(r) == "HashReport");
        let magic = record.reports.iter().find(|r| type_name(r) == "FileMagicReport");
        if is_file && !is_link {
            let sha256 = match hash {
                None => None,
                Some(hash) => Some((|| -> Z<String> { Ok(digest(field(hash, "sha256")?)?.to_string()) })().map_err(zod)?),
            };
            let mime_type = match magic {
                None => None,
                Some(magic) => {
                    Some((|| -> Z<String> { Ok(string(field(magic, "mime_type")?)?.to_string()) })().map_err(zod)?)
                }
            };
            files.insert(path.clone(), FileInfo { sha256, mime_type, depth: record.task.depth });
        }
        for item in &record.reports {
            let kind = type_name(item);
            if !KNOWN.contains(&kind) {
                diagnostics.push(json!({ "input_path": path, "report": Value::Object(item.clone()) }));
            }
            if kind == "ChunkReport" || kind == "UnknownChunkReport" {
                let (id, start, end, chunk_size) = (|| -> Z<(String, u64, u64, u64)> {
                    Ok((
                        string(field(item, "id")?)?.to_string(),
                        integer(field(item, "start_offset")?)?,
                        integer(field(item, "end_offset")?)?,
                        integer(field(item, "size")?)?,
                    ))
                })()
                .map_err(zod)?;
                if end <= start || end > stat_size || chunk_size != end - start {
                    return Err(output_error(OP, format!("Invalid chunk bounds for {path}")));
                }
                let detail = if kind == "ChunkReport" {
                    Some(
                        (|| -> Z<(String, bool, Vec<Value>)> {
                            Ok((
                                string(field(item, "handler_name")?)?.to_string(),
                                boolean(field(item, "is_encrypted")?)?,
                                array(field(item, "extraction_reports")?)?.clone(),
                            ))
                        })()
                        .map_err(zod)?,
                    )
                } else {
                    None
                };
                if let Some((_, _, problems)) = &detail {
                    for problem in problems {
                        diagnostics.push(json!({ "input_path": path, "report": problem }));
                    }
                }
                chunks.push(Chunk {
                    input_path: path.clone(),
                    provider_id: id,
                    offset: start,
                    length: chunk_size,
                    handler: detail.as_ref().map(|d| d.0.clone()),
                    encrypted: detail.as_ref().map(|d| d.1),
                    root_file_range: if path == "$input" { Some((context.offset + start, chunk_size)) } else { None },
                });
            }
            if kind == "MultiFileReport" {
                let extraction_reports = (|| -> Z<usize> {
                    string(field(item, "id")?)?;
                    string(field(item, "handler_name")?)?;
                    string(field(item, "name")?)?;
                    for p in array(field(item, "paths")?)? {
                        string(p)?;
                    }
                    Ok(array(field(item, "extraction_reports")?)?.len())
                })()
                .map_err(zod)?;
                if extraction_reports > 0 {
                    diagnostics.push(json!({ "input_path": path, "report": Value::Object(item.clone()) }));
                }
            }
        }
    }
    // Later duplicates win in a JS Map, but duplicate task paths were refused above.
    let mut records_by_path: HashMap<&str, &Task> = HashMap::new();
    for record in &records {
        records_by_path.insert(record.task.path.as_str(), &record.task);
    }
    let mut chunks_by_origin: HashMap<(String, String), &Chunk> = HashMap::new();
    for chunk in &chunks {
        let key = (chunk.input_path.clone(), chunk.provider_id.clone());
        if chunks_by_origin.contains_key(&key) {
            return Err(output_error(OP, format!("Duplicate chunk identity in {}", chunk.input_path)));
        }
        chunks_by_origin.insert(key, chunk);
    }
    let mut derivations: Vec<Value> = Vec::new();
    let mut edges: Vec<(String, String)> = Vec::new();
    for record in &records {
        for child in &record.subtasks {
            let parent_path = logical(&record.task.path)?;
            let child_path = logical(&child.path)?;
            if !seen.contains(&child_path) {
                return Err(output_error(OP, format!("Missing child task: {child_path}")));
            }
            let reported = records_by_path.get(child.path.as_str());
            let matches = reported
                .map(|r| r.depth == child.depth && r.blob_id == child.blob_id && r.is_multi_file == child.is_multi_file)
                .unwrap_or(false);
            if !matches {
                return Err(output_error(OP, format!("Child task identity disagrees with its analysis: {child_path}")));
            }
            let origin = chunks_by_origin.get(&(parent_path.clone(), child.blob_id.clone()));
            derivations.push(json!({
                "parent_path": parent_path,
                "child_path": child_path,
                "provider_blob_id": child.blob_id,
                "handler": origin.and_then(|c| c.handler.clone()),
                "parent_file_range": origin.map(|c| json!({"offset": c.offset, "length": c.length})),
            }));
            edges.push((parent_path, child_path));
        }
    }
    let mut reachable: HashSet<String> = HashSet::from(["$input".to_string()]);
    let mut pending: Vec<String> = vec!["$input".to_string()];
    let mut children_by_parent: HashMap<String, Vec<String>> = HashMap::new();
    for (parent, child) in &edges {
        children_by_parent.entry(parent.clone()).or_default().push(child.clone());
    }
    while let Some(parent) = pending.pop() {
        for child in children_by_parent.get(&parent).cloned().unwrap_or_default() {
            if reachable.insert(child.clone()) {
                pending.push(child);
            }
        }
    }
    if reachable.len() != seen.len() {
        return Err(output_error(OP, "Report contains tasks disconnected from the selected input"));
    }
    depths.sort_by(|a, b| utf16_order(a, b));
    let partial = !depths.is_empty()
        || !diagnostics.is_empty()
        || chunks.iter().any(|c| c.handler.is_none() || c.encrypted == Some(true));
    let _ = seen_order;
    Ok(Normalized {
        files,
        sizes,
        chunks,
        derivations,
        depth_limited_paths: depths,
        diagnostics,
        coverage: if partial { "partial" } else { "complete" },
    })
}
