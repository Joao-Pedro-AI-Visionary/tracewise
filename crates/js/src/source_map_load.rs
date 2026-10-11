//! Locate a bundle source map and turn generated tokens into byte ranges.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use serde_json::{json, Value};

use crate::error::JsError;

pub(crate) fn token_ranges(bundle: &str, map: &sourcemap::SourceMap) -> BTreeMap<u32, Vec<Value>> {
    let line_starts = line_starts(bundle);
    let mut points: Vec<(u32, usize)> = Vec::new();
    for token in map.tokens() {
        let source_id = token.get_src_id();
        if source_id == u32::MAX || map.get_source(source_id).is_none() {
            continue;
        }
        let line = token.get_dst_line() as usize;
        if line >= line_starts.len() {
            continue;
        }
        let line_text = bundle[line_starts[line]..].split('\n').next().unwrap_or("");
        let Some(column) = utf16_column_to_byte(line_text, token.get_dst_col()) else {
            continue;
        };
        points.push((source_id, line_starts[line] + column));
    }
    points.sort_by_key(|point| point.1);
    let mut ranges: BTreeMap<u32, Vec<(usize, usize)>> = BTreeMap::new();
    for (index, (source_id, start)) in points.iter().enumerate() {
        let end = points.get(index + 1).map(|next| next.1).unwrap_or(bundle.len());
        if end < *start {
            continue;
        }
        let list = ranges.entry(*source_id).or_default();
        if let Some(last) = list.last_mut() {
            if last.1 == *start {
                last.1 = end;
                continue;
            }
        }
        list.push((*start, end));
    }
    ranges
        .into_iter()
        .map(|(source_id, spans)| {
            (
                source_id,
                spans
                    .into_iter()
                    .map(|(start, end)| json!({"start": start, "end": end}))
                    .collect(),
            )
        })
        .collect()
}

fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (index, byte) in text.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(index + 1);
        }
    }
    starts
}

fn utf16_column_to_byte(line: &str, column: u32) -> Option<usize> {
    let mut units = 0u32;
    for (byte_index, ch) in line.char_indices() {
        if units == column {
            return Some(byte_index);
        }
        let width = if (ch as u32) > 0xFFFF { 2 } else { 1 };
        if units + width > column {
            return None;
        }
        units += width;
    }
    if units == column {
        Some(line.len())
    } else {
        None
    }
}

pub(crate) fn load_source_map(bundle_text: &str, bundle_path: &Path) -> Result<(Vec<u8>, PathBuf), JsError> {
    if let Some(url) = last_source_mapping_url(bundle_text) {
        if let Some(data) = url.strip_prefix("data:") {
            let bytes = decode_data_url(data)?;
            let inline = bundle_path.with_extension("inline-source-map.json");
            return Ok((bytes, inline));
        }
        if url.contains("://") {
            return Err(JsError::InvalidInput(
                "remote sourceMappingURL values are not fetched".into(),
            ));
        }
        let map_path = if Path::new(url).is_absolute() {
            PathBuf::from(url)
        } else {
            bundle_path.parent().unwrap_or(Path::new(".")).join(url)
        };
        return read_map(&map_path);
    }
    let sibling = bundle_path.with_extension("js.map");
    let direct = PathBuf::from(format!("{}.map", bundle_path.display()));
    if direct.is_file() {
        return read_map(&direct);
    }
    if sibling.is_file() {
        return read_map(&sibling);
    }
    Err(JsError::InvalidInput(
        "no local source map was found beside the bundle or in sourceMappingURL".into(),
    ))
}

fn read_map(path: &Path) -> Result<(Vec<u8>, PathBuf), JsError> {
    let bytes = fs::read(path).map_err(|error| {
        JsError::InvalidInput(format!("cannot read source map {}: {error}", path.display()))
    })?;
    let absolute = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    Ok((bytes, absolute))
}

fn decode_data_url(data: &str) -> Result<Vec<u8>, JsError> {
    let Some((meta, payload)) = data.split_once(',') else {
        return Err(JsError::InvalidInput("sourceMappingURL data URL is malformed".into()));
    };
    if !meta.contains("base64") {
        return Err(JsError::InvalidInput(
            "inline source maps must use a base64 data URL".into(),
        ));
    }
    base64::engine::general_purpose::STANDARD
        .decode(payload.trim())
        .map_err(|error| JsError::InvalidInput(format!("inline source map base64 is invalid: {error}")))
}

fn last_source_mapping_url(text: &str) -> Option<&str> {
    let key = "sourceMappingURL=";
    let mut last = None;
    let mut rest = text;
    while let Some(index) = rest.find(key) {
        let after = &rest[index + key.len()..];
        let end = after
            .find(|ch: char| ch.is_whitespace() || ch == '*')
            .unwrap_or(after.len());
        let url = after[..end].trim_end_matches(';');
        if !url.is_empty() {
            last = Some(url);
        }
        rest = &after[end..];
    }
    last
}

