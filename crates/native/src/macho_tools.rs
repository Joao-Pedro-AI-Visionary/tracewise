//! `list_architectures` and `inspect_macho`: native replacements for the `lipo`, `otool`,
//! `nm`, `dyld_info` and `dwarfdump` pipeline of REA (`native/NativeMachoInspection.ts`,
//! `NativeMacOSProvider.ts`, `native/parsers/lipo.ts`).

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::bounded_read::{read_bounded, Bounded};
use crate::dyld_syms::{read_symbols, ExportKind};
use crate::error::NativeError;
use crate::macho_image::{
    lipo_architecture_name, lipo_cpu_subtype, lipo_cpu_type, parse_container, select_slice, slice_bytes, Container,
    Image, SliceSelection,
};
use crate::otool::{parse_otool, print_header_and_commands};

/// A file-offset evidence location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileLocation {
    Offset(u64),
    Range(u64, u64),
}

pub struct NativeObservation {
    pub result: Value,
    pub limitations: Vec<String>,
    pub locations: Vec<FileLocation>,
}

const MAX_IMAGE_BYTES: u64 = 1024 * 1024 * 1024;

fn output_error(operation: &str, reason: impl Into<String>) -> NativeError {
    NativeError::Output { operation: operation.to_string(), reason: reason.into() }
}

/// Read a bounded regular file.
pub fn read_image_file(path: &Path, operation: &str) -> Result<Vec<u8>, NativeError> {
    let mut file = File::open(path).map_err(|e| output_error(operation, format!("could not open {}: {e}", path.display())))?;
    let length = file.metadata().map(|m| m.len()).unwrap_or(0);
    if length > MAX_IMAGE_BYTES {
        return Err(NativeError::Resource {
            operation: operation.to_string(),
            resource: "memory".to_string(),
            reason: format!("Mach-O file exceeds {MAX_IMAGE_BYTES} bytes."),
            reported_limits: json!({ "max_file_bytes": MAX_IMAGE_BYTES }),
        });
    }
    match read_bounded(&mut file, MAX_IMAGE_BYTES)
        .map_err(|e| output_error(operation, format!("could not read {}: {e}", path.display())))?
    {
        Bounded::Complete(data) => Ok(data),
        Bounded::TooLarge => Err(NativeError::Resource {
            operation: operation.to_string(),
            resource: "memory".to_string(),
            reason: format!("Mach-O file exceeds {MAX_IMAGE_BYTES} bytes."),
            reported_limits: json!({ "max_file_bytes": MAX_IMAGE_BYTES }),
        }),
    }
}

fn executable_sha256() -> &'static str {
    static CELL: OnceLock<String> = OnceLock::new();
    CELL.get_or_init(|| {
        let from_exe = std::env::current_exe().ok().and_then(|path| {
            let mut file = File::open(path).ok()?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0u8; 1 << 20];
            loop {
                let count = file.read(&mut buffer).ok()?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            Some(hex::encode(hasher.finalize()))
        });
        from_exe.unwrap_or_else(|| {
            hex::encode(Sha256::digest(format!("tracewise-native {}", env!("CARGO_PKG_VERSION")).as_bytes()))
        })
    })
}

/// The one provenance record of a native (in-process) decoder run.
pub fn native_provenance(operation: &str, artifact_alias: &str) -> Value {
    json!({
        "tool": "tracewise-native",
        "command": ["tracewise-native", operation, artifact_alias],
        "tool_version": env!("CARGO_PKG_VERSION"),
        "version_reason": null,
        "executable_sha256": executable_sha256(),
        "exit": { "code": 0, "signal": null },
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    })
}

fn coverage(items: Vec<Value>, exhaustive: bool, limitations: Vec<String>) -> Value {
    let total = items.len();
    json!({
        "items": items,
        "total": if exhaustive { json!(total) } else { Value::Null },
        "exhaustive": exhaustive,
        "limitations": limitations,
    })
}

// ---------------------------------------------------------------------------
// lipo
// ---------------------------------------------------------------------------

fn unknown_name(cputype: u32, cpusubtype: u32) -> String {
    format!("unknown({},{})", cputype as i32, cpusubtype & !0xff00_0000)
}

/// `parseLipoArchitectures` of a native read: slice metadata and whether the input was thin.
pub fn lipo_architectures(data: &[u8]) -> Result<(Vec<Value>, bool), String> {
    let container = parse_container(data).map_err(|e| e.0)?;
    match container {
        Container::Thin => {
            let image = Image::parse(data).map_err(|e| e.0)?;
            let name = lipo_architecture_name(image.header.cputype, image.header.cpusubtype)
                .map(String::from)
                .unwrap_or_else(|| unknown_name(image.header.cputype, image.header.cpusubtype));
            Ok((
                vec![json!({
                    "name": name,
                    "cpu_type": null,
                    "cpu_subtype": null,
                    "file_offset": null,
                    "size": null,
                    "alignment": null,
                })],
                true,
            ))
        }
        Container::Fat { arches, .. } => {
            let items = arches
                .iter()
                .map(|arch| {
                    let name = lipo_architecture_name(arch.cputype, arch.cpusubtype)
                        .map(String::from)
                        .unwrap_or_else(|| unknown_name(arch.cputype, arch.cpusubtype));
                    let alignment = if arch.align <= 52 { json!(1u64 << arch.align) } else { Value::Null };
                    json!({
                        "name": name,
                        "cpu_type": lipo_cpu_type(arch.cputype),
                        "cpu_subtype": lipo_cpu_subtype(arch.cputype, arch.cpusubtype),
                        "file_offset": arch.offset,
                        "size": arch.size,
                        "alignment": alignment,
                    })
                })
                .collect();
            Ok((items, false))
        }
    }
}

fn architecture_locations(items: &[Value]) -> Vec<FileLocation> {
    items
        .iter()
        .filter_map(|item| {
            let offset = item.get("file_offset").and_then(Value::as_u64)?;
            Some(match item.get("size").and_then(Value::as_u64) {
                None => FileLocation::Offset(offset),
                Some(size) => FileLocation::Range(offset, offset + size),
            })
        })
        .collect()
}

pub fn list_architectures(path: &Path, alias: &str) -> Result<NativeObservation, NativeError> {
    const OPERATION: &str = "list_architectures";
    let data = read_image_file(path, OPERATION)?;
    let (items, _) = lipo_architectures(&data).map_err(|reason| output_error(OPERATION, reason))?;
    let locations = architecture_locations(&items);
    let result = json!({
        "architectures": coverage(items, true, Vec::new()),
        "provenance": [native_provenance(OPERATION, alias)],
        "limitations": [],
    });
    Ok(NativeObservation { result, limitations: Vec::new(), locations })
}

// ---------------------------------------------------------------------------
// inspect_macho
// ---------------------------------------------------------------------------

fn locale_compare(left: &str, right: &str) -> std::cmp::Ordering {
    use icu_collator::options::CollatorOptions;
    use icu_collator::{Collator, CollatorBorrowed, CollatorPreferences};
    static CELL: OnceLock<CollatorBorrowed<'static>> = OnceLock::new();
    let collator = CELL.get_or_init(|| {
        Collator::try_new(CollatorPreferences::default(), CollatorOptions::default()).expect("root collator")
    });
    collator.compare(left, right)
}

fn canonical_hex(value: u128) -> String {
    format!("0x{value:x}")
}

fn parse_hex_u128(text: &str) -> Option<u128> {
    u128::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

pub fn inspect_macho(path: &Path, requested_architecture: Option<&str>, alias: &str) -> Result<NativeObservation, NativeError> {
    const OPERATION: &str = "inspect_macho";
    let data = read_image_file(path, OPERATION)?;
    let container = parse_container(&data).map_err(|e| output_error(OPERATION, e.0))?;
    let (architectures, thin) = lipo_architectures(&data).map_err(|reason| output_error(OPERATION, reason))?;
    // REA filters slices only for a universal file with at least two slices.
    let filter = match &container {
        Container::Fat { arches, .. } if arches.len() >= 2 => requested_architecture,
        _ => None,
    };
    let selection: SliceSelection = select_slice(&data, &container, filter).map_err(|e| output_error(OPERATION, e.0))?;
    let slice = slice_bytes(&data, &selection).map_err(|e| output_error(OPERATION, e.0))?;
    let image = Image::parse(slice).map_err(|e| output_error(OPERATION, e.0))?;

    let path_line = match &selection.name {
        Some(name) if matches!(container, Container::Fat { .. }) => format!("$ARTIFACT (architecture {name})"),
        _ => "$ARTIFACT".to_string(),
    };
    let text = print_header_and_commands(&image, &path_line).map_err(|e| output_error(OPERATION, e.0))?;
    let load = parse_otool(&text);

    let image_base: Option<String> = load.segments.iter().find_map(|segment| {
        let file_offset = segment.get("file_offset").and_then(Value::as_f64);
        let file_size = segment.get("file_size").and_then(Value::as_f64).unwrap_or(0.0);
        if file_offset == Some(0.0) && file_size > 0.0 {
            segment.get("vm_address").and_then(Value::as_str).map(String::from)
        } else {
            None
        }
    });

    let inventory = read_symbols(&image);
    let imports: Vec<Value> = inventory
        .imports
        .iter()
        .map(|row| {
            json!({
                "name": row.name,
                "address": null,
                "weak": if row.weak { json!(true) } else { Value::Null },
                "reexport": null,
                "source": row.source,
            })
        })
        .collect();

    let base = image_base.as_deref().and_then(parse_hex_u128);
    let dyld_exports = inventory.exports.iter().map(|row| {
        let (address, reexport, source) = match &row.reexport {
            Some(source) => (Value::Null, true, source.library.clone()),
            None => {
                let address = match row.kind {
                    ExportKind::Absolute => Some(canonical_hex(u128::from(row.value))),
                    _ => base.map(|b| canonical_hex(b + u128::from(row.value))),
                };
                (address.map(Value::String).unwrap_or(Value::Null), false, None)
            }
        };
        json!({
            "name": row.name,
            "address": address,
            "weak": if row.weak_definition { json!(true) } else { Value::Null },
            "reexport": reexport,
            "source": source,
        })
    });
    let nm_exports = inventory.nm_exports.iter().map(|name| {
        json!({"name": name, "address": null, "weak": null, "reexport": null, "source": "nm"})
    });
    let mut seen = std::collections::HashSet::new();
    let mut exports: Vec<Value> = Vec::new();
    for item in dyld_exports.chain(nm_exports) {
        let name = item["name"].as_str().unwrap_or("").to_string();
        if seen.insert(name) {
            exports.push(item);
        }
    }
    exports.sort_by(|a, b| locale_compare(a["name"].as_str().unwrap_or(""), b["name"].as_str().unwrap_or("")));

    let thread_entrypoint = load.entrypoints.is_empty()
        && load.kinds.iter().any(|kind| kind == "LC_UNIXTHREAD" || kind == "LC_THREAD");
    let thread_limitation = "Thread-state entrypoints (LC_UNIXTHREAD/LC_THREAD) are retained as raw load commands; file offsets are not derived.";
    let mut limitations: Vec<String> = vec![
        "Imports and exports combine the binding information, the export trie and the symbol table; stripped or toolchain-hidden symbols may be absent.".to_string(),
        "Decoded in-process from the file bytes; no Apple command-line tool was run, and textual details follow cctools otool conventions.".to_string(),
    ];
    limitations.extend(inventory.notes.iter().cloned());
    if thread_entrypoint {
        limitations.push(thread_limitation.to_string());
    }
    if image_base.is_none() && !inventory.exports.is_empty() {
        limitations.push(
            "Export virtual addresses are unavailable because no file-backed image base was observed.".to_string(),
        );
    }

    let segments: Vec<Value> = load
        .segments
        .iter()
        .map(|segment| {
            let mut segment = segment.clone();
            let sections = segment["sections"].as_array().cloned().unwrap_or_default();
            segment["sections"] = coverage(sections, true, Vec::new());
            segment
        })
        .collect();

    let word_size = if image.header.is64 { json!(64) } else { json!(32) };
    let endian = if image.header.big { "big" } else { "little" };
    let mut result = json!({
        "format": "mach-o",
        "endian": endian,
        "word_size": word_size,
        "file_type": load.file_type,
        "flags": load.flags,
        "uuid": load.uuid,
        "entrypoints": coverage(
            load.entrypoints.clone(),
            !thread_entrypoint,
            if thread_entrypoint { vec![thread_limitation.to_string()] } else { Vec::new() },
        ),
        "architectures": coverage(architectures.clone(), true, Vec::new()),
        "build_metadata": coverage(load.builds.clone(), true, Vec::new()),
        "load_commands": coverage(load.commands.clone(), true, Vec::new()),
        "dependencies": coverage(load.dependencies.clone(), true, Vec::new()),
        "imports": coverage(
            imports,
            false,
            vec!["Decoded binding information may omit metadata the decoder does not support.".to_string()],
        ),
        "exports": coverage(
            exports,
            false,
            vec!["Merged export-trie and symbol-table results may be incomplete for stripped binaries.".to_string()],
        ),
        "segments": coverage(segments.clone(), true, Vec::new()),
        "provenance": [native_provenance(OPERATION, alias)],
        "limitations": limitations,
    });

    // Container offset of the selected slice (segment offsets are slice-relative).
    let selected_architecture = selection.name.as_deref();
    let slice_offset: Option<u64> = {
        let candidate = match selected_architecture {
            None => {
                if architectures.len() == 1 {
                    architectures[0].get("file_offset").and_then(Value::as_u64)
                } else {
                    None
                }
            }
            Some(name) => architectures
                .iter()
                .find(|a| a["name"] == name)
                .and_then(|a| a.get("file_offset").and_then(Value::as_u64)),
        };
        candidate.or(if thin && selected_architecture.is_none() && architectures.len() == 1 { Some(0) } else { None })
    };
    let mut locations = architecture_locations(&architectures);
    match slice_offset {
        Some(base_offset) => {
            for segment in &segments {
                let (Some(file_offset), Some(file_size)) =
                    (segment["file_offset"].as_u64(), segment["file_size"].as_u64())
                else {
                    continue;
                };
                locations.push(FileLocation::Range(base_offset + file_offset, base_offset + file_offset + file_size));
            }
        }
        None => {
            let note = "Segment evidence file offsets are unavailable because the selected Mach-O slice's container offset was not observed.";
            result["limitations"].as_array_mut().unwrap().push(Value::String(note.to_string()));
        }
    }
    let limitations: Vec<String> = result["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    Ok(NativeObservation { result, limitations, locations })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A universal header with the slice table of REA's `lipo-fat.txt` capture
    /// (x86_64 at 16384/4096, arm64 at 32768/8192, both 2^14 aligned).
    fn fat_fixture() -> Vec<u8> {
        let mut data = vec![0u8; 32768 + 8192];
        data[0..4].copy_from_slice(&0xcafe_babe_u32.to_be_bytes());
        data[4..8].copy_from_slice(&2u32.to_be_bytes());
        let table: [(u32, u32, u32, u32, u32); 2] = [
            (0x0100_0007, 3, 16384, 4096, 14),
            (0x0100_000c, 0, 32768, 8192, 14),
        ];
        for (index, (cpu, sub, offset, size, align)) in table.iter().enumerate() {
            let at = 8 + index * 20;
            for (i, value) in [cpu, sub, offset, size, align].iter().enumerate() {
                data[at + i * 4..at + i * 4 + 4].copy_from_slice(&value.to_be_bytes());
            }
        }
        data
    }

    #[test]
    fn universal_slice_table_matches_the_lipo_capture() {
        let (items, thin) = lipo_architectures(&fat_fixture()).unwrap();
        assert!(!thin);
        let summary: Vec<(String, u64, u64, u64)> = items
            .iter()
            .map(|i| {
                (
                    i["name"].as_str().unwrap().to_string(),
                    i["file_offset"].as_u64().unwrap(),
                    i["size"].as_u64().unwrap(),
                    i["alignment"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![("x86_64".to_string(), 16384, 4096, 16384), ("arm64".to_string(), 32768, 8192, 16384)]
        );
        assert_eq!(items[0]["cpu_type"], "CPU_TYPE_X86_64");
        assert_eq!(items[1]["cpu_subtype"], "CPU_SUBTYPE_ARM64_ALL");
        assert_eq!(
            architecture_locations(&items),
            vec![FileLocation::Range(16384, 20480), FileLocation::Range(32768, 40960)]
        );
    }

    #[test]
    fn a_cpu_lipo_did_not_list_is_refused() {
        let data = fat_fixture();
        let container = parse_container(&data).unwrap();
        let error = select_slice(&data, &container, Some("armv7")).unwrap_err();
        assert_eq!(error.0, "lipo did not list armv7; refusing to read another slice");
        // `x86` is lipo's `i386`, which this file does not hold either.
        assert!(select_slice(&data, &container, Some("x86")).is_err());
        assert_eq!(select_slice(&data, &container, Some("arm64")).unwrap().offset, 32768);
    }
}
