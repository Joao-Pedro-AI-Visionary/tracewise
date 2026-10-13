//! `inspect_managed_artifact` (REA `ManagedArtifactInspector`).

use serde_json::{json, Value};

use crate::budget::Budget;
use crate::common::{issues_json, Buf, Failure, Issue, R};
use crate::inventory::{read_metadata_inventory, read_resource_directory, table_row_counts, Inventory, ResourceDirectory};
use crate::layout::{read_metadata_layout, MetadataLayout};
use crate::pe::{read_pe_layout, CliHeader, PeLayout};
use crate::ManagedTarget;

fn flag_names(flags: u32) -> Vec<&'static str> {
    [
        (0x0000_0001u32, "il-only"),
        (0x0000_0002, "32-bit-required"),
        (0x0000_0004, "il-library"),
        (0x0000_0008, "strong-name-signed"),
        (0x0000_0010, "native-entry-point"),
        (0x0001_0000, "track-debug-data"),
        (0x0002_0000, "32-bit-preferred"),
    ]
    .iter()
    .filter(|(mask, _)| flags & mask != 0)
    .map(|(_, name)| *name)
    .collect()
}

fn cli_projection(cli: &CliHeader) -> Value {
    let entry_point = if cli.entry_point == 0 {
        json!({ "kind": "none", "value": null })
    } else if cli.flags & 0x10 != 0 {
        json!({ "kind": "native-rva", "value": format!("0x{:x}", cli.entry_point) })
    } else {
        json!({ "kind": "metadata-token", "value": format!("0x{:08x}", cli.entry_point) })
    };
    json!({
        "header_offset": cli.header_offset,
        "header_size": cli.header_size,
        "runtime_version": format!("{}.{}", cli.runtime_major, cli.runtime_minor),
        "flags": cli.flags,
        "flag_names": flag_names(cli.flags),
        "entry_point": entry_point,
        "metadata_rva": cli.metadata.rva,
        "metadata_size": cli.metadata.size,
        "resources_rva": cli.resources.rva,
        "resources_size": cli.resources.size,
        "strong_name_rva": cli.strong_name.rva,
        "strong_name_size": cli.strong_name.size,
        "managed_native_header_rva": cli.managed_native_header.rva,
        "managed_native_header_size": cli.managed_native_header.size,
        "ready_to_run_signature": cli.ready_to_run_signature,
    })
}

fn pe_projection(layout: &PeLayout) -> Value {
    json!({
        "machine": layout.machine,
        "machine_hex": format!("0x{:04x}", layout.machine),
        "architecture": layout.architecture,
        "optional_header": layout.optional_header,
        "section_count": layout.section_count,
        "characteristics": layout.characteristics,
        "cli": layout.cli.as_ref().map(cli_projection),
    })
}

fn base(target: &ManagedTarget, bytes: &[u8], layout: &PeLayout) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    map.insert(
        "artifact".into(),
        json!({
            "path": target.path,
            "sha256": target.sha256,
            "byte_length": bytes.len(),
            "format": "pe",
        }),
    );
    map.insert("pe".into(), pe_projection(layout));
    map
}

fn unavailable_result(target: &ManagedTarget, bytes: &[u8], layout: &PeLayout) -> R<Value> {
    let malformed = layout.cli_directory_present;
    let issues: Vec<Issue> = layout.cli_issue.iter().cloned().collect();
    let limitation = if malformed {
        "The PE declares a CLI directory, but its CLI header could not be admitted."
    } else {
        "The PE has no CLI data directory; managed metadata and CIL are unavailable."
    };
    let mut map = base(target, bytes, layout);
    map.insert(
        "classification".into(),
        json!({
            "status": if malformed { "malformed" } else { "not-managed" },
            "container": "pe",
            "runtime_family": "unknown",
            "implementation": if malformed { "unknown" } else { "not-managed" },
            "managed_architecture": "unknown",
            "evidence": [{
                "code": if malformed { "cli-directory-malformed" } else { "cli-directory-absent" },
                "detail": limitation,
                "file_offset": layout.cli_issue.as_ref().and_then(|i| i.offset),
            }],
        }),
    );
    map.insert(
        "metadata".into(),
        json!({
            "status": if malformed { "malformed" } else { "absent" },
            "version": null,
            "stream_names": [],
            "table_row_counts": {},
        }),
    );
    for key in ["module", "assembly"] {
        map.insert(key.into(), Value::Null);
    }
    for key in ["target_frameworks", "references", "resources", "attributes"] {
        map.insert(key.into(), json!([]));
    }
    map.insert(
        "coverage".into(),
        json!({ "state": if malformed { "partial" } else { "unavailable" }, "issues": issues_json(&issues) }),
    );
    map.insert("limitations".into(), json!([limitation]));
    Budget::new().admit(Value::Object(map))
}

struct Classification {
    runtime_family: &'static str,
    implementation: &'static str,
    managed_architecture: &'static str,
    evidence: Vec<Value>,
}

fn runtime_classification(
    pe: &PeLayout,
    metadata: &MetadataLayout,
    inventory: &Inventory,
) -> R<Classification> {
    let cli = pe.cli.as_ref().expect("managed classification requires CLI");
    let mut evidence = vec![json!({
        "code": "cli-header-observed",
        "detail": "A file-backed PE CLI header and metadata root were admitted.",
        "file_offset": cli.header_offset,
    })];
    let frameworks = &inventory.target_frameworks;
    let has_unity =
        inventory.reference_names.iter().any(|name| name == "UnityEngine" || name.starts_with("UnityEngine."));
    let mut runtime_family = "unknown";
    let table_offset = |index: usize| metadata.table(index).map(|t| t.offset);
    if cli.flags & 1 == 0 {
        runtime_family = "mixed-clr-native";
        evidence.push(json!({
            "code": "cli-il-only-clear",
            "detail": "COMIMAGE_FLAGS_ILONLY is clear, so managed and native analysis must remain composed.",
            "file_offset": cli.header_offset + 16,
        }));
    } else if has_unity {
        runtime_family = "unity-mono";
        evidence.push(json!({
            "code": "unity-reference-observed",
            "detail": "The admitted AssemblyRef table contains a UnityEngine reference.",
            "file_offset": table_offset(35),
        }));
    } else if frameworks.iter().any(|value| value.starts_with(".NETFramework,")) {
        runtime_family = "dotnet-framework";
        evidence.push(json!({
            "code": "target-framework-observed",
            "detail": "An assembly-level TargetFrameworkAttribute names .NET Framework.",
            "file_offset": table_offset(12),
        }));
    } else if frameworks.iter().any(|value| value.starts_with(".NETCoreApp,") || value.starts_with(".NETStandard,"))
        || cli.ready_to_run_signature
    {
        runtime_family = "modern-dotnet";
        let r2r = cli.ready_to_run_signature;
        evidence.push(json!({
            "code": if r2r { "ready-to-run-signature-observed" } else { "target-framework-observed" },
            "detail": if r2r {
                "The managed native header has the ReadyToRun signature."
            } else {
                "An assembly-level TargetFrameworkAttribute names modern .NET."
            },
            "file_offset": if r2r {
                Some(pe.rva_to_offset(cli.managed_native_header.rva, 4, "cli.managed-native-header")?)
            } else {
                table_offset(12)
            },
        }));
    }
    let implementation = if cli.flags & 1 == 0 {
        "cpp-cli-mixed"
    } else if cli.ready_to_run_signature {
        "cil-and-ready-to-run"
    } else if metadata.row_count(6) == 0 {
        "metadata-only"
    } else {
        "cil"
    };
    let managed_architecture = if pe.architecture != "x86" || cli.flags & 1 == 0 {
        pe.architecture
    } else if cli.flags & 0x0000_0002 != 0 {
        "x86"
    } else if cli.flags & 0x0002_0000 != 0 {
        "anycpu-prefer-32"
    } else {
        "anycpu"
    };
    evidence.push(json!({
        "code": "managed-architecture-derived",
        "detail": format!("Managed architecture {managed_architecture} is derived from PE machine and CLI flags."),
        "file_offset": cli.header_offset + 16,
    }));
    Ok(Classification { runtime_family, implementation, managed_architecture, evidence })
}

fn partial_metadata_result(target: &ManagedTarget, bytes: &[u8], layout: &PeLayout, issue: &Issue) -> R<Value> {
    let resource_limit = issue.code == "resource-limit";
    let il_only = layout.cli.as_ref().map(|c| c.flags).unwrap_or(1) & 1 != 0;
    let mut map = base(target, bytes, layout);
    map.insert(
        "classification".into(),
        json!({
            "status": if resource_limit { "managed" } else { "malformed" },
            "container": "pe",
            "runtime_family": if il_only { "unknown" } else { "mixed-clr-native" },
            "implementation": "unknown",
            "managed_architecture": "unknown",
            "evidence": [{
                "code": "metadata-not-admitted",
                "detail": issue.detail,
                "file_offset": issue.offset,
            }],
        }),
    );
    map.insert(
        "metadata".into(),
        json!({
            "status": if resource_limit { "partial" } else { "malformed" },
            "version": null,
            "stream_names": [],
            "table_row_counts": {},
        }),
    );
    for key in ["module", "assembly"] {
        map.insert(key.into(), Value::Null);
    }
    for key in ["target_frameworks", "references", "resources", "attributes"] {
        map.insert(key.into(), json!([]));
    }
    map.insert("coverage".into(), json!({ "state": "partial", "issues": [issue.to_json()] }));
    map.insert(
        "limitations".into(),
        json!([if resource_limit {
            "CLI metadata inspection stopped at its representation budget; omitted facts are unknown."
        } else {
            "CLI metadata could not be read because the PE/CLI structure is malformed or unsupported."
        }]),
    );
    Budget::new().admit(Value::Object(map))
}

fn full_result(
    target: &ManagedTarget,
    bytes: &[u8],
    pe: &PeLayout,
    metadata: &MetadataLayout,
    resource_issues: &[Issue],
    resource_directory: Option<ResourceDirectory>,
) -> R<Value> {
    let buf = Buf(bytes);
    let inventory = read_metadata_inventory(&buf, metadata, resource_directory)?;
    let mut issues: Vec<Issue> = resource_issues.to_vec();
    issues.extend(inventory.issues.iter().cloned());
    let limitations = {
        let mut list: Vec<&str> = Vec::new();
        if !issues.is_empty() {
            list.push("At least one metadata or resource item could not be read; coverage is partial.");
        }
        list.push(
            "Static inspection did not load the assembly, resolve dependencies through a CLR, decompile C#, or execute target code.",
        );
        list
    };
    let classification = runtime_classification(pe, metadata, &inventory)?;
    let mut map = base(target, bytes, pe);
    map.insert(
        "classification".into(),
        json!({
            "status": "managed",
            "container": "pe",
            "runtime_family": classification.runtime_family,
            "implementation": classification.implementation,
            "managed_architecture": classification.managed_architecture,
            "evidence": classification.evidence,
        }),
    );
    map.insert(
        "metadata".into(),
        json!({
            "status": if issues.is_empty() { "complete" } else { "partial" },
            "version": metadata.version,
            "stream_names": metadata.stream_names,
            "table_row_counts": table_row_counts(metadata),
        }),
    );
    map.insert("module".into(), inventory.module.clone().unwrap_or(Value::Null));
    map.insert("assembly".into(), inventory.assembly.clone().unwrap_or(Value::Null));
    map.insert("target_frameworks".into(), json!(inventory.target_frameworks));
    map.insert("references".into(), Value::Array(inventory.references.clone()));
    map.insert("resources".into(), Value::Array(inventory.resources.clone()));
    map.insert("attributes".into(), Value::Array(inventory.attributes.clone()));
    map.insert(
        "coverage".into(),
        json!({ "state": if issues.is_empty() { "complete" } else { "partial" }, "issues": issues_json(&issues) }),
    );
    map.insert("limitations".into(), json!(limitations));
    metadata.budget.admit(Value::Object(map))
}

/// Inspect PE/CLI identity directly from local bytes without CLR loading.
pub fn inspect_managed_artifact_bytes(bytes: &[u8], target: &ManagedTarget) -> Result<Value, Failure> {
    let layout = read_pe_layout(bytes)?;
    let Some(cli) = layout.cli.as_ref() else {
        return unavailable_result(target, bytes, &layout);
    };
    let metadata = (|| -> R<MetadataLayout> {
        let metadata_offset = layout.rva_to_offset(cli.metadata.rva, cli.metadata.size, "cli.metadata")?;
        read_metadata_layout(bytes, metadata_offset, cli.metadata.size)
    })();
    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(Failure::Reader(issue)) => return partial_metadata_result(target, bytes, &layout, &issue),
        Err(other) => return Err(other),
    };
    let mut resource_issues: Vec<Issue> = Vec::new();
    let resource_directory = read_resource_directory(&layout, &mut resource_issues)?;
    match full_result(target, bytes, &layout, &metadata, &resource_issues, resource_directory) {
        Ok(value) => Ok(value),
        Err(Failure::Reader(issue)) => partial_metadata_result(target, bytes, &layout, &issue),
        Err(other) => Err(other),
    }
}
