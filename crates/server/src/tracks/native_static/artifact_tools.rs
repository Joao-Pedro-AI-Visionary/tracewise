//! `trace_dylib_resolution`, `inspect_keyed_archive`, `decode_interface_builder`
//! (REA `ArtifactProvider`, native Rust, no host dependency).

use std::path::Path;

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::{json, Map, Value};
use tracewise_native::dylib::{trace_dylib_resolution as trace, DylibRequest};
use tracewise_native::ib::{analyze_interface_builder_bundle, InterfaceBuilderLimits};
use tracewise_native::keyed_archive::{inspect_bundle_keyed_archive, KeyedArchiveRequest};
use tracewise_native::NativeError;

use super::common::{
    active_target, artifact_graph_provider, artifact_path_locations, error_result, error_text_result,
    evidence_result, strings_of, TargetKind,
};
use super::validate::{validate, Field, Kind};
use crate::session::BinarySession;

fn int_arg(args: &Value, key: &str, default: i64) -> i64 {
    args.get(key).and_then(Value::as_i64).unwrap_or(default)
}

pub fn trace_dylib_resolution(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    const TOOL: &str = "trace_dylib_resolution";
    let fields = [
        Field {
            name: "roots",
            kind: Kind::RelativePaths,
            required: false,
        },
        Field {
            name: "architecture",
            kind: Kind::Enum(&["arm64", "arm64e", "x86_64"]),
            required: false,
        },
    ];
    if let Err(text) = validate(TOOL, args, &fields) {
        return Ok(error_text_result(text));
    }
    let target = match active_target(session) {
        Ok(target) => target,
        Err(error) => return Ok(error_result(&error)),
    };
    if target.kind != TargetKind::Executable || target.format() != "mach-o" {
        return Ok(error_result(&NativeError::unsupported(
            TOOL,
            target.path(),
            "trace_dylib_resolution requires an active Mach-O or .app bundle target",
        )));
    }
    // Only a target opened from an app bundle directory carries its Info.plist.
    let bundle = if target.bundle_info_plist.is_some() {
        target.bundle.clone()
    } else {
        None
    };
    let target_path = Path::new(target.path()).to_path_buf();
    let root_path = match &bundle {
        Some(bundle) => bundle.clone(),
        None => target_path.parent().map(Path::to_path_buf).unwrap_or_else(|| Path::new(".").to_path_buf()),
    };
    let roots = args.get("roots").map(|_| strings_of(args, "roots"));
    let architecture = args.get("architecture").and_then(Value::as_str).map(str::to_string);
    let result = trace(&DylibRequest {
        root_path: &root_path,
        target_path: &target_path,
        target_sha256: &target.subject.digest.sha256,
        enumerate_roots: bundle.is_some(),
        roots,
        architecture,
    });
    let result = match result {
        Ok(result) => result,
        Err(error) => return Ok(error_result(&error)),
    };
    let limitations = strings_of(&result, "limitations");
    let locations = artifact_path_locations(
        result["images"]
            .as_array()
            .map(|images| {
                images
                    .iter()
                    .filter_map(|image| image["path"].as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    );
    evidence_result(
        session,
        Some(target.subject.clone()),
        artifact_graph_provider(),
        TOOL,
        args.clone(),
        result,
        limitations,
        locations,
    )
}

pub fn inspect_keyed_archive(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    const TOOL: &str = "inspect_keyed_archive";
    let fields = [
        Field {
            name: "path",
            kind: Kind::Str { min: 1 },
            required: false,
        },
        Field {
            name: "root",
            kind: Kind::Str { min: 0 },
            required: false,
        },
        Field {
            name: "offset",
            kind: Kind::Int {
                min: 0,
                max: 9_007_199_254_740_991,
            },
            required: false,
        },
        Field {
            name: "limit",
            kind: Kind::Int { min: 1, max: 20_000 },
            required: false,
        },
    ];
    if let Err(text) = validate(TOOL, args, &fields) {
        return Ok(error_text_result(text));
    }
    let target = match active_target(session) {
        Ok(target) => target,
        Err(error) => return Ok(error_result(&error)),
    };
    let standalone = target.kind == TargetKind::Artifact && target.format() == "plist";
    let path = args.get("path").and_then(Value::as_str).unwrap_or(".").to_string();
    let target_path = Path::new(target.path()).to_path_buf();
    let target_name = target_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if standalone && path != "." && path != target_name {
        return Ok(error_result(&NativeError::Input {
            operation: TOOL.to_string(),
            issues: vec![tracewise_native::InputIssue {
                path: vec![json!("path")],
                reason: "invalid_value".to_string(),
                message: Some(
                    "For an active plist, path must select that archive (omit path or use its basename)."
                        .to_string(),
                ),
                expected: Some(json!(target_name)),
            }],
        }));
    }
    let bundle_path = if standalone {
        target_path.parent().map(Path::to_path_buf)
    } else {
        target.bundle.clone()
    };
    let Some(bundle_path) = bundle_path else {
        return Ok(error_result(&NativeError::unsupported(
            TOOL,
            target.path(),
            "inspect_keyed_archive requires an active plist or .app bundle",
        )));
    };
    if !standalone && !bundle_path.to_string_lossy().to_lowercase().ends_with(".app") {
        return Ok(error_result(&NativeError::unsupported(
            TOOL,
            target.path(),
            "inspect_keyed_archive requires an active plist or .app bundle",
        )));
    }
    let effective_path = if standalone { target_name.clone() } else { path.clone() };
    let offset = int_arg(args, "offset", 0).max(0) as usize;
    let limit = int_arg(args, "limit", 20_000).clamp(1, 20_000) as usize;
    let root = args.get("root").and_then(Value::as_str).map(str::to_string);
    let result = inspect_bundle_keyed_archive(&KeyedArchiveRequest {
        bundle_path: &bundle_path,
        target_sha256: &target.subject.digest.sha256,
        path: effective_path.clone(),
        root: root.clone(),
        offset,
        limit,
        plist_remediation: Some(
            "Inspect an ordinary property list with inspect_plist; inspect_keyed_archive decodes NSKeyedArchiver archives only."
                .to_string(),
        ),
    });
    let result = match result {
        Ok(result) => result,
        Err(error) => return Ok(error_result(&error)),
    };
    if standalone && result["archive_sha256"].as_str() != Some(target.subject.digest.sha256.as_str()) {
        return Ok(error_result(&NativeError::artifact(
            TOOL,
            tracewise_native::ArtifactReason::Integrity,
            format!(
                "Active archive digest changed: expected {}, observed {}",
                target.subject.digest.sha256,
                result["archive_sha256"].as_str().unwrap_or("")
            ),
        )));
    }
    let mut parameters = Map::new();
    parameters.insert("path".into(), json!(path));
    if let Some(root) = &root {
        parameters.insert("root".into(), json!(root));
    }
    parameters.insert("offset".into(), json!(offset));
    parameters.insert("limit".into(), json!(limit));
    let limitations = strings_of(&result, "limitations");
    let locations = artifact_path_locations(vec![result["archive_path"].as_str().unwrap_or("").to_string()]);
    evidence_result(
        session,
        Some(target.subject.clone()),
        artifact_graph_provider(),
        TOOL,
        Value::Object(parameters),
        result,
        limitations,
        locations,
    )
}

pub fn decode_interface_builder(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    const TOOL: &str = "decode_interface_builder";
    let fields = [
        Field {
            name: "max_documents",
            kind: Kind::Int { min: 1, max: 64 },
            required: false,
        },
        Field {
            name: "max_objects",
            kind: Kind::Int { min: 1, max: 20_000 },
            required: false,
        },
        Field {
            name: "max_connections",
            kind: Kind::Int { min: 1, max: 40_000 },
            required: false,
        },
    ];
    if let Err(text) = validate(TOOL, args, &fields) {
        return Ok(error_text_result(text));
    }
    let target = match active_target(session) {
        Ok(target) => target,
        Err(error) => return Ok(error_result(&error)),
    };
    let bundle = match (&target.kind, &target.bundle) {
        (TargetKind::Executable, Some(bundle)) if bundle.to_string_lossy().to_lowercase().ends_with(".app") => {
            bundle.clone()
        }
        _ => {
            return Ok(error_result(&NativeError::unsupported(
                TOOL,
                target.path(),
                "decode_interface_builder requires an active .app bundle target",
            )))
        }
    };
    let limits = InterfaceBuilderLimits {
        max_documents: int_arg(args, "max_documents", 64) as usize,
        max_objects: int_arg(args, "max_objects", 20_000) as usize,
        max_connections: int_arg(args, "max_connections", 40_000) as usize,
    };
    let result = match analyze_interface_builder_bundle(&bundle, &target.subject.digest.sha256, limits) {
        Ok(result) => result,
        Err(error) => return Ok(error_result(&error)),
    };
    let limitations = strings_of(&result, "limitations");
    let locations = artifact_path_locations(
        result["documents"]
            .as_array()
            .map(|documents| {
                documents
                    .iter()
                    .filter_map(|d| d["relative_path"].as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    );
    evidence_result(
        session,
        Some(target.subject.clone()),
        artifact_graph_provider(),
        TOOL,
        json!({
            "max_documents": limits.max_documents,
            "max_objects": limits.max_objects,
            "max_connections": limits.max_connections,
        }),
        result,
        limitations,
        locations,
    )
}

pub fn inspect_asset_catalog(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    use tracewise_native::asset_catalog::{analyze_asset_catalogs, AssetCatalogRequest};
    const TOOL: &str = "inspect_asset_catalog";
    let fields = [
        Field { name: "offset", kind: Kind::Int { min: 0, max: 9_007_199_254_740_991 }, required: false },
        Field { name: "limit", kind: Kind::Int { min: 1, max: 10_000 }, required: false },
    ];
    if let Err(text) = validate(TOOL, args, &fields) {
        return Ok(error_text_result(text));
    }
    let target = match active_target(session) {
        Ok(target) => target,
        Err(error) => return Ok(error_result(&error)),
    };
    let bundle = match (&target.kind, &target.bundle) {
        (TargetKind::Executable, Some(bundle)) if bundle.to_string_lossy().to_lowercase().ends_with(".app") => {
            bundle.clone()
        }
        _ => {
            return Ok(error_result(&NativeError::unsupported(
                TOOL,
                target.path(),
                "inspect_asset_catalog requires an active .app bundle target",
            )))
        }
    };
    let offset = int_arg(args, "offset", 0) as u64;
    let limit = int_arg(args, "limit", 1_000) as u64;
    let result = match analyze_asset_catalogs(&AssetCatalogRequest {
        bundle_path: &bundle,
        target_sha256: &target.subject.digest.sha256,
        offset,
        limit,
    }) {
        Ok(result) => result,
        Err(error) => return Ok(error_result(&error)),
    };
    let limitations = strings_of(&result, "limitations");
    let locations = artifact_path_locations(
        result["catalogs"]
            .as_array()
            .map(|catalogs| catalogs.iter().filter_map(|c| c["path"].as_str().map(String::from)).collect::<Vec<_>>())
            .unwrap_or_default(),
    );
    let mut parameters = Map::new();
    for key in ["offset", "limit"] {
        if let Some(value) = args.get(key) {
            parameters.insert(key.to_string(), value.clone());
        }
    }
    evidence_result(
        session,
        Some(target.subject.clone()),
        artifact_graph_provider(),
        TOOL,
        Value::Object(parameters),
        result,
        limitations,
        locations,
    )
}
