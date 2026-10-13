//! `inspect_managed_members` (REA `ManagedMemberInspector`).

use serde_json::{json, Value};

use crate::budget::Budget;
use crate::common::{issues_json, unique_issues, Buf, Failure, Issue, R};
use crate::inventory::{read_metadata_inventory, read_resource_directory, table_row_counts};
use crate::layout::read_metadata_layout;
use crate::member_rows::{edges, parse_fields, parse_member_refs, parse_methods, parse_types, type_ranges};
use crate::pe::read_pe_layout;
use crate::ManagedTarget;

fn unavailable(target: &ManagedTarget, bytes: &[u8], issue: Option<&Issue>) -> R<Value> {
    let status = match issue {
        None => "absent",
        Some(issue) if issue.code == "resource-limit" => "partial",
        Some(_) => "malformed",
    };
    let value = json!({
        "artifact": { "path": target.path, "sha256": target.sha256, "byte_length": bytes.len(), "format": "pe" },
        "module": null,
        "metadata": { "status": status, "version": null, "table_row_counts": {} },
        "identity_scope": {
            "token_identity": "build-local",
            "requires_artifact_sha256": target.sha256,
            "requires_mvid": null,
        },
        "types": [],
        "fields": [],
        "methods": [],
        "member_refs": [],
        "call_edges": [],
        "field_accesses": [],
        "coverage": { "state": "unavailable", "issues": issues_json(&issue.cloned().into_iter().collect::<Vec<_>>()) },
        "limitations": [if issue.is_none() {
            "The PE has no admitted CLI metadata; managed member inspection is unavailable."
        } else {
            "The CLI metadata could not be admitted; managed member inspection is unavailable."
        }],
    });
    Budget::new().admit(value)
}

/// Inspect metadata members and method bodies without loading target code.
pub fn inspect_managed_members_bytes(bytes: &[u8], target: &ManagedTarget) -> Result<Value, Failure> {
    let pe = read_pe_layout(bytes)?;
    let Some(cli) = pe.cli.as_ref() else {
        return unavailable(target, bytes, pe.cli_issue.as_ref());
    };
    let buf = Buf(bytes);
    let mut issues: Vec<Issue> = Vec::new();
    let mut attempt = || -> R<Value> {
        // readMemberInventory
        let root_offset = pe.rva_to_offset(cli.metadata.rva, cli.metadata.size, "cli.metadata")?;
        let layout = read_metadata_layout(bytes, root_offset, cli.metadata.size)?;
        let resource_directory = read_resource_directory(&pe, &mut issues)?;
        let inventory = read_metadata_inventory(&buf, &layout, resource_directory)?;
        issues.extend(inventory.issues.iter().cloned());
        let ranges = type_ranges(&buf, &layout, &mut issues)?;
        let (types, type_issues) = parse_types(&buf, &layout, &ranges)?;
        issues.extend(type_issues);
        let fields = parse_fields(&buf, &layout, &ranges)?;
        let member_refs = parse_member_refs(&buf, &layout)?;
        issues.extend(member_refs.issues.iter().cloned());
        let methods = parse_methods(&buf, &layout, &pe, &ranges)?;
        issues.extend(fields.issues.iter().cloned());
        issues.extend(methods.issues.iter().cloned());
        let coverage_issues = unique_issues(&issues);
        let incomplete_signature = |value: &Value| value["signature"]["parse_status"] != "decoded";
        let incomplete_members = fields.fields.iter().any(incomplete_signature)
            || member_refs.refs.iter().any(incomplete_signature)
            || methods.methods.iter().any(|m| incomplete_signature(&m.json))
            || methods
                .methods
                .iter()
                .any(|m| matches!(m.json["body"]["status"].as_str(), Some("partial") | Some("malformed")));
        let (call_edges, field_accesses) = edges(&methods.methods, &methods.core, &fields.core, &member_refs.core);
        let complete = issues.is_empty() && !incomplete_members;
        let value = json!({
            "artifact": { "path": target.path, "sha256": target.sha256, "byte_length": bytes.len(), "format": "pe" },
            "module": inventory.module,
            "metadata": {
                "status": if issues.is_empty() { "complete" } else { "partial" },
                "version": layout.version,
                "table_row_counts": table_row_counts(&layout),
            },
            "identity_scope": {
                "token_identity": "build-local",
                "requires_artifact_sha256": target.sha256,
                "requires_mvid": inventory.module.as_ref().and_then(|m| m["mvid"].as_str()),
            },
            "types": types,
            "fields": fields.fields,
            "methods": methods.methods.iter().map(|m| m.json.clone()).collect::<Vec<Value>>(),
            "member_refs": member_refs.refs,
            "call_edges": call_edges,
            "field_accesses": field_accesses,
            "coverage": {
                "state": if complete { "complete" } else { "partial" },
                "issues": issues_json(&coverage_issues),
            },
            "limitations": [
                "Metadata tokens are build-local coordinates and are only meaningful with the reported artifact SHA-256 and MVID.",
                "CIL instruction anchors are decoded from file-backed method bodies only; no target assembly is loaded or executed.",
                "Signatures are decoded for common ECMA-335 primitive, class, valuetype, pointer, byref, array, and generic variable forms; unsupported forms retain raw signature hashes.",
            ],
        });
        layout.budget.admit(value)
    };
    match attempt() {
        Ok(value) => Ok(value),
        Err(Failure::Reader(issue)) => unavailable(target, bytes, Some(&issue)),
        Err(other) => Err(other),
    }
}
