//! Hopper operation set and limitations (port of `HopperProviderCapabilities.ts`).

use crate::provider::{CachePolicy, Capability, Effects, ProviderIdentity};

/// Analyst operations implemented by REA's private Hopper bridge.
pub const OPERATIONS: [&str; 36] = [
    "address_name",
    "comment",
    "current_address",
    "current_procedure",
    "current_document",
    "goto_address",
    "inline_comment",
    "list_bookmarks",
    "list_documents",
    "list_names",
    "list_procedures",
    "list_segments",
    "list_strings",
    "next_address",
    "prev_address",
    "procedure_address",
    "procedure_assembly",
    "procedure_callees",
    "procedure_callers",
    "procedure_info",
    "read_function_instructions",
    "read_bytes",
    "address_to_file_offset",
    "procedure_references",
    "procedure_pseudo_code",
    "resolve_containing_procedure",
    "search_procedures",
    "search_strings",
    "set_address_name",
    "set_addresses_names",
    "set_bookmark",
    "set_comment",
    "set_inline_comment",
    "unset_bookmark",
    "xrefs",
    "analyze_function",
];

const MUTATING: [&str; 6] = [
    "set_address_name",
    "set_addresses_names",
    "set_bookmark",
    "set_comment",
    "set_inline_comment",
    "unset_bookmark",
];

pub fn provider_identity() -> ProviderIdentity {
    ProviderIdentity::new("hopper", "Hopper Disassembler", None)
}

pub fn is_hopper_operation(operation: &str) -> bool {
    OPERATIONS.contains(&operation)
}

pub fn limitations_for(operation: &str) -> Vec<String> {
    let mut out = vec!["Results depend on Hopper's completed static analysis.".to_string()];
    if operation == "address_to_file_offset" {
        out.push("Original-file coordinates require source bytes matching the selected executable digest. A changed, unavailable, or database-only source retains native mapping facts in partial error evidence.".to_string());
    }
    if operation == "search_strings" || operation == "search_procedures" {
        out.push("Regex mode uses ECMAScript Unicode semantics in a supervised worker with a five-second matching deadline. Cancellation or deadline failure stops matching without blocking Hopper; literal mode retains native casefold semantics.".to_string());
    }
    if operation == "list_strings" || operation == "search_strings" || operation == "analyze_function" {
        out.push("String values cover native typed objects. Hopper may split long literals into adjacent unterminated fragments; string searches match each object independently.".to_string());
        out.push("Undecodable typed objects retain native display text with an explicit decoding unknown; these values do not establish decoded source literals.".to_string());
        out.push("Reported string encodings are inferred from typed bytes and native display; the original source's intended encoding is unknown.".to_string());
    }
    out
}

/// Source-owned capabilities without acquiring or probing a Hopper session.
pub fn capabilities(identity: &ProviderIdentity) -> Vec<Capability> {
    OPERATIONS
        .iter()
        .map(|operation| {
            let mutating = MUTATING.contains(operation);
            Capability {
                provider: identity.clone(),
                operation: (*operation).to_string(),
                available: true,
                reason: None,
                availability_code: None,
                cache_policy: CachePolicy::Unspecified,
                effects: Effects {
                    mutates_artifact: mutating,
                    launches_process: true,
                    may_show_ui: true,
                    may_access_network: false,
                    may_write_filesystem: mutating,
                    changes_permissions: false,
                    requires_root: false,
                },
                limitations: limitations_for(operation),
            }
        })
        .collect()
}
