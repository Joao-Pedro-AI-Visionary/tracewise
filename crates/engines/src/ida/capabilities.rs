//! IDA identity, operation set and shared limitations
//! (port of `IdaProviderCapabilities.ts`).

use crate::provider::{CachePolicy, Capability, Effects, ProviderIdentity};

use super::config::IdaMode;

/// The version identifies REA's adapter, not IDA or the upstream Python package.
pub fn provider_identity() -> ProviderIdentity {
    ProviderIdentity::new("ida", "IDA Pro MCP adapter", Some("1"))
}

/// Read-only analyst outcomes supported by both upstream compatibility profiles.
pub const IDA_OPERATIONS: [&str; 12] = [
    "list_procedures",
    "search_procedures",
    "list_strings",
    "search_strings",
    "procedure_address",
    "procedure_pseudo_code",
    "procedure_assembly",
    "procedure_callers",
    "procedure_callees",
    "read_function_instructions",
    "xrefs",
    "analyze_function",
];

pub fn is_ida_operation(operation: &str) -> bool {
    IDA_OPERATIONS.contains(&operation)
}

/// Shared limitations of observations from an externally mutable analysis database.
pub fn ida_limitations() -> Vec<String> {
    [
        "Provider version identifies the REA IDA adapter. IDA engine and upstream distribution versions are unknown unless separately observed; MCP serverInfo is reported independently.",
        "Results describe the current IDA analysis database. Input identity does not prove an unmodified database; patches, annotations, analysis completeness, and database revision remain unknown.",
        "Live results are never replayed from analysis snapshots. Target checks before and after a request do not provide an atomic lock against external GUI changes.",
        "Caller cancellation drains the in-flight MCP request before cleanup; it does not prove that IDA engine work was interrupted.",
        "Headless workers are released through the upstream database lifecycle. Abrupt termination of REA, its proxy, or the supervisor cannot prove worker cleanup; inspect upstream inventory after an interrupted process.",
        "Complete function body ranges, typed references, unresolved indirect calls, referenced data, and basic blocks are unavailable in this adapter. Empty unsupported dossier facets are unknown, not observed absence.",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Why headless mode cannot report direct callers.
pub const HEADLESS_CALLERS_REASON: &str =
    "The modern upstream profile reports code references without proving direct call edges.";

/// Advertise live observations and configured lifecycle effects truthfully.
pub fn capabilities(mode: IdaMode, stdio: bool) -> Vec<Capability> {
    let identity = provider_identity();
    let launches = stdio || mode == IdaMode::Headless;
    IDA_OPERATIONS
        .iter()
        .map(|operation| {
            let unavailable = mode == IdaMode::Headless && *operation == "procedure_callers";
            Capability {
                provider: identity.clone(),
                operation: (*operation).to_string(),
                available: !unavailable,
                reason: unavailable.then(|| HEADLESS_CALLERS_REASON.to_string()),
                availability_code: None,
                cache_policy: CachePolicy::Live,
                effects: Effects {
                    mutates_artifact: false,
                    launches_process: launches,
                    may_show_ui: false,
                    may_access_network: true,
                    may_write_filesystem: launches,
                    changes_permissions: false,
                    requires_root: false,
                },
                limitations: ida_limitations(),
            }
        })
        .collect()
}
