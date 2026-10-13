//! Ghidra operation set, mutation policy and per-operation limitations
//! (port of `GhidraProviderCapabilities.ts` and the operation lists of
//! `GhidraInventoryValues.ts` / `GhidraFunctionValues.ts`).

use crate::provider::{CachePolicy, Capability, Effects, ProviderIdentity};

/// Direct inventory operations admitted by the Ghidra adapter.
pub const INVENTORY_OPERATIONS: [&str; 15] = [
    "inspect_native_load_image",
    "read_bytes",
    "address_to_file_offset",
    "address_name",
    "list_documents",
    "list_names",
    "list_procedures",
    "list_segments",
    "list_strings",
    "procedure_address",
    "resolve_containing_procedure",
    "search_procedures",
    "search_strings",
    "set_address_name",
    "set_addresses_names",
];

/// Function analysis and annotation operations admitted by the Ghidra adapter.
pub const FUNCTION_OPERATIONS: [&str; 13] = [
    "annotate_native_function",
    "inspect_native_data_type",
    "inspect_native_instruction",
    "resolve_native_call_targets",
    "analyze_function",
    "procedure_assembly",
    "procedure_callees",
    "procedure_callers",
    "procedure_info",
    "procedure_pseudo_code",
    "read_function_instructions",
    "procedure_references",
    "xrefs",
];

pub const NAMING_OPERATIONS: [&str; 2] = ["set_address_name", "set_addresses_names"];

pub fn is_inventory_operation(operation: &str) -> bool {
    INVENTORY_OPERATIONS.contains(&operation)
}

pub fn is_function_operation(operation: &str) -> bool {
    FUNCTION_OPERATIONS.contains(&operation)
}

pub fn is_ghidra_operation(operation: &str) -> bool {
    is_inventory_operation(operation) || is_function_operation(operation)
}

/// Methods that edit the session database; read-only bridges omit them.
pub fn is_mutating_operation(operation: &str) -> bool {
    operation == "annotate_native_function" || NAMING_OPERATIONS.contains(&operation)
}

/// Every operation a session proves through the handshake, in bridge order.
pub fn session_capabilities() -> Vec<&'static str> {
    let mut all = vec!["ping", "shutdown"];
    all.extend(INVENTORY_OPERATIONS);
    all.extend(FUNCTION_OPERATIONS);
    all
}

pub fn provider_identity() -> ProviderIdentity {
    ProviderIdentity::new("ghidra", "Ghidra", None)
}

/// Health limitations shared by every Ghidra-backed capability.
pub fn health_limitations() -> Vec<String> {
    vec![
        "The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.".to_string(),
        "The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.".to_string(),
        "Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.".to_string(),
    ]
}

/// Limitation text for one admitted operation, including the common base.
pub fn limitations_for(operation: &str) -> Vec<String> {
    let mut common = health_limitations();
    common.push("Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.".to_string());
    let extra: Vec<&str> = match operation {
        "annotate_native_function" => vec![
            "Names use Ghidra USER_DEFINED source. Name writes accept a leaf name or a fully qualified name within the existing namespace; readback uses the fully qualified name and can be reused without adding namespace prefixes. Edits retain the current namespace; other namespace-like text remains literal leaf-name text. Regular comments map to PRE and inline comments to EOL at the exact function entry. Changes commit together after readback and refreshed analysis; failure rolls them all back.",
            "Annotation text rejects NUL and unpaired Unicode surrogates before mutation, with the field and UTF-16 index in the error. Supported Unicode and line endings are preserved.",
            "Metadata edits invalidate immutable analysis snapshots and are discarded on close. CLI returns the updated dossier before session cleanup; this is not a saved Ghidra project.",
        ],
        "set_address_name" | "set_addresses_names" => vec![
            "Names use Ghidra USER_DEFINED source. A local function entry renames that function; any other mapped address receives a new or renamed primary label. Existing symbols retain their namespace and accept leaf names or qualified names within that namespace; qualified readback can be reused without adding namespace prefixes. Readback compares the primary symbol name.",
            "set_addresses_names applies each address in its own transaction and reports per-address success; invalid names, unmapped addresses, and readback mismatches roll back only that address.",
            "Metadata edits invalidate immutable analysis snapshots and are discarded on close; this is not a saved Ghidra project.",
        ],
        "inspect_native_load_image" => vec![
            "Independent verification supports DOS MZ and explicitly selected COM, including measured COM entry context. Measured source mappings use inclusive end addresses and complete region digests; no target execution or project mutation occurs.",
        ],
        "read_bytes" => vec![
            "Bytes reflect Ghidra's initialized memory, including loader fixups. Reads stop at an unmapped or uninitialized byte and report completeness explicitly.",
        ],
        "address_to_file_offset" => vec![
            "Offsets come from Ghidra source-byte mappings, not virtual-address arithmetic. Uninitialized memory, missing mappings and ambiguous mappings fail explicitly.",
        ],
        "list_documents" => vec![
            "A headless Ghidra session contains exactly one imported Program, unlike Hopper's multi-document GUI session.",
        ],
        "list_names" => vec![
            "The symbol inventory includes memory and external symbols, including dynamic symbols, but excludes variable and no-address namespace records.",
        ],
        "list_procedures" | "procedure_address" => vec![
            "External functions and local thunks are distinct; procedure metadata identifies both and preserves a thunk target when Ghidra resolves one.",
        ],
        "list_strings" => vec![
            "Only Ghidra-defined string Data is observed; charset is reported, while a non-missing terminator cannot distinguish a present terminator from a fixed or Pascal layout.",
        ],
        "resolve_containing_procedure" => vec![
            "An exact external entry resolves to its observed function identity even when its body is empty. This does not establish mapped executable bytes or containment of nearby external addresses.",
        ],
        "list_segments" => vec![
            "Memory-block end addresses are exclusive; permissions come from Ghidra MemoryBlock flags rather than inference from section names.",
        ],
        "search_procedures" | "search_strings" => vec![
            "Regex mode uses Java Pattern semantics. Matcher or compiler stack exhaustion returns a resource constraint without closing the session; literal mode avoids regex recursion and returns complete matching values.",
        ],
        "procedure_pseudo_code" => vec![
            "Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.",
            "External functions and functions without an analyzable body return null; other decompiler failures remain explicit.",
        ],
        "read_function_instructions" => vec![
            "This fast path reads only the requested function and does not invoke the decompiler or whole-program string/name inventories.",
            "Instruction text is Ghidra-specific and does not claim textual equivalence with Hopper output.",
        ],
        "procedure_assembly" => vec![
            "Assembly is Ghidra Listing text and does not claim textual equivalence with Hopper output.",
        ],
        "procedure_callers" | "procedure_callees" => vec![
            "Only resolved Ghidra call references are returned; unresolved computed or indirect calls remain unknown, while function classifications distinguish thunks and externals.",
        ],
        "xrefs" => vec![
            "The direct address list projects exact Ghidra references to one address but does not expose their kinds; procedure_references and analyze_function preserve available kind metadata.",
            "Synthetic Ghidra entry-point references without actionable memory sources are omitted.",
        ],
        "procedure_references" => vec![
            "References cover the complete Ghidra function-body AddressSet and exact entry, including instruction-interior destinations and embedded-data sources; an enclosing address span does not establish function ownership.",
            "Reference kinds are direct Ghidra ReferenceManager observations; unresolved computed flows without a target are absent and remain unknown.",
            "Synthetic Ghidra entry-point references without actionable memory sources are omitted.",
        ],
        "analyze_function" => vec![
            "References cover the complete Ghidra function-body AddressSet and exact entry. Dossier incoming edges omit sources owned by that function; procedure_references also retains those internal edges.",
            "The dossier combines Ghidra FunctionManager, Listing, ReferenceManager, BasicBlockModel, and decompiler observations; provider-specific pseudocode and assembly are not cross-provider text invariants.",
            "Resolved reference metadata identifies computed, indirect, external, call, jump, and data edges; unresolved targetless flows remain unknown, and function classifications distinguish thunks and externals.",
            "Synthetic Ghidra entry-point references without actionable memory sources are omitted.",
            "The Java bridge serializes one function request per Program and lets each decompilation run until it completes or the caller cancels.",
        ],
        _ => vec![],
    };
    common.extend(extra.into_iter().map(str::to_string));
    common
}

/// Provider-neutral capabilities advertised by every Ghidra session on POSIX hosts.
pub fn capabilities(identity: &ProviderIdentity) -> Vec<Capability> {
    INVENTORY_OPERATIONS
        .iter()
        .chain(FUNCTION_OPERATIONS.iter())
        .map(|operation| Capability {
            provider: identity.clone(),
            operation: (*operation).to_string(),
            available: true,
            reason: None,
            availability_code: None,
            cache_policy: if is_mutating_operation(operation) || *operation == "list_documents" {
                CachePolicy::Unspecified
            } else {
                CachePolicy::Snapshot
            },
            effects: Effects {
                mutates_artifact: is_mutating_operation(operation),
                launches_process: true,
                may_show_ui: false,
                may_access_network: false,
                may_write_filesystem: true,
                changes_permissions: false,
                requires_root: false,
            },
            limitations: limitations_for(operation),
        })
        .collect()
}
