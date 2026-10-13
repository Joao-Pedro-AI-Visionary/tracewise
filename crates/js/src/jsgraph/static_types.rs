//! Result types of the AST-only static analysis (REA `javascriptStaticAnalysisTypes.ts` and
//! `electronStaticAnalysisTypes.ts`). Field names are the REA JSON names.
//!
//! TypeScript unions that are intersections of discriminated parts are flattened into one struct
//! whose inactive members are `None` (serialized as `null`, exactly as REA emits them).

use serde::{Deserialize, Serialize};

pub use super::ast::{SourcePoint, SourceRange};

fn is_none<T>(value: &Option<T>) -> bool {
    value.is_none()
}

/// `"module-specifier"` or `"filesystem-expression"`.
pub type StaticPathContext = String;

/// Receiver identity facts for the overloaded `.open` syntax (REA `JavaScriptOpenReceiverFact`),
/// keyed by call-expression start offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OpenReceiverFact {
    Window,
    IndexedDb,
    CacheStorage,
    Local,
    LocalIndexedDb,
    LocalCacheStorage,
}

/// A statically visible module, worker, or service-worker reference.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StaticReference {
    /// `static-import`, `dynamic-import`, `require`, `worker`, `service-worker`.
    pub kind: String,
    pub module_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub module_runtime: Option<String>,
    pub location: SourceRange,
    pub specifier: Option<String>,
    pub expression: Option<String>,
}

/// A route or network endpoint literal observed in syntax.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StaticEndpoint {
    /// `route` or `network`.
    pub kind: String,
    pub value: String,
    pub mechanism: String,
    pub module_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub module_runtime: Option<String>,
    pub location: SourceRange,
}

/// A storage surface observed without executing application code.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StaticStorage {
    /// `local-storage`, `session-storage`, `indexed-db`, `cache-storage`, `sqlite`.
    pub kind: String,
    pub name: Option<String>,
    pub mechanism: String,
    pub module_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub module_runtime: Option<String>,
    pub location: SourceRange,
}

/// One exact module factory recovered from a Webpack/Rspack registration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BundlerModule {
    pub module_key: String,
    pub factory_require_name: Option<String>,
    pub source_sha256: String,
    pub exports: Vec<String>,
    pub location: SourceRange,
    pub structural_fingerprint_sha256: String,
    /// Always `babel-ast-v1`.
    pub structural_fingerprint_algorithm: String,
}

/// One statically recognized bundler chunk or module registration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BundlerRegistration {
    /// `webpack`, `rspack`, `esbuild`.
    pub bundler: String,
    pub runtime: String,
    pub chunk_keys: Vec<String>,
    pub unknown_chunk_keys: u64,
    pub runtime_require_name: Option<String>,
    /// `observed` or `not-observed`.
    pub runtime_module_cache_status: String,
    pub entry_module_keys: Vec<String>,
    pub unknown_entry_module_keys: u64,
    pub async_chunk_keys: Vec<String>,
    pub unknown_async_chunk_keys: u64,
    pub modules: Vec<BundlerModule>,
    pub location: SourceRange,
}

/// Static Electron role paths discovered from package or JavaScript syntax.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RolePath {
    /// `preload` or `renderer`.
    pub role: String,
    pub path: String,
    pub resolution_context: StaticPathContext,
    pub mechanism: String,
    pub module_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub module_runtime: Option<String>,
    pub location: SourceRange,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SourceMapUrl {
    pub declared_url: String,
    pub location: SourceRange,
}

/// One inert literal or unresolved expression observed in Electron syntax.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElectronStaticValue {
    /// `literal` or `dynamic`.
    pub status: String,
    /// `string | number | boolean | null` (null for dynamic values).
    pub value: super::ir::Primitive,
    pub expression: Option<String>,
}

/// One explicitly present BrowserWindow webPreference.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElectronWebPreference {
    pub name: String,
    pub value: ElectronStaticValue,
}

/// Statically visible BrowserWindow construction and preference surface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElectronBrowserWindowFinding {
    pub preload_path: Option<String>,
    pub preload_resolution_context: Option<StaticPathContext>,
    /// `object-literal`, `dynamic`, `missing`.
    pub options_status: String,
    pub web_preferences_status: String,
    pub web_preferences: Vec<ElectronWebPreference>,
    pub module_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub module_runtime: Option<String>,
    pub location: SourceRange,
}

/// One contextBridge API declaration without executing its API object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElectronContextBridgeFinding {
    pub api_key: Option<String>,
    pub api_key_expression: Option<String>,
    /// `main` or `isolated`.
    pub world: String,
    pub world_id: Option<ElectronStaticValue>,
    pub api_status: String,
    pub members: Vec<String>,
    pub unknown_members: u64,
    pub module_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub module_runtime: Option<String>,
    pub location: SourceRange,
}

/// One statically visible Electron IPC send, invocation, listener, or handler.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElectronIpcFinding {
    /// `renderer` or `main`.
    pub side: String,
    pub operation: String,
    /// `send`, `invoke`, `listen`, `handle`.
    pub mode: String,
    pub handler_kind: Option<String>,
    pub handler_location: Option<SourceRange>,
    pub module_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub module_runtime: Option<String>,
    pub location: SourceRange,
    pub channel: Option<String>,
    pub channel_expression: Option<String>,
}

/// Static check involving an IPC sender, frame, process, URL, or origin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElectronSenderValidationFinding {
    pub subject: String,
    pub mechanism: String,
    pub expected: ElectronStaticValue,
    /// Always `unknown`.
    pub enforcement: String,
    pub module_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub module_runtime: Option<String>,
    pub location: SourceRange,
}

/// One utilityProcess.fork declaration and its statically visible entrypoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElectronUtilityProcessFinding {
    pub service_name: Option<String>,
    pub module_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub module_runtime: Option<String>,
    pub location: SourceRange,
    pub module_path: Option<String>,
    pub module_resolution_context: Option<StaticPathContext>,
    pub module_expression: Option<String>,
}

/// JavaScript-side binding or re-export requested from one native `.node` addon.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElectronNativeAddonBindingFinding {
    pub specifier: String,
    /// `import`, `require`, `re-export`.
    pub binding_kind: String,
    /// `import` or `require`.
    pub module_kind: String,
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub namespace_access: Option<bool>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub dynamic_member_access: Option<bool>,
    pub module_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub module_runtime: Option<String>,
    pub location: SourceRange,
}

/// All Electron-specific facts collected during one shared AST traversal.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ElectronStaticFindings {
    pub browser_windows: Vec<ElectronBrowserWindowFinding>,
    pub context_bridge_apis: Vec<ElectronContextBridgeFinding>,
    pub ipc: Vec<ElectronIpcFinding>,
    pub sender_validations: Vec<ElectronSenderValidationFinding>,
    pub utility_processes: Vec<ElectronUtilityProcessFinding>,
    pub native_addon_bindings: Vec<ElectronNativeAddonBindingFinding>,
}

/// Deterministic AST-only analysis of one JavaScript source file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StaticAnalysis {
    /// `complete`, `partial`, `failed`.
    pub parse_status: String,
    pub parse_error_count: u64,
    pub visited_ast_nodes: u64,
    pub references: Vec<StaticReference>,
    pub endpoints: Vec<StaticEndpoint>,
    pub storage: Vec<StaticStorage>,
    pub bundler_registrations: Vec<BundlerRegistration>,
    pub role_paths: Vec<RolePath>,
    pub source_map_urls: Vec<SourceMapUrl>,
    pub vendors: Vec<String>,
    pub electron: ElectronStaticFindings,
    pub limitations: Vec<String>,
}

impl StaticAnalysis {
    /// REA `failedJavaScriptStaticAnalysis`.
    pub fn failed() -> StaticAnalysis {
        StaticAnalysis {
            parse_status: "failed".into(),
            parse_error_count: 1,
            visited_ast_nodes: 0,
            references: Vec::new(),
            endpoints: Vec::new(),
            storage: Vec::new(),
            bundler_registrations: Vec::new(),
            role_paths: Vec::new(),
            source_map_urls: Vec::new(),
            vendors: Vec::new(),
            electron: ElectronStaticFindings::default(),
            limitations: vec![
                "JavaScript source could not be parsed; absence of findings is not evidence of absence.".into(),
                "JavaScript syntax was parsed as data and was never evaluated.".into(),
            ],
        }
    }
}
