//! Provider-neutral JavaScript semantic IR (REA `javascriptSemanticIr.ts`,
//! `javascriptSemanticValueTypes.ts`, `javascriptSemanticCoverage.ts`). Field names are the REA
//! JSON names (camelCase), so `serde_json::to_value(ir)` is directly comparable to REA's output.

use serde::{Deserialize, Serialize, Serializer};

pub use super::ast::SourceRange;

fn is_none<T>(value: &Option<T>) -> bool {
    value.is_none()
}

/// A JavaScript number: integral values serialize as JSON integers (like `JSON.stringify`),
/// `-0` as `0`, and non-finite values as `null`.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize)]
#[serde(transparent)]
pub struct JsNumber(pub f64);

impl Serialize for JsNumber {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.0;
        if !value.is_finite() {
            serializer.serialize_none()
        } else if value.fract() == 0.0 && value.abs() < 9.2e18 {
            serializer.serialize_i64(value as i64)
        } else {
            serializer.serialize_f64(value)
        }
    }
}

/// `string | number | boolean | null`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Primitive {
    Null,
    Bool(bool),
    Num(JsNumber),
    Str(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceLimit {
    PrimitiveCandidates,
    PrimitiveBytes,
    ExpressionDepth,
}

impl ResourceLimit {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceLimit::PrimitiveCandidates => "primitive-candidates",
            ResourceLimit::PrimitiveBytes => "primitive-bytes",
            ResourceLimit::ExpressionDepth => "expression-depth",
        }
    }
}

/// Own-slot presence, independent of its value and sibling coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SlotPresence {
    Present,
    Absent,
    UnknownCoverage,
}

/// One statically named own slot in an object or array.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SemanticProperty {
    pub name: String,
    pub value: SemanticValue,
    pub presence: SlotPresence,
}

/// Execution-free value lattice for JavaScript expressions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum SemanticValue {
    Literal {
        value: Primitive,
    },
    Union {
        values: Vec<Primitive>,
    },
    #[serde(rename_all = "camelCase")]
    Object {
        properties: Vec<SemanticProperty>,
        unknown_properties: bool,
        /// `0` when `unknown_properties` is false; a count or `null` when true.
        omitted_properties: Option<u64>,
    },
    #[serde(rename_all = "camelCase")]
    Array {
        items: Vec<SemanticProperty>,
        unknown_items: bool,
        omitted_items: Option<u64>,
    },
    #[serde(rename_all = "camelCase")]
    Unknown {
        reason: String,
        #[serde(default, skip_serializing_if = "is_none")]
        resource_limit: Option<ResourceLimit>,
    },
    #[serde(rename_all = "camelCase")]
    Ambiguous {
        reason: String,
        #[serde(default, skip_serializing_if = "is_none")]
        resource_limit: Option<ResourceLimit>,
    },
    #[serde(rename_all = "camelCase")]
    Cycle {
        reason: String,
        #[serde(default, skip_serializing_if = "is_none")]
        resource_limit: Option<ResourceLimit>,
    },
}

/// Coverage state for one semantic recovery pass.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCoverage {
    /// `complete`, `partial`, `failed`.
    pub status: String,
    pub omitted_count: Option<u64>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub resource_limits: Option<Vec<ResourceLimit>>,
}

/// Exact retention state for one callable's direct returns.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReturnCoverage {
    pub status: String,
    pub retained_count: u64,
    pub omitted_count: Option<u64>,
}

/// One exact module origin followed through imports, requires, or aliases.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleOrigin {
    pub specifier: String,
    pub imported_path: Vec<String>,
}

/// Fail-closed provenance classification for one binding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BindingProvenance {
    /// `module`, `local`, `ambiguous`, `unknown`, `cycle`.
    pub status: String,
    pub origins: Vec<ModuleOrigin>,
    pub reason: Option<String>,
}

/// One lexical scope recovered without executing source.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticScope {
    pub scope_id: String,
    pub parent_scope_id: Option<String>,
    /// `program`, `function`, `block`, `static-block`, `class`, `catch`.
    pub kind: String,
    pub location: SourceRange,
    pub bindings_complete: bool,
    pub binding_ids: Vec<String>,
}

/// One declaration or assignment contributing to a binding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SemanticDefinition {
    /// `import`, `variable`, `parameter`, `function`, `class`, `catch`, `assignment`.
    pub kind: String,
    pub location: SourceRange,
}

/// One resolved lexical binding plus static value and provenance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticBinding {
    pub binding_id: String,
    pub scope_id: String,
    pub name: String,
    pub kind: String,
    pub mutable: bool,
    pub definitions: Vec<SemanticDefinition>,
    pub value: SemanticValue,
    pub provenance: BindingProvenance,
}

/// One identifier use and its fail-closed lexical resolution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticReference {
    pub name: String,
    /// `read`, `write`, `export`.
    pub role: String,
    pub location: SourceRange,
    pub binding_id: Option<String>,
    /// `resolved`, `unbound`, `ambiguous`, `unknown`.
    pub resolution: String,
}

/// One direct return expression belonging to exactly one callable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticReturnSite {
    pub return_site_id: String,
    pub location: SourceRange,
    pub identity_reference_location: Option<SourceRange>,
    pub value: SemanticValue,
}

/// Function, class, or method identity without pretending it is a binding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCallable {
    pub callable_id: String,
    /// `function`, `class`, `method`.
    pub kind: String,
    pub name: Option<String>,
    pub container_scope_id: String,
    pub body_scope_id: Option<String>,
    pub location: SourceRange,
    pub return_sites: Vec<SemanticReturnSite>,
    pub return_coverage: ReturnCoverage,
}

/// One argument occurrence retained without evaluating application code.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SemanticCallArgument {
    pub index: u64,
    pub location: SourceRange,
    pub spread: bool,
}

/// One statically visible call or construction expression.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCallSite {
    pub call_site_id: String,
    /// `call` or `construct`.
    pub kind: String,
    pub caller_callable_id: Option<String>,
    pub location: SourceRange,
    pub callee_location: SourceRange,
    /// `exact`, `ambiguous`, `unresolved`.
    pub resolution: String,
    pub callee_callable_ids: Vec<String>,
    pub arguments: Vec<SemanticCallArgument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticArgumentFlow {
    pub call_site_id: String,
    pub argument_index: u64,
    pub argument_location: SourceRange,
    pub callable_id: String,
    pub parameter_binding_id: String,
    pub parameter_location: SourceRange,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCallReturnFlow {
    pub call_site_id: String,
    pub callable_id: String,
    pub return_site_id: String,
    pub return_location: SourceRange,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCallResultFlow {
    pub call_site_id: String,
    pub binding_id: String,
    pub definition_location: SourceRange,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticClosureCapture {
    pub callable_id: String,
    pub binding_id: String,
    pub reference_location: SourceRange,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticPromiseOperation {
    pub promise_id: String,
    /// `constructor`, `static`, `chain`, `aggregate`, `awaited-expression`.
    pub kind: String,
    /// `new`, `resolve`, `reject`, `then`, `catch`, `finally`, `all`, `allSettled`, `await`.
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    /// `awaited`, `returned`, `detached`, `assigned`, `chained`, `aggregated`, `unknown`.
    pub ownership: String,
    pub owner_binding_id: Option<String>,
    pub return_site_id: Option<String>,
    pub source_promise_ids: Vec<String>,
    /// `complete`, `partial`, `unresolved`.
    pub source_resolution: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintComponents {
    pub parameter_arity: u64,
    pub normalized_ast_sha256: String,
    pub control_flow_sha256: String,
    pub relation_shape_sha256: String,
    pub literal_set_sha256: String,
    /// `async`, `child-process`, `event`, `network`, `promise`, `resource`, `timer`.
    pub effects: Vec<String>,
}

/// Rename-resistant bounded component commitment for one callable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticFunctionFingerprint {
    pub callable_id: String,
    /// `complete`, `partial`, `unavailable`.
    pub status: String,
    pub components: FingerprintComponents,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticEventOperation {
    pub event_id: String,
    /// `register`, `remove`, `dispatch`.
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub emitter_key: String,
    pub emitter_binding_id: Option<String>,
    pub event_name: Option<String>,
    pub listener_binding_id: Option<String>,
    pub listener_location: Option<SourceRange>,
    pub resolution: String,
}

/// A destructured result binding with its known projection path.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectedResultBinding {
    pub binding_id: String,
    /// Entries are strings, numbers, or `null`.
    pub projection_path: Vec<Option<ProjectionKey>>,
    pub resolution: String,
}

/// One projection path element: a property name or an array index.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProjectionKey {
    Index(u64),
    Name(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticTimerOperation {
    pub timer_id: String,
    /// `schedule` or `cancel`.
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub handle_binding_id: Option<String>,
    pub projected_result_bindings: Vec<ProjectedResultBinding>,
    pub linked_timer_id: Option<String>,
    pub delay_milliseconds: Option<JsNumber>,
    pub resolution: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticChildProcessSpawn {
    pub process_id: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub result_binding_id: Option<String>,
    pub projected_result_bindings: Vec<ProjectedResultBinding>,
    pub command: Option<String>,
    pub argv_count: Option<u64>,
    pub environment_supplied: bool,
    pub stdio_mode: String,
    pub resolution: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticChildProcessInteraction {
    pub interaction_id: String,
    /// `listener` or `signal`.
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub process_binding_id: Option<String>,
    pub linked_process_ids: Vec<String>,
    pub event_name: Option<String>,
    pub signal_name: Option<String>,
    pub listener_location: Option<SourceRange>,
    pub resolution: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticConfigurationOperation {
    pub config_id: String,
    /// `environment`, `argv`, `file`, `default`.
    pub kind: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub result_binding_id: Option<String>,
    pub key: Option<String>,
    pub source_config_id: Option<String>,
    pub value: Primitive,
    pub resolution: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestField {
    pub name: String,
    pub source_binding_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticRequestOperation {
    pub request_id: String,
    /// `request` or `response-consumer`.
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub result_binding_id: Option<String>,
    pub projected_result_bindings: Vec<ProjectedResultBinding>,
    pub linked_request_ids: Vec<String>,
    pub endpoint: Option<String>,
    pub fields: Vec<RequestField>,
    pub resolution: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticBoundaryOperation {
    pub boundary_id: String,
    /// `parse`, `coerce`, `validate`.
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub source_binding_id: Option<String>,
    pub result_binding_id: Option<String>,
    pub resolution: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticResourceOperation {
    pub resource_id: String,
    /// `acquire` or `release`.
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub result_binding_id: Option<String>,
    pub linked_resource_ids: Vec<String>,
    pub resolution: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticObjectOperation {
    pub object_operation_id: String,
    /// `read`, `write`, `spread`, `destructure`.
    pub kind: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub object_binding_id: Option<String>,
    pub target_binding_id: Option<String>,
    pub property_path: Option<Vec<String>>,
    pub resolution: String,
}

/// One syntax location where exact local semantic continuation is unavailable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticFrontier {
    /// `dynamic-call`, `dynamic-property`, `dynamic-scope`.
    pub kind: String,
    pub callable_id: Option<String>,
    pub location: SourceRange,
    pub reason: String,
}

/// Static import/export relationship retained for cross-file composition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticModuleLink {
    /// `import`, `require`, `export`, `re-export`, `commonjs-export`.
    pub kind: String,
    pub specifier: Option<String>,
    pub imported_name: Option<String>,
    pub local_name: Option<String>,
    pub exported_name: Option<String>,
    pub callable_id: Option<String>,
    pub location: SourceRange,
}

/// Provider-neutral JavaScript semantic IR.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticIr {
    /// Always `JavaScriptSemanticIR`.
    pub schema: String,
    pub scopes: Vec<SemanticScope>,
    pub bindings: Vec<SemanticBinding>,
    pub callables: Vec<SemanticCallable>,
    pub references: Vec<SemanticReference>,
    pub module_links: Vec<SemanticModuleLink>,
    pub call_sites: Vec<SemanticCallSite>,
    pub argument_flows: Vec<SemanticArgumentFlow>,
    pub call_return_flows: Vec<SemanticCallReturnFlow>,
    pub call_result_flows: Vec<SemanticCallResultFlow>,
    pub closure_captures: Vec<SemanticClosureCapture>,
    pub promise_operations: Vec<SemanticPromiseOperation>,
    pub event_operations: Vec<SemanticEventOperation>,
    pub timer_operations: Vec<SemanticTimerOperation>,
    pub child_process_spawns: Vec<SemanticChildProcessSpawn>,
    pub child_process_interactions: Vec<SemanticChildProcessInteraction>,
    pub configuration_operations: Vec<SemanticConfigurationOperation>,
    pub request_operations: Vec<SemanticRequestOperation>,
    pub boundary_operations: Vec<SemanticBoundaryOperation>,
    pub resource_operations: Vec<SemanticResourceOperation>,
    pub object_operations: Vec<SemanticObjectOperation>,
    pub function_fingerprints: Vec<SemanticFunctionFingerprint>,
    pub frontiers: Vec<SemanticFrontier>,
    pub coverage: SemanticCoverage,
    pub limitations: Vec<String>,
}

impl SemanticIr {
    /// REA `failedJavaScriptSemanticIr`.
    pub fn failed() -> SemanticIr {
        SemanticIr {
            schema: "JavaScriptSemanticIR".into(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            callables: Vec::new(),
            references: Vec::new(),
            module_links: Vec::new(),
            call_sites: Vec::new(),
            argument_flows: Vec::new(),
            call_return_flows: Vec::new(),
            call_result_flows: Vec::new(),
            closure_captures: Vec::new(),
            promise_operations: Vec::new(),
            event_operations: Vec::new(),
            timer_operations: Vec::new(),
            child_process_spawns: Vec::new(),
            child_process_interactions: Vec::new(),
            configuration_operations: Vec::new(),
            request_operations: Vec::new(),
            boundary_operations: Vec::new(),
            resource_operations: Vec::new(),
            object_operations: Vec::new(),
            function_fingerprints: Vec::new(),
            frontiers: Vec::new(),
            coverage: SemanticCoverage {
                status: "failed".into(),
                omitted_count: None,
                resource_limits: None,
            },
            limitations: vec![
                "JavaScript parsing failed; no semantic absence claim is available.".into(),
                "No JavaScript was executed.".into(),
            ],
        }
    }
}
