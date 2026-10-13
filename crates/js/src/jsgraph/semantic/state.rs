//! Port of `javascriptSemanticState.ts`: the mutable construction state shared by semantic
//! collection and evaluation.
//!
//! JS object identity becomes arena indices: a binding is a [`BindingIx`] into
//! [`SemanticAnalysisState::bindings`] (creation order = `Map` insertion order of
//! `bindingsById`) and a scope is a [`ScopeIx`] into [`SemanticAnalysisState::scopes`]. AST nodes
//! are [`N`] cursors (compared by id), the Rust analogue of `WeakMap<t.Node, ..>` keys.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use crate::jsgraph::ast::{Ast, Kind, NodeId, SourceRange, N};
use crate::jsgraph::ir::{
    ModuleOrigin, SemanticCallable, SemanticDefinition, SemanticModuleLink, SemanticValue,
};

use super::property_paths::{PathKey, PropertyPath};

/// Index of a binding in [`SemanticAnalysisState::bindings`].
pub type BindingIx = usize;
/// Index of a scope in [`SemanticAnalysisState::scopes`].
pub type ScopeIx = usize;

/// Internal initializer plus a destructuring/member projection.
#[derive(Clone, Debug)]
pub struct SemanticInitializer<'a> {
    pub node: N<'a>,
    pub projection: Vec<PathKey>,
    /// Set when the initializer is the copy of a parameter into its separate body var scope.
    pub entry_body: Option<N<'a>>,
}

/// `{ node, projection }` source of a default value or destructured reference.
#[derive(Clone, Debug)]
pub struct SourceRef<'a> {
    pub node: N<'a>,
    pub projection: PropertyPath,
}

/// How a shallow-copy reference (rest element) was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyKind {
    ObjectRest,
    ArrayRest,
}

/// Additional references from destructuring copies and possible defaults.
#[derive(Clone, Debug)]
pub struct ReferenceInitializer<'a> {
    pub node: N<'a>,
    pub projection: Vec<PathKey>,
    pub copy_kind: Option<CopyKind>,
    pub copy_projection_offset: Option<usize>,
    pub copy_excluded_keys: Option<Vec<String>>,
    pub copy_start_index: Option<u64>,
    pub fallback_sources: Option<Vec<SourceRef<'a>>>,
    pub required_sources: Option<Vec<SourceRef<'a>>>,
}

/// One escape of an object reference with the node that caused it.
#[derive(Clone, Debug)]
pub struct EscapedPath<'a> {
    pub path: PropertyPath,
    pub node: Option<N<'a>>,
}

/// Mutable binding state used only while constructing the immutable IR.
#[derive(Clone, Debug)]
pub struct BindingState<'a> {
    pub binding_id: String,
    pub scope_id: String,
    pub name: String,
    /// `import`, `variable`, `parameter`, `function`, `class`, `catch`, `assignment`.
    pub kind: &'static str,
    pub mutable: bool,
    pub mutated_paths: Vec<PropertyPath>,
    pub escaped_paths: Vec<EscapedPath<'a>>,
    pub definitions: Vec<SemanticDefinition>,
    pub initializers: Vec<SemanticInitializer<'a>>,
    pub reference_initializers: Vec<ReferenceInitializer<'a>>,
    pub direct_origins: Vec<ModuleOrigin>,
}

/// Mutable lexical-scope state used only during AST recovery.
pub struct ScopeState {
    pub scope_id: String,
    pub parent_scope_id: Option<String>,
    /// Index of the parent scope (resolved at creation; parents always exist first).
    pub parent: Option<ScopeIx>,
    /// `program`, `function`, `block`, `static-block`, `class`, `catch`.
    pub kind: &'static str,
    pub location: SourceRange,
    pub bindings_complete: bool,
    pub bindings: HashMap<String, BindingIx>,
}

/// Memoized evaluations (`primitiveBindingValuesByState` and friends in the TS module).
#[derive(Default)]
pub struct EvaluationCaches {
    /// Ordinary primitive binding values (`primitiveBindingValuesFor`).
    pub primitive_bindings: HashMap<BindingIx, SemanticValue>,
    /// Point-local values keyed by the capture point node.
    pub captured_bindings: HashMap<NodeId, HashMap<BindingIx, SemanticValue>>,
    /// Literal-field primitives captured at construction.
    pub primitive_expressions: HashMap<NodeId, SemanticValue>,
}

/// Shared state for semantic collection and evaluation (`JavaScriptSemanticAnalysisState`).
pub struct SemanticAnalysisState<'a> {
    pub ast: &'a Ast,
    pub scopes: Vec<ScopeState>,
    pub scopes_by_id: HashMap<String, ScopeIx>,
    /// Scope boundaries and descendant scopes resolved on demand (`u32::MAX` = none).
    pub(crate) scope_by_node: RefCell<Vec<u32>>,
    pub bindings: Vec<BindingState<'a>>,
    pub bindings_by_id: HashMap<String, BindingIx>,
    pub callables: Vec<SemanticCallable>,
    pub callable_nodes_by_id: HashMap<String, N<'a>>,
    pub module_links: Vec<SemanticModuleLink>,
    /// `moduleLinkBindings`: link index -> binding.
    pub module_link_bindings: HashMap<usize, BindingIx>,
    pub conditional_initializers: HashSet<NodeId>,
    pub(crate) caches: RefCell<EvaluationCaches>,
}

const NO_SCOPE: u32 = u32::MAX;

impl<'a> SemanticAnalysisState<'a> {
    /// `createState(program)`.
    pub fn new(ast: &'a Ast) -> Self {
        let program = ast.root();
        let root = ScopeState {
            scope_id: semantic_scope_id("program", program),
            parent_scope_id: None,
            parent: None,
            kind: "program",
            location: program.loc(),
            bindings_complete: true,
            bindings: HashMap::new(),
        };
        let mut scopes_by_id = HashMap::new();
        scopes_by_id.insert(root.scope_id.clone(), 0);
        let mut scope_by_node = vec![NO_SCOPE; ast.len()];
        scope_by_node[program.id as usize] = 0;
        SemanticAnalysisState {
            ast,
            scopes: vec![root],
            scopes_by_id,
            scope_by_node: RefCell::new(scope_by_node),
            bindings: Vec::new(),
            bindings_by_id: HashMap::new(),
            callables: Vec::new(),
            callable_nodes_by_id: HashMap::new(),
            module_links: Vec::new(),
            module_link_bindings: HashMap::new(),
            conditional_initializers: HashSet::new(),
            caches: RefCell::new(EvaluationCaches::default()),
        }
    }

    /// `state.scopeByNode.set(node, scope)`.
    pub(crate) fn set_scope_for_node(&self, node: N<'_>, scope: ScopeIx) {
        self.scope_by_node.borrow_mut()[node.id as usize] = scope as u32;
    }

    /// Register a scope (`state.scopes.push` + `state.scopesById.set`).
    pub fn push_scope(&mut self, scope: ScopeState) -> ScopeIx {
        let ix = self.scopes.len();
        self.scopes_by_id.insert(scope.scope_id.clone(), ix);
        self.scopes.push(scope);
        ix
    }

    /// `state.scopesById.get(id)`.
    pub fn scope_by_id(&self, scope_id: &str) -> Option<ScopeIx> {
        self.scopes_by_id.get(scope_id).copied()
    }

    /// The binding with a stable id.
    pub fn binding_by_id(&self, binding_id: &str) -> Option<BindingIx> {
        self.bindings_by_id.get(binding_id).copied()
    }
}

/// Return the active scope from a non-empty construction stack (`currentSemanticScope`).
pub fn current_semantic_scope(stack: &[ScopeIx]) -> ScopeIx {
    *stack.last().expect("Missing semantic scope")
}

/// Create a stable source-position identity for one lexical scope.
pub fn semantic_scope_id(kind: &str, node: N<'_>) -> String {
    format!("scope:{kind}:{}:{}", node.start(), node.end())
}

/// Resolve one lexical name from the scope containing a node.
pub fn resolve_semantic_binding_state(
    state: &SemanticAnalysisState<'_>,
    node: N<'_>,
    name: &str,
) -> Option<BindingIx> {
    let mut scope = semantic_scope_for_node(state, node);
    while let Some(ix) = scope {
        let current = &state.scopes[ix];
        if let Some(binding) = current.bindings.get(name) {
            return Some(*binding);
        }
        if !current.bindings_complete {
            return None;
        }
        scope = current.parent;
    }
    None
}

/// Report whether an omitted binding scope blocks a trustworthy miss.
pub fn semantic_resolution_blocked(state: &SemanticAnalysisState<'_>, node: N<'_>, name: &str) -> bool {
    let mut scope = semantic_scope_for_node(state, node);
    while let Some(ix) = scope {
        let current = &state.scopes[ix];
        if current.bindings.contains_key(name) {
            return false;
        }
        if !current.bindings_complete {
            return true;
        }
        scope = current.parent;
    }
    false
}

fn semantic_scope_for_node(state: &SemanticAnalysisState<'_>, node: N<'_>) -> Option<ScopeIx> {
    let mut candidate = Some(node);
    while let Some(current) = candidate {
        let found = state.scope_by_node.borrow()[current.id as usize];
        if found != NO_SCOPE {
            // Repeated references in a deep expression share this ancestry. Cache the
            // traversed path without eagerly indexing nodes never resolved.
            let mut cache = state.scope_by_node.borrow_mut();
            let mut descendant = Some(node);
            while let Some(walker) = descendant {
                if walker.id == current.id {
                    break;
                }
                cache[walker.id as usize] = found;
                descendant = walker.parent();
            }
            return Some(found as usize);
        }
        candidate = current.parent();
    }
    None
}

/// Resolve one name starting from an explicitly selected lexical scope.
pub fn resolve_semantic_binding_from_scope(
    state: &SemanticAnalysisState<'_>,
    scope: ScopeIx,
    name: &str,
) -> Option<BindingIx> {
    let mut candidate = Some(scope);
    while let Some(ix) = candidate {
        let current = &state.scopes[ix];
        if let Some(binding) = current.bindings.get(name) {
            return Some(*binding);
        }
        if !current.bindings_complete {
            return None;
        }
        candidate = current.parent;
    }
    None
}

/// Select the function/program owner for a var declaration.
pub fn semantic_variable_scope(
    state: &SemanticAnalysisState<'_>,
    scope: ScopeIx,
    parent: Option<N<'_>>,
) -> ScopeIx {
    let is_var = parent
        .is_some_and(|p| p.is(Kind::VariableDeclaration) && p.str("kind") == Some("var"));
    if !is_var {
        return scope;
    }
    let mut candidate = scope;
    while state.scopes[candidate].kind == "block" || state.scopes[candidate].kind == "catch" {
        match state.scopes[candidate].parent {
            Some(outer) => candidate = outer,
            None => break,
        }
    }
    candidate
}

/// Identify a global name only when no lexical or dynamic environment shadows it.
pub fn is_unshadowed_global(node: N<'_>, state: &SemanticAnalysisState<'_>, name: &str) -> bool {
    node.is_identifier()
        && node.name() == Some(name)
        && resolve_semantic_binding_state(state, node, name).is_none()
        && !semantic_resolution_blocked(state, node, name)
}
