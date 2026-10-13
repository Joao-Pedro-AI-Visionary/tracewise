//! Ports of `javascriptStaticAnalysisState.ts` and `javascriptStaticAnalysisFindings.ts`:
//! the mutable accumulator of one traversal, the module range index and located findings.

use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};

use super::super::ast::{Ast, NodeId, N};
use super::super::static_types::{
    BundlerRegistration, ElectronBrowserWindowFinding, ElectronContextBridgeFinding,
    ElectronIpcFinding, ElectronNativeAddonBindingFinding, ElectronSenderValidationFinding,
    ElectronUtilityProcessFinding, OpenReceiverFact, RolePath, SourceMapUrl, StaticEndpoint,
    StaticReference, StaticStorage,
};

/// Source offsets for one recovered bundle module factory.
#[derive(Clone, Debug)]
pub struct ModuleRange {
    pub start: i64,
    pub end: i64,
    pub key: String,
    pub runtime: String,
    pub require_name: Option<String>,
}

#[derive(Default)]
struct TreeNode {
    /// Child slots in [`ModuleRangeIndex::nodes`]; `0` means absent (slot 0 is the root).
    left: usize,
    right: usize,
    /// Insertion order of the best (earliest discovered) range covering this node's span.
    best: Option<usize>,
}

/// Incremental point lookup preserving insertion-order precedence for overlaps.
pub struct ModuleRangeIndex {
    nodes: Vec<TreeNode>,
    ranges: Vec<ModuleRange>,
    end: i64,
}

impl ModuleRangeIndex {
    /// Create an empty offset index bounded by the analyzed source length (UTF-16 units).
    pub fn new(source_length: u32) -> Self {
        ModuleRangeIndex {
            nodes: vec![TreeNode::default()],
            ranges: Vec::new(),
            end: (i64::from(source_length) + 1).max(1),
        }
    }

    /// Add a module range in the same discovery order used by the analysis pass.
    pub fn add(&mut self, range: ModuleRange) {
        let order = self.ranges.len();
        let start = range.start.max(0);
        let end = self.end.min(range.end + 1);
        self.ranges.push(range);
        if start < end {
            self.insert(0, 0, self.end, start, end, order);
        }
    }

    /// The first discovered inclusive range containing an offset.
    pub fn find(&self, offset: i64) -> Option<&ModuleRange> {
        if offset < 0 || offset >= self.end {
            return None;
        }
        let mut node = Some(0usize);
        let mut low = 0i64;
        let mut high = self.end;
        let mut best: Option<usize> = None;
        while let Some(index) = node {
            let current = &self.nodes[index];
            if let Some(candidate) = current.best {
                if best.is_none_or(|existing| candidate < existing) {
                    best = Some(candidate);
                }
            }
            if high - low <= 1 {
                break;
            }
            let middle = low + (high - low) / 2;
            if offset < middle {
                node = (current.left != 0).then_some(current.left);
                high = middle;
            } else {
                node = (current.right != 0).then_some(current.right);
                low = middle;
            }
        }
        best.map(|order| &self.ranges[order])
    }

    fn insert(&mut self, node: usize, low: i64, high: i64, query_low: i64, query_high: i64, order: usize) {
        if query_low <= low && high <= query_high {
            let slot = &mut self.nodes[node].best;
            if slot.is_none_or(|existing| order < existing) {
                *slot = Some(order);
            }
            return;
        }
        let middle = low + (high - low) / 2;
        if query_low < middle {
            if self.nodes[node].left == 0 {
                self.nodes.push(TreeNode::default());
                let created = self.nodes.len() - 1;
                self.nodes[node].left = created;
            }
            let child = self.nodes[node].left;
            self.insert(child, low, middle, query_low, query_high, order);
        }
        if query_high > middle {
            if self.nodes[node].right == 0 {
                self.nodes.push(TreeNode::default());
                let created = self.nodes.len() - 1;
                self.nodes[node].right = created;
            }
            let child = self.nodes[node].right;
            self.insert(child, middle, high, query_low, query_high, order);
        }
    }
}

/// Static finding retained with its source offset until module attribution.
pub struct Located<Value> {
    pub offset: i64,
    pub value: Value,
}

/// Findings that carry `module_key` / `module_runtime` attribution.
pub trait ModuleAttributed {
    fn set_module(&mut self, key: Option<&str>, runtime: Option<&str>);
}

macro_rules! module_attributed {
    ($($type:ty),* $(,)?) => {$(
        impl ModuleAttributed for $type {
            fn set_module(&mut self, key: Option<&str>, runtime: Option<&str>) {
                self.module_key = key.map(str::to_string);
                if let Some(runtime) = runtime {
                    self.module_runtime = Some(runtime.to_string());
                }
            }
        }
    )*};
}

module_attributed!(
    StaticReference,
    StaticEndpoint,
    StaticStorage,
    RolePath,
    ElectronBrowserWindowFinding,
    ElectronContextBridgeFinding,
    ElectronIpcFinding,
    ElectronSenderValidationFinding,
    ElectronUtilityProcessFinding,
    ElectronNativeAddonBindingFinding,
);

/// Mutable collections used during one inert AST traversal.
pub struct Accumulator {
    pub references: Vec<Located<StaticReference>>,
    pub endpoints: Vec<Located<StaticEndpoint>>,
    pub storage: Vec<Located<StaticStorage>>,
    pub roles: Vec<Located<RolePath>>,
    pub source_maps: Vec<SourceMapUrl>,
    pub registrations: Vec<BundlerRegistration>,
    pub browser_windows: Vec<Located<ElectronBrowserWindowFinding>>,
    pub context_bridge_apis: Vec<Located<ElectronContextBridgeFinding>>,
    pub ipc: Vec<Located<ElectronIpcFinding>>,
    pub sender_validations: Vec<Located<ElectronSenderValidationFinding>>,
    pub utility_processes: Vec<Located<ElectronUtilityProcessFinding>>,
    pub native_addon_bindings: Vec<Located<ElectronNativeAddonBindingFinding>>,
    pub module_range_index: ModuleRangeIndex,
    /// `preload` properties of audio and video elements, which are not scripts.
    pub media_element_preloads: HashSet<NodeId>,
    pub seen: HashSet<String>,
    pub visited_nodes: u64,
    pub unknown_findings: u64,
    /// Lazily parsed Vite preload dependency table (a pure function of the source).
    pub vite_table: OnceCell<Vec<String>>,
    /// Whether a module-cache marker occurs in the source (also a pure function of it).
    pub module_cache_observed: OnceCell<bool>,
}

impl Accumulator {
    pub fn new(source_length: u32) -> Self {
        Accumulator {
            references: Vec::new(),
            endpoints: Vec::new(),
            storage: Vec::new(),
            roles: Vec::new(),
            source_maps: Vec::new(),
            registrations: Vec::new(),
            browser_windows: Vec::new(),
            context_bridge_apis: Vec::new(),
            ipc: Vec::new(),
            sender_validations: Vec::new(),
            utility_processes: Vec::new(),
            native_addon_bindings: Vec::new(),
            module_range_index: ModuleRangeIndex::new(source_length),
            media_element_preloads: HashSet::new(),
            seen: HashSet::new(),
            visited_nodes: 0,
            unknown_findings: 0,
            vite_table: OnceCell::new(),
            module_cache_observed: OnceCell::new(),
        }
    }

    /// `addFindingOnce`: reserve one deterministic finding key; `true` when it is new.
    pub fn reserve(&mut self, key: String) -> bool {
        self.seen.insert(key)
    }
}

/// Shared source and accumulator for helper inspections.
pub struct Ctx<'a> {
    pub ast: &'a Ast,
    pub acc: Accumulator,
    pub open_receivers: &'a HashMap<u32, OpenReceiverFact>,
    /// Electron export paths for renamed call roots, by identifier offset.
    pub electron_bindings: &'a HashMap<u32, String>,
}

impl Ctx<'_> {
    pub fn source(&self) -> &str {
        self.ast.source.text()
    }
}

/// `addLocatedFinding`: add one module-attributable finding once per source location.
pub fn add_located<Value>(
    seen: &mut HashSet<String>,
    collection: &mut Vec<Located<Value>>,
    key: &str,
    node: N<'_>,
    value: Value,
) {
    let full = format!("{key}\0{}", node.start());
    if !seen.insert(full) {
        return;
    }
    collection.push(Located { offset: i64::from(node.start()), value });
}

/// `finalizeLocatedFindings`: attach recovered bundle-module ownership after traversal.
pub fn finalize_located<Value: ModuleAttributed>(
    values: Vec<Located<Value>>,
    modules: &ModuleRangeIndex,
) -> Vec<Value> {
    values
        .into_iter()
        .map(|Located { offset, mut value }| {
            match modules.find(offset) {
                Some(module) => value.set_module(Some(&module.key), Some(&module.runtime)),
                None => value.set_module(None, None),
            }
            value
        })
        .collect()
}
