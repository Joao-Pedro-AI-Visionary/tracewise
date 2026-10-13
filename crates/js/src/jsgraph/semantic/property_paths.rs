//! Port of `javascriptSemanticPropertyPaths.ts`: mutation path keys and the exact-prefix
//! coverage index.

use std::collections::HashMap;

/// Slots retained by a shallow copy after exclusions or an array prefix
/// (`JavaScriptSemanticPropertySelection`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Selection {
    pub excluded_keys: Vec<String>,
    pub start_index: Option<u64>,
}

/// One element of a mutation path or binding projection: `string | number | null | Selection`.
///
/// `Name` and `Index` stay distinct (JS `"1"` vs `1`) because REA's identity strings are built
/// with `JSON.stringify`, which keeps the difference.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathKey {
    Null,
    Name(String),
    Index(u64),
    Select(Selection),
}

/// `JavaScriptSemanticPropertyPath`.
pub type PropertyPath = Vec<PathKey>;

impl PathKey {
    pub fn name(value: impl Into<String>) -> PathKey {
        PathKey::Name(value.into())
    }

    /// `typeof key === "object"` (a selection; `null` is handled separately).
    pub fn is_selection(&self) -> bool {
        matches!(self, PathKey::Select(_))
    }

    /// `key === null || typeof key === "object"`.
    pub fn is_null_or_selection(&self) -> bool {
        matches!(self, PathKey::Null | PathKey::Select(_))
    }

    /// JS `String(key)` for a string or number key (`None` for `null` and selections).
    pub fn as_plain_string(&self) -> Option<String> {
        match self {
            PathKey::Name(name) => Some(name.clone()),
            PathKey::Index(index) => Some(index.to_string()),
            PathKey::Null | PathKey::Select(_) => None,
        }
    }

    /// `String(key)` including the `null` / object spellings.
    pub fn js_string(&self) -> String {
        match self {
            PathKey::Name(name) => name.clone(),
            PathKey::Index(index) => index.to_string(),
            PathKey::Null => "null".into(),
            PathKey::Select(_) => "[object Object]".into(),
        }
    }
}

/// Parse a canonical JavaScript array index from text (`String(Number(text)) === text`).
fn canonical_index(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 10 {
        return None;
    }
    if bytes[0] == b'0' {
        return if bytes.len() == 1 { Some(0) } else { None };
    }
    if !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let value: u64 = text.parse().ok()?;
    (value < 4_294_967_295).then_some(value)
}

/// `semanticArrayIndex` for a string key.
pub fn semantic_array_index_str(key: &str) -> Option<u64> {
    canonical_index(key)
}

/// `semanticArrayIndex` for a string or number key (`None` for `null` and selections, which the
/// callers never pass).
pub fn semantic_array_index(key: &PathKey) -> Option<u64> {
    match key {
        PathKey::Index(index) => (*index < 4_294_967_295).then_some(*index),
        PathKey::Name(name) => canonical_index(name),
        PathKey::Null | PathKey::Select(_) => None,
    }
}

/// Test an exact key, wildcard, or copied-slot selection against an own key.
pub fn semantic_property_path_key_matches(key: &PathKey, name: &str) -> bool {
    match key {
        PathKey::Null => true,
        PathKey::Name(text) => text == name,
        PathKey::Index(index) => index.to_string() == name,
        PathKey::Select(selection) => {
            if selection.excluded_keys.iter().any(|excluded| excluded == name) {
                return false;
            }
            match selection.start_index {
                None => true,
                Some(start) => semantic_array_index_str(name).is_some_and(|index| index >= start),
            }
        }
    }
}

#[derive(Default)]
struct CoverageNode {
    terminal: bool,
    exact: HashMap<String, usize>,
    /// Insertion-ordered selector children (`null` or a selection).
    selectors: Vec<(PathKey, usize)>,
}

/// Index exact effect prefixes without widening distinct member paths.
pub struct SemanticPropertyPathCoverage {
    nodes: Vec<CoverageNode>,
}

impl Default for SemanticPropertyPathCoverage {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticPropertyPathCoverage {
    pub fn new() -> Self {
        SemanticPropertyPathCoverage { nodes: vec![CoverageNode::default()] }
    }

    /// Retain a path only when no previously retained prefix covers it.
    pub fn retain(&mut self, path: &[PathKey]) -> bool {
        let mut pending = vec![(0usize, 0usize)];
        while let Some((node, offset)) = pending.pop() {
            if self.nodes[node].terminal {
                return false;
            }
            let Some(key) = path.get(offset) else { continue };
            if !key.is_null_or_selection() {
                if let Some(&exact) = key.as_plain_string().and_then(|name| self.nodes[node].exact.get(&name)) {
                    pending.push((exact, offset + 1));
                }
            }
            for (selected_key, child) in &self.nodes[node].selectors {
                if key_covers(selected_key, key) {
                    pending.push((*child, offset + 1));
                }
            }
        }
        let mut node = 0usize;
        for key in path {
            if !key.is_null_or_selection() {
                let name = key.as_plain_string().unwrap_or_default();
                let existing = self.nodes[node].exact.get(&name).copied();
                node = match existing {
                    Some(child) => child,
                    None => {
                        self.nodes.push(CoverageNode::default());
                        let child = self.nodes.len() - 1;
                        self.nodes[node].exact.insert(name, child);
                        child
                    }
                };
            } else {
                let existing = self.nodes[node]
                    .selectors
                    .iter()
                    .find(|(selected_key, _)| selected_key == key)
                    .map(|(_, child)| *child);
                node = match existing {
                    Some(child) => child,
                    None => {
                        self.nodes.push(CoverageNode::default());
                        let child = self.nodes.len() - 1;
                        self.nodes[node].selectors.push((key.clone(), child));
                        child
                    }
                };
            }
        }
        let terminal = &mut self.nodes[node];
        terminal.terminal = true;
        terminal.exact.clear();
        terminal.selectors.clear();
        true
    }
}

fn key_covers(covering: &PathKey, key: &PathKey) -> bool {
    if matches!(covering, PathKey::Null) {
        return true;
    }
    if matches!(key, PathKey::Null) {
        return false;
    }
    match key {
        PathKey::Select(key_selection) => match covering {
            PathKey::Select(covering_selection) => {
                covering_selection
                    .excluded_keys
                    .iter()
                    .all(|name| key_selection.excluded_keys.contains(name))
                    && (covering_selection.start_index.is_none()
                        || key_selection
                            .start_index
                            .is_some_and(|start| covering_selection.start_index.is_some_and(|c| c <= start)))
            }
            _ => false,
        },
        _ => {
            let name = key.js_string();
            match covering {
                PathKey::Select(_) => semantic_property_path_key_matches(covering, &name),
                other => other.js_string() == name,
            }
        }
    }
}
