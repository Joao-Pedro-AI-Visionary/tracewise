//! Objective-C and Swift symbol analysis (port of `domain/symbolAnalysis.ts` and
//! `domain/swiftSymbolClassification.ts`).

use std::collections::{BTreeMap, HashSet};

use regex::Regex;
use serde_json::{json, Map, Value};

/// `{ address, name }` record of a procedure or symbol inventory.
#[derive(Debug, Clone)]
pub struct Addressed {
    pub address: String,
    pub name: String,
}

const OBJC_CLASS_MARKER: &str = "OBJC_CLASS_$_";
const LEGACY_OBJC_CLASS_PREFIX: &str = "l_OBJC_CLASS_";
const OBJC_PROTOCOL_MARKER: &str = "OBJC_PROTOCOL_$_";

const LEGACY_CATEGORIES: [(&str, &str); 5] = [
    ("_TtC", "classes"),
    ("_TtV", "structs"),
    ("_TtO", "enums"),
    ("_TtP", "protocols"),
    ("_TtE", "extensions"),
];

fn nominal_category(kind: char) -> Option<&'static str> {
    match kind {
        'C' => Some("classes"),
        'V' => Some("structs"),
        'O' => Some("enums"),
        'P' => Some("protocols"),
        _ => None,
    }
}

/// Category of a recognized Swift mangling: `None` = not Swift, `Some(None)` = unknown category.
pub fn classify_swift_symbol(name: &str) -> Option<Option<&'static str>> {
    static PREFIX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let prefix = PREFIX.get_or_init(|| Regex::new(r"^_?(?:\$[sS]|_T0)").unwrap());
    let Some(found) = prefix.find(name) else {
        if !name.contains("_Tt") {
            return None;
        }
        return Some(
            LEGACY_CATEGORIES
                .iter()
                .find(|(p, _)| name.starts_with(p))
                .map(|(_, c)| *c),
        );
    };
    let mangling = &name[found.end()..];
    let Some(mut offset) = identifier_end(mangling, 0) else {
        return Some(None);
    };
    let mut category: Option<&'static str> = None;
    while let Some(end) = identifier_end(mangling, offset) {
        let kind = mangling[end..].chars().next().unwrap_or('\0');
        match nominal_category(kind) {
            None => {
                if &mangling[end..] == "Mp" {
                    category = Some("protocols");
                } else if kind == 'E' && category.is_some() {
                    category = Some("extensions");
                }
                break;
            }
            Some(nominal) => {
                category = Some(nominal);
                offset = end + 1;
            }
        }
    }
    Some(category)
}

fn identifier_end(mangling: &str, offset: usize) -> Option<usize> {
    let rest = mangling.get(offset..)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() || digits.starts_with('0') {
        return None;
    }
    let length: usize = digits.parse().ok()?;
    let start = offset + digits.len();
    let end = start.checked_add(length)?;
    let identifier = mangling.get(start..end)?;
    let mut chars = identifier.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(end)
}

fn unique_by_name(entries: Vec<&Addressed>) -> Vec<&Addressed> {
    let mut seen = HashSet::new();
    entries.into_iter().filter(|e| seen.insert(e.name.clone())).collect()
}

fn entry_json(entry: &Addressed) -> Value {
    json!({ "address": entry.address, "name": entry.name })
}

/// Select and deduplicate Objective-C class labels.
pub fn discover_objc_classes(names: &[Addressed], pattern: &str) -> Value {
    let legacy_name = Regex::new(r"^l_OBJC_CLASS_NAME_(?:\.\d+)?$").unwrap();
    let selected: Vec<&Addressed> = names
        .iter()
        .filter(|e| {
            e.name.contains(OBJC_CLASS_MARKER)
                || (e.name.starts_with(LEGACY_OBJC_CLASS_PREFIX)
                    && e.name.len() > LEGACY_OBJC_CLASS_PREFIX.len()
                    && !legacy_name.is_match(&e.name))
        })
        .filter(|e| pattern.is_empty() || e.name.contains(pattern))
        .collect();
    let classes = unique_by_name(selected);
    json!({ "count": classes.len(), "classes": classes.iter().map(|e| entry_json(e)).collect::<Vec<_>>() })
}

/// Select and deduplicate Objective-C and Swift protocol labels.
pub fn discover_objc_protocols(names: &[Addressed]) -> Value {
    let selected: Vec<&Addressed> = names
        .iter()
        .filter(|e| {
            e.name.contains(OBJC_PROTOCOL_MARKER)
                || e.name.contains("_TtP")
                || (e.name.ends_with("Mp") && classify_swift_symbol(&e.name) == Some(Some("protocols")))
        })
        .collect();
    let protocols = unique_by_name(selected);
    json!({ "count": protocols.len(), "protocols": protocols.iter().map(|e| entry_json(e)).collect::<Vec<_>>() })
}

/// Categorize procedure names using Swift manglings at their exact addresses.
pub fn categorize_swift_types(
    procedures: &[Addressed],
    category_filter: Option<&str>,
    pattern: Option<&str>,
    symbols: &[Addressed],
) -> Value {
    let order = ["classes", "structs", "enums", "protocols", "extensions", "other"];
    let mut groups: BTreeMap<&str, Vec<Value>> = order.iter().map(|c| (*c, Vec::new())).collect();
    let mut aliases: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for symbol in symbols {
        if classify_swift_symbol(&symbol.name).is_some() {
            aliases.entry(symbol.address.clone()).or_default().push(symbol.name.clone());
        }
    }
    let mut seen: HashSet<String> = HashSet::new();
    let mut unclassified_names: HashSet<String> = HashSet::new();
    let mut unclassified: Vec<Value> = Vec::new();
    for entry in procedures {
        if seen.contains(&entry.name) {
            continue;
        }
        let mut mangled: Vec<String> = Vec::new();
        if classify_swift_symbol(&entry.name).is_some() {
            mangled.push(entry.name.clone());
        }
        for alias in aliases.get(&entry.address).cloned().unwrap_or_default() {
            if !mangled.contains(&alias) {
                mangled.push(alias);
            }
        }
        if mangled.is_empty() {
            continue;
        }
        if let Some(pattern) = pattern {
            let matches = std::iter::once(&entry.name)
                .chain(mangled.iter())
                .any(|n| n.contains(pattern));
            if !matches {
                continue;
            }
        }
        let mut kinds: Vec<Option<&'static str>> = Vec::new();
        for name in &mangled {
            let kind = classify_swift_symbol(name).flatten();
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        let category = if kinds.len() == 1 { kinds[0] } else { None };
        let item = json!({ "address": entry.address, "name": entry.name, "mangled_names": mangled });
        if category.is_none() && !unclassified_names.contains(&entry.name) {
            unclassified_names.insert(entry.name.clone());
            let reason = if kinds.len() > 1 && !kinds.contains(&None) {
                "conflicting_categories"
            } else {
                "category_not_decoded"
            };
            let mut record = item.as_object().cloned().unwrap_or_default();
            record.insert("reason".into(), json!(reason));
            unclassified.push(Value::Object(record));
        }
        let bucket = category.unwrap_or("other");
        if category_filter.is_none() || category_filter == Some(bucket) {
            seen.insert(entry.name.clone());
            groups.get_mut(bucket).unwrap().push(item);
        }
    }
    let total: usize = groups.values().map(Vec::len).sum();
    let mut categories = Map::new();
    for category in order {
        let items = groups.remove(category).unwrap_or_default();
        categories.insert(category.to_string(), json!({ "count": items.len(), "items": items }));
    }
    let mut limitations = vec![json!(
        "Identification uses Swift mangled procedure names or same-address symbol aliases. Demangled names without retained Swift manglings cannot be identified. Counts deduplicate procedure names, not source declarations."
    )];
    if !unclassified.is_empty() {
        limitations.push(json!(
            "Some Swift categories could not be established from the retained manglings. Unclassified observations remain inline regardless of the category filter."
        ));
    }
    json!({
        "total": total,
        "categories": Value::Object(categories),
        "unclassified": unclassified,
        "limitations": limitations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(address: &str, name: &str) -> Addressed {
        Addressed {
            address: address.to_string(),
            name: name.to_string(),
        }
    }

    #[test]
    fn classifies_swift_manglings_by_nominal_kind() {
        assert_eq!(classify_swift_symbol("$s4main3FooC"), Some(Some("classes")));
        assert_eq!(classify_swift_symbol("$s4main3BarV"), Some(Some("structs")));
        assert_eq!(classify_swift_symbol("$s4main3BazO"), Some(Some("enums")));
        assert_eq!(classify_swift_symbol("_$s4main7ScoringMp"), Some(Some("protocols")));
        assert_eq!(classify_swift_symbol("_TtC4main3Foo"), Some(Some("classes")));
        assert_eq!(classify_swift_symbol("plain_c_function"), None);
        // Substitutions and other encodings stay unclassified, never guessed.
        assert_eq!(classify_swift_symbol("$s4main3FooCACvg"), Some(Some("classes")));
        assert_eq!(classify_swift_symbol("$sSS"), Some(None));
    }

    #[test]
    fn objc_discovery_deduplicates_and_filters() {
        let names = vec![
            entry("0x1", "_OBJC_CLASS_$_NSObject"),
            entry("0x2", "_OBJC_CLASS_$_NSObject"),
            entry("0x3", "l_OBJC_CLASS_NAME_"),
            entry("0x4", "l_OBJC_CLASS_Legacy"),
            entry("0x5", "unrelated"),
        ];
        let all = discover_objc_classes(&names, "");
        assert_eq!(all["count"], 2);
        let filtered = discover_objc_classes(&names, "Legacy");
        assert_eq!(filtered["classes"][0]["name"], "l_OBJC_CLASS_Legacy");
        let protocols = discover_objc_protocols(&[entry("0x6", "_OBJC_PROTOCOL_$_NSCopying")]);
        assert_eq!(protocols["count"], 1);
    }
}
