//! Mutable completeness ledger projected to the canonical browser completeness object
//! (port of REA browser/CdpCaptureCompleteness.ts and domain/browserCompleteness.ts).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

const POLICY_REASONS: &[&str] = &[
    "disallowed_origin",
    "unsupported_url",
    "unattributed_origin",
    "not_approved",
    "out_of_target_scope",
];

const EVENT_SECTIONS: &[(&str, &str)] = &[
    ("scripts", "scripts"),
    ("network_requests", "network_requests"),
    ("console_events", "console_events"),
    ("websocket_connections", "websocket_connections"),
    ("websocket_frames", "websocket_frames"),
    ("webmcp_tools", "webmcp_tools"),
    ("timeline_events", "timeline"),
];

#[derive(Debug, Clone)]
pub struct CdpCaptureCompleteness {
    initial_attach_limited: Vec<&'static str>,
    policy_filtered: BTreeSet<&'static str>,
    attach_limited: BTreeSet<&'static str>,
    truncated: BTreeSet<&'static str>,
    unavailable: BTreeSet<&'static str>,
    /// Keyed by section then reason. `None` count means an unknown omission size.
    excluded: BTreeMap<(&'static str, &'static str), Option<i64>>,
    dropped: BTreeMap<&'static str, i64>,
}

impl CdpCaptureCompleteness {
    pub fn new(initial_attach_limited: &[&'static str]) -> Self {
        let mut ledger = Self {
            initial_attach_limited: initial_attach_limited.to_vec(),
            policy_filtered: BTreeSet::new(),
            attach_limited: BTreeSet::new(),
            truncated: BTreeSet::new(),
            unavailable: BTreeSet::new(),
            excluded: BTreeMap::new(),
            dropped: BTreeMap::new(),
        };
        ledger.reset();
        ledger
    }

    pub fn reset(&mut self) {
        self.policy_filtered.clear();
        self.attach_limited.clear();
        self.truncated.clear();
        self.unavailable.clear();
        self.excluded.clear();
        self.dropped = empty_dropped();
        for section in &self.initial_attach_limited {
            self.attach_limited.insert(*section);
        }
    }

    pub fn exclude(&mut self, section: &'static str, reason: &'static str, count: Option<i64>) {
        if POLICY_REASONS.contains(&reason) {
            self.policy_filtered.insert(section);
        }
        if reason == "provider_unavailable" || reason == "invalid_protocol_value" {
            self.unavailable.insert(section);
        }
        if reason == "resource_budget_exhausted" {
            self.truncated.insert(section);
        }
        let existing = self.excluded.get(&(section, reason)).copied();
        let combined = match (count, existing) {
            (None, _) | (_, Some(None)) => None,
            (Some(count), None) => Some(count),
            (Some(count), Some(Some(previous))) => Some(previous.saturating_add(count)),
        };
        self.excluded.insert((section, reason), combined);
    }

    pub fn attach_limited(&mut self, section: &'static str) {
        self.attach_limited.insert(section);
    }

    pub fn unavailable(&mut self, section: &'static str) {
        self.unavailable.insert(section);
        self.exclude(section, "provider_unavailable", None);
    }

    pub fn truncate(&mut self, section: &'static str) {
        self.truncated.insert(section);
    }

    pub fn dropped_total(&self) -> i64 {
        self.dropped.values().copied().sum()
    }

    pub fn drop_events(&mut self, kind: &'static str, count: i64) {
        if let Some(slot) = self.dropped.get_mut(kind) {
            *slot = slot.saturating_add(count);
        }
        if let Some((_, section)) = EVENT_SECTIONS.iter().find(|(name, _)| *name == kind) {
            self.truncated.insert(*section);
        }
    }

    pub fn snapshot(&self) -> Value {
        let policy = !self.policy_filtered.is_empty();
        let truncated = !self.truncated.is_empty() || self.dropped.values().any(|count| *count > 0);
        let attach = !self.attach_limited.is_empty() || !self.unavailable.is_empty();
        let status = if truncated {
            "truncated"
        } else if policy {
            "policy_filtered"
        } else if attach {
            "attach_limited"
        } else {
            "complete_within_window"
        };
        let mut conditions = Vec::new();
        if attach {
            conditions.push("attach_limited");
        }
        if policy {
            conditions.push("policy_filtered");
        }
        if truncated {
            conditions.push("truncated");
        }
        if conditions.is_empty() {
            conditions.push("complete_within_window");
        }
        let dropped_total: i64 = self.dropped.values().sum();
        let mut dropped = serde_json::Map::new();
        for (key, value) in &self.dropped {
            dropped.insert((*key).to_string(), json!(value));
        }
        dropped.insert("total".to_string(), json!(dropped_total));
        let excluded: Vec<Value> = self
            .excluded
            .iter()
            .map(|((section, reason), count)| {
                json!({
                    "section": section,
                    "reason": reason,
                    "count": count.map(|n| json!(n)).unwrap_or(Value::Null),
                })
            })
            .collect();
        json!({
            "status": status,
            "conditions": conditions,
            "policy_filtered_sections": self.policy_filtered.iter().copied().collect::<Vec<_>>(),
            "attach_limited_sections": self.attach_limited.iter().copied().collect::<Vec<_>>(),
            "truncated_sections": self.truncated.iter().copied().collect::<Vec<_>>(),
            "unavailable_sections": self.unavailable.iter().copied().collect::<Vec<_>>(),
            "excluded": excluded,
            "dropped_events": dropped,
        })
    }
}

fn empty_dropped() -> BTreeMap<&'static str, i64> {
    BTreeMap::from([
        ("scripts", 0),
        ("network_requests", 0),
        ("console_events", 0),
        ("websocket_connections", 0),
        ("websocket_frames", 0),
        ("webmcp_tools", 0),
        ("timeline_events", 0),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_and_attach_compose_without_claiming_completeness() {
        let mut ledger = CdpCaptureCompleteness::new(&["network_requests", "metadata"]);
        ledger.exclude("console_text", "not_approved", None);
        let snapshot = ledger.snapshot();
        assert_eq!(snapshot["status"], "policy_filtered");
        assert_eq!(
            snapshot["conditions"],
            json!(["attach_limited", "policy_filtered"])
        );
        assert_eq!(snapshot["excluded"][0]["count"], Value::Null);
        assert_eq!(snapshot["dropped_events"]["total"], 0);
    }
}
