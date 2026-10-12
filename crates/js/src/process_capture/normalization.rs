//! Port of REA `process/capture/ProcessNormalization.ts`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use fancy_regex::{Captures, Regex};

use super::scenario::ProcessScenario;

/// One raw process-tree sample before normalization.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessSample {
    pub at_ms: u64,
    pub pid: u64,
    pub parent_pid: u64,
    pub command: String,
    pub process_group_id: Option<u64>,
    pub session_id: Option<u64>,
}

/// Bucket one elapsed process-capture timestamp under scenario normalization.
pub fn bucket(elapsed_ms: u64, time_bucket_ms: u64) -> u64 {
    (elapsed_ms / time_bucket_ms.max(1)) * time_bucket_ms.max(1)
}

/// Normalize one terminal/protocol payload under explicitly selected scenario rules.
pub fn normalize_text(value: &str, scenario: &ProcessScenario, temporary_root: &str, pid: i64) -> String {
    let mut normalized = value.to_string();
    if scenario.normalization.paths {
        normalized = replace_all_literal(&normalized, temporary_root, "<temporary-root>");
        normalized = replace_all_literal(&normalized, &scenario.working_directory, "<working-directory>");
        normalized = replace_all_literal(&normalized, &scenario.executable, "<executable>");
        for (index, root) in scenario.filesystem_observation_paths.iter().enumerate() {
            normalized = replace_all_literal(&normalized, root, &format!("<filesystem-root-{index}>"));
        }
    }
    if scenario.normalization.ports {
        normalized = normalize_port_tokens(&normalized);
    }
    if scenario.normalization.pids {
        normalized = normalize_pid_tokens(&normalized, &[pid]);
    }
    for pattern in &scenario.normalization.patterns {
        normalized = replace_all_literal(&normalized, &pattern.pattern, &pattern.replacement);
    }
    normalized
}

/// JavaScript `String.prototype.replaceAll` with a literal pattern (an empty
/// pattern inserts the replacement at every boundary).
fn replace_all_literal(value: &str, pattern: &str, replacement: &str) -> String {
    value.replace(pattern, replacement)
}

fn endpoint_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // JavaScript `\b` (ASCII word boundary) is spelled as lookaround because
        // fancy-regex rejects `(?-u:\b)`.
        Regex::new(
            r#"(?i)((?<![A-Za-z0-9_])[a-z][a-z0-9+.\-]*://[^\s/?#"'<>]+|(?<![A-Za-z0-9_])localhost|(?<![A-Za-z0-9_])(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\[[0-9a-f:.%]+\]):([0-9]{1,5})(?![\p{L}\p{N}_@:]|\.(?:[\p{L}\p{N}_]|$))"#,
        )
        .expect("endpoint regex")
    })
}

fn keyword_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // JavaScript `\b` (ASCII word boundary) is spelled as lookaround because
        // fancy-regex rejects `(?-u:\b)`.
        Regex::new(
            r#"(?i)((?<![A-Za-z0-9_])(?:port|tcp_port|udp_port|listen)(?![A-Za-z0-9_])["']?\s*[:=]\s*)([0-9]{1,5})(?![\p{L}\p{N}_]|\.(?:[\p{L}\p{N}_]|$))"#,
        )
        .expect("keyword regex")
    })
}

/// Node `net.isIPv4` (no leading zeros).
fn is_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) && (p.len() == 1 || !p.starts_with('0'))
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
        && value.parse::<Ipv4Addr>().is_ok()
}

fn is_ip(value: &str) -> bool {
    if is_ipv4(value) {
        return true;
    }
    let address = value.split('%').next().unwrap_or(value);
    address.parse::<Ipv6Addr>().is_ok()
}

fn replace_with<F>(regex: &Regex, value: &str, mut f: F) -> String
where
    F: FnMut(&Captures) -> String,
{
    let mut out = String::with_capacity(value.len());
    let mut last = 0;
    for caps in regex.captures_iter(value) {
        let Ok(caps) = caps else { return value.to_string() };
        let whole = caps.get(0).expect("match");
        out.push_str(&value[last..whole.start()]);
        out.push_str(&f(&caps));
        last = whole.end();
    }
    out.push_str(&value[last..]);
    out
}

fn normalize_port_tokens(value: &str) -> String {
    // Both patterns need a ':' or '=' before the port; skip the regex engine otherwise.
    if !value.contains(':') && !value.contains('=') {
        return value.to_string();
    }
    let endpoint_normalized = replace_with(endpoint_regex(), value, |caps| {
        let matched = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
        let endpoint = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let port = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if port.parse::<u32>().unwrap_or(u32::MAX) > 65_535 {
            return matched.to_string();
        }
        let is_endpoint = if endpoint.contains("://") {
            url::Url::parse(&format!("{endpoint}:{port}")).is_ok()
        } else {
            endpoint.eq_ignore_ascii_case("localhost") || is_ip(endpoint.trim_start_matches('[').trim_end_matches(']'))
        };
        if is_endpoint {
            format!("{endpoint}:<port>")
        } else {
            matched.to_string()
        }
    });
    replace_with(keyword_regex(), &endpoint_normalized, |caps| {
        let matched = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
        let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let port = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if port.parse::<u32>().unwrap_or(u32::MAX) <= 65_535 {
            format!("{prefix}<port>")
        } else {
            matched.to_string()
        }
    })
}

/// `value.replace(/(?<!\d)(?:tokens)(?!\d)/gu, "<pid>")`: a match can neither
/// start after nor end before an ASCII digit, so it is exactly a maximal digit
/// run equal to one token.
fn normalize_pid_tokens(value: &str, identifiers: &[i64]) -> String {
    let tokens: std::collections::HashSet<String> =
        identifiers.iter().filter(|id| **id > 0).map(|id| id.to_string()).collect();
    if tokens.is_empty() {
        return value.to_string();
    }
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            let run = &value[start..index];
            out.push_str(if tokens.contains(run) { "<pid>" } else { run });
        } else {
            let start = index;
            while index < bytes.len() && !bytes[index].is_ascii_digit() {
                index += 1;
            }
            out.push_str(&value[start..index]);
        }
    }
    out
}

/// Project sampled observations under the caller-selected normalization rules.
pub fn normalize_samples(samples: &[ProcessSample], scenario: &ProcessScenario, root_pid: u64) -> Vec<ProcessSample> {
    let mut identifiers: Vec<u64> = vec![root_pid];
    for s in samples {
        identifiers.extend([s.pid, s.parent_pid, s.process_group_id.unwrap_or(0), s.session_id.unwrap_or(0)]);
    }
    let mut mapping: HashMap<u64, u64> = HashMap::new();
    for id in &identifiers {
        if *id > 0 && !mapping.contains_key(id) {
            let next = mapping.len() as u64 + 1;
            mapping.insert(*id, next);
        }
    }
    let signed: Vec<i64> = identifiers.iter().map(|i| *i as i64).collect();
    let pids = scenario.normalization.pids;
    samples
        .iter()
        .map(|s| {
            let normalized = normalize_text(&s.command, scenario, "<no-temporary-root>", root_pid as i64);
            let normalized = if pids { normalize_pid_tokens(&normalized, &signed) } else { normalized };
            ProcessSample {
                at_ms: bucket(s.at_ms, scenario.normalization.time_bucket_ms),
                pid: if pids { mapping.get(&s.pid).copied().unwrap_or(1) } else { s.pid },
                parent_pid: if pids { mapping.get(&s.parent_pid).copied().unwrap_or(0) } else { s.parent_pid },
                process_group_id: match s.process_group_id {
                    Some(g) if pids => Some(mapping.get(&g).copied().unwrap_or(0)),
                    other => other,
                },
                session_id: match s.session_id {
                    Some(g) if pids => Some(mapping.get(&g).copied().unwrap_or(0)),
                    other => other,
                },
                command: normalized.trim().to_string(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_follow_rea_boundaries() {
        // Ground truth from REA `normalizeProcessText` (ports only).
        for (input, expected) in [
            ("listening on http://localhost:8080/x", "listening on http://localhost:<port>/x"),
            ("at 127.0.0.1:3000.", "at 127.0.0.1:3000."),
            ("at 127.0.0.1:3000. ok", "at 127.0.0.1:<port>. ok"),
            ("v1.2.3:45.6", "v1.2.3:45.6"),
            ("port=5432 ok", "port=<port> ok"),
            ("localhost:99999", "localhost:99999"),
            ("[::1]:22 up", "[::1]:<port> up"),
            ("http://a:1:2 x", "http://a:1:2 x"),
            ("LISTEN: 80, Port 443", "LISTEN: <port>, Port 443"),
        ] {
            assert_eq!(normalize_port_tokens(input), expected, "{input}");
        }
    }

    #[test]
    fn pids_are_whole_numbers() {
        assert_eq!(normalize_pid_tokens("pid 123 1234 123", &[123]), "pid <pid> 1234 <pid>");
    }
}
