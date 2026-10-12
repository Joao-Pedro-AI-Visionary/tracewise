//! Port of REA `domain/process/processCaptureValidation.ts` plus the structural
//! part of `processCaptureSchema` needed to trust a capture before comparison.

use serde_json::Value;

use super::scenario::digest_commitment;

const TOP_LEVEL: [&str; 18] = [
    "manifest", "normalization", "frames", "rendered_frames", "interaction_events", "exit", "settlement",
    "process_samples", "filesystem_checkpoints", "event_journal", "files_before", "files_after",
    "filesystem_effects", "truncated", "truncation_details", "limitations", "residual_unknowns", "cleanup",
];

fn arr(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

fn u(value: &Value) -> u64 {
    value.as_u64().unwrap_or(0)
}

fn structural_issues(capture: &Value) -> Vec<String> {
    let mut issues = Vec::new();
    let Some(object) = capture.as_object() else {
        return vec!["capture must be an object".into()];
    };
    for key in TOP_LEVEL {
        if !object.contains_key(key) {
            issues.push(format!("{key}: required"));
        }
    }
    for key in object.keys() {
        if !TOP_LEVEL.contains(&key.as_str()) {
            issues.push(format!("Unrecognized key: \"{key}\""));
        }
    }
    for key in ["frames", "rendered_frames", "interaction_events", "process_samples", "filesystem_checkpoints", "event_journal",
        "files_before", "files_after", "filesystem_effects", "limitations", "residual_unknowns"]
    {
        if object.get(key).is_some_and(|v| !v.is_array()) {
            issues.push(format!("{key}: expected array"));
        }
    }
    if capture["manifest"]["pty_backend"] != "node-pty" {
        issues.push("manifest.pty_backend: expected \"node-pty\"".into());
    }
    if !capture["truncated"].is_boolean() {
        issues.push("truncated: expected boolean".into());
    }
    let settlement = &capture["settlement"];
    let valid_settlement = match settlement["state"].as_str() {
        Some("quiesced") => settlement["cleanup_outcome"] == "not_required",
        Some("alive_at_deadline" | "unverifiable") => matches!(settlement["cleanup_outcome"].as_str(), Some("cleaned" | "failed")),
        _ => false,
    };
    if !valid_settlement {
        issues.push("settlement: invalid settlement".into());
    }
    if settlement["cleanup_outcome"] == "failed" {
        issues.push("settlement.cleanup_outcome: verified captures cannot contain failed cleanup".into());
    }
    if !matches!(capture["exit"]["reason"].as_str(), Some("exited" | "timeout" | "idle_timeout")) {
        issues.push("exit.reason: invalid".into());
    }
    if capture["cleanup"]["owned_process_group"] != "verified" || capture["cleanup"]["temporary_root"] != "removed" {
        issues.push("cleanup: expected verified owned process group and removed temporary root".into());
    }
    for unknown in arr(&capture["residual_unknowns"]) {
        if !unknown["scope"].is_string() || !unknown["reason"].is_string() {
            issues.push("residual_unknowns: expected scope and reason".into());
        }
    }
    issues
}

fn ordered(values: &[Value]) -> bool {
    values.windows(2).all(|w| u(&w[1]["at_ms"]) >= u(&w[0]["at_ms"]))
}

/// Recompute commitments and cross-field invariants.
pub fn collect_capture_issues(capture: &Value) -> Vec<String> {
    let structural = structural_issues(capture);
    if !structural.is_empty() {
        return structural;
    }
    let mut issues = Vec::new();
    let mut require = |ok: bool, path: &str, message: &str| {
        if !ok {
            issues.push(format!("{path}: {message}"));
        }
    };
    let manifest = &capture["manifest"];
    require(
        manifest["scenario"]["executable_sha256"] == manifest["selected_executable_sha256"],
        "manifest.selected_executable_sha256",
        "selected executable commitment does not match the scenario projection",
    );
    let identity_ok = if manifest["executable_identity"]["state"] == "path_metadata_unchanged" {
        manifest["executable_sha256"] == manifest["selected_executable_sha256"] && manifest["executable_identity"]["reason"].is_null()
    } else {
        manifest["executable_sha256"].is_null() && !manifest["executable_identity"]["reason"].is_null()
    };
    require(identity_ok, "manifest.executable_identity", "launch identity and executable digest do not agree");
    for (field, value) in [
        ("full_scenario_sha256", &manifest["scenario"]),
        ("comparison_contract_sha256", &manifest["comparison_contract"]),
        ("normalization_sha256", &capture["normalization"]),
    ] {
        let digest = digest_commitment(value).ok();
        require(
            digest.as_deref() == manifest[field].as_str(),
            &format!("manifest.{field}"),
            "commitment does not match its canonical value",
        );
    }
    let started = manifest["started_at"].as_str().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
    let completed = manifest["completed_at"].as_str().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
    require(
        matches!((started, completed), (Some(s), Some(c)) if s <= c),
        "manifest.completed_at",
        "completion precedes start",
    );
    for name in ["frames", "rendered_frames", "interaction_events"] {
        require(
            arr(&capture[name]).iter().enumerate().all(|(i, v)| v["sequence"].as_u64() == Some(i as u64)),
            name,
            "sequence values must be contiguous from zero",
        );
    }
    for name in ["frames", "rendered_frames", "process_samples"] {
        require(ordered(arr(&capture[name])), name, "timestamps must be ordered");
    }
    let journal = arr(&capture["event_journal"]);
    if !journal.is_empty() {
        let size = |collection: &str| -> u64 {
            match collection {
                "lifecycle" => 2,
                "frames" | "rendered_frames" | "interaction_events" | "process_samples" | "filesystem_checkpoints" => {
                    arr(&capture[collection]).len() as u64
                }
                _ => 0,
            }
        };
        let mut references = std::collections::HashSet::new();
        for (position, entry) in journal.iter().enumerate() {
            require(entry["capture_order"].as_u64() == Some(position as u64), &format!("event_journal.{position}.capture_order"), "capture order must be contiguous from zero");
            let collection = entry["collection"].as_str().unwrap_or_default();
            require(u(&entry["index"]) < size(collection), &format!("event_journal.{position}.index"), "journal reference is outside its capture collection");
            let reference = format!("{collection}:{}", u(&entry["index"]));
            require(!references.contains(&reference), &format!("event_journal.{position}"), "journal references must be unique");
            references.insert(reference);
        }
        let expected: u64 = ["frames", "rendered_frames", "interaction_events", "lifecycle", "process_samples", "filesystem_checkpoints"]
            .iter()
            .map(|c| size(c))
            .sum();
        require(journal.len() as u64 == expected, "event_journal", "nonempty journal must reference every captured observation");
    }
    let checkpoints = arr(&capture["filesystem_checkpoints"]);
    let names: Vec<&str> = checkpoints.iter().filter_map(|c| c["name"].as_str()).collect();
    require(names == ["before", "after_settlement"], "filesystem_checkpoints", "capture must include initial and final filesystem snapshots");
    require(ordered(checkpoints), "filesystem_checkpoints", "filesystem snapshot times must be ordered");
    let truncated = capture["truncated"].as_bool() == Some(true);
    require(
        !checkpoints.iter().any(|c| c["truncated"] == true) || truncated,
        "truncated",
        "filesystem snapshot truncation must propagate to the capture",
    );
    require(
        capture["exit"]["reason"] == "exited" || capture["exit"]["code"].is_null(),
        "exit",
        "deadline termination cannot declare a normal exit code",
    );
    let details = &capture["truncation_details"];
    let process = &details["process"];
    let failures = u(&process["sampling_failures"]);
    require(
        u(&process["retained_samples"]) == arr(&capture["process_samples"]).len() as u64
            && u(&process["retained_samples"]) <= u(&process["sample_limit"])
            && process["sampling_partial"].as_bool() == Some(process["sample_limit_reached"] == true || failures > 0)
            && (failures == 0) == process["first_sampling_failure"].is_null(),
        "truncation_details.process",
        "sampling coverage must agree with retained samples and observed failures",
    );
    let omitted = |r: &Value| u(&r["observed_frames"]) > u(&r["retained_frames"]);
    let fs_truncated = |c: &Value| c["enumeration_truncated"] == true || !arr(&c["hash_omissions"]).is_empty();
    let aggregate = omitted(&details["raw_terminal"])
        || omitted(&details["rendered_terminal"])
        || fs_truncated(&details["filesystem_before"])
        || fs_truncated(&details["filesystem_after"])
        || process["sampling_partial"] == true;
    require(truncated == aggregate, "truncation_details", "aggregate truncation must match producer coverage");
    let raw_bytes: u64 = arr(&capture["frames"])
        .iter()
        .map(|f| f.get("raw_data").unwrap_or(&f["data"]).as_str().map_or(0, str::len) as u64)
        .sum();
    let rendered_bytes: u64 = arr(&capture["rendered_frames"])
        .iter()
        .map(|f| {
            f["serialized_state"].as_str().map_or(0, str::len) as u64
                + arr(&f["lines"]).iter().map(|l| l.as_str().map_or(0, str::len) as u64).sum::<u64>()
        })
        .sum();
    for (name, count, bytes) in [
        ("raw_terminal", arr(&capture["frames"]).len() as u64, raw_bytes),
        ("rendered_terminal", arr(&capture["rendered_frames"]).len() as u64, rendered_bytes),
    ] {
        let r = &details[name];
        require(
            u(&r["retained_frames"]) == count
                && u(&r["observed_frames"]) >= count
                && u(&r["retained_bytes"]) == bytes
                && u(&r["observed_bytes"]) >= u(&r["retained_bytes"])
                && (u(&r["observed_frames"]) > count || u(&r["observed_bytes"]) == u(&r["retained_bytes"]))
                && u(&r["retained_bytes"]) <= u(&r["budget_bytes"]),
            &format!("truncation_details.{name}"),
            "retained observations and budget accounting do not agree",
        );
    }
    for (name, files, index) in [("filesystem_before", "files_before", 0), ("filesystem_after", "files_after", 1)] {
        let coverage = &details[name];
        let files = arr(&capture[files]);
        let unhashed: std::collections::HashMap<&str, u64> = files
            .iter()
            .filter(|f| f["type"] == "file" && f["sha256"].is_null())
            .filter_map(|f| Some((f["path"].as_str()?, u(&f["size"]))))
            .collect();
        let omissions = arr(&coverage["hash_omissions"]);
        let omission_paths: std::collections::HashSet<&str> = omissions.iter().filter_map(|o| o["path"].as_str()).collect();
        require(
            omissions.len() == unhashed.len()
                && omission_paths.len() == unhashed.len()
                && omissions.iter().all(|o| {
                    o["path"].as_str().and_then(|p| unhashed.get(p)).copied() == Some(u(&o["size_bytes"]))
                        && u(&o["remaining_budget_bytes"]) <= u(&coverage["hash_budget_bytes"])
                        && if o["reason"] == "file_unavailable" { !o["system_code"].is_null() } else { o["system_code"].is_null() }
                }),
            &format!("truncation_details.{name}.hash_omissions"),
            "every retained regular file without a digest must have one matching omission reason",
        );
        let hashed: u64 = files.iter().filter(|f| f["type"] == "file" && !f["sha256"].is_null()).map(|f| u(&f["size"])).sum();
        require(
            u(&coverage["hashed_bytes"]) == hashed
                && u(&coverage["hashed_bytes"]) <= u(&coverage["hash_budget_bytes"])
                && files.len() as u64 <= u(&coverage["files_limit"]),
            &format!("truncation_details.{name}"),
            "filesystem budget accounting does not match retained observations",
        );
        let enumeration_truncated = coverage["enumeration_truncated"] == true;
        require(
            enumeration_truncated == !arr(&coverage["enumeration_reasons"]).is_empty()
                && checkpoints.get(index).map(|c| c["truncated"] == true) == Some(enumeration_truncated || !omissions.is_empty()),
            &format!("truncation_details.{name}"),
            "filesystem checkpoint truncation must match enumeration and digest coverage",
        );
    }
    issues
}
