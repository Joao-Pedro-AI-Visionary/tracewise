use serde_json::Value;
use tracewise_domain::canonical::{canonical_json, canonical_sha256};
use tracewise_domain::evidence::Evidence;
use tracewise_domain::ledger::EvidenceLedger;
use tracewise_domain::parse_evidence_bundle;
use tracewise_domain::unknown::{
    create_residual_unknown, update_residual_unknown, RecordUnknownInput, UpdateUnknownInput,
};

fn fixture_path(name: &str) -> String {
    format!(
        "{}/../../fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

#[test]
fn test_canonical_cases() {
    let raw = std::fs::read_to_string(fixture_path("canonical_cases.json"))
        .expect("Failed to read canonical_cases.json");
    let cases: Vec<Value> = serde_json::from_str(&raw).expect("Failed to parse canonical_cases.json");

    for (i, case) in cases.iter().enumerate() {
        let val = &case["value"];
        let expected = case["sha256"].as_str().expect("Expected sha256 string");
        let hash = canonical_sha256(val).expect("Failed to canonicalize value");
        assert_eq!(
            hash, expected,
            "Case {i} failed: expected {expected}, got {hash}"
        );
    }
}

#[test]
fn test_evidence_cases() {
    let raw = std::fs::read_to_string(fixture_path("evidence_cases.json"))
        .expect("Failed to read evidence_cases.json");
    let cases: Vec<Value> = serde_json::from_str(&raw).expect("Failed to parse evidence_cases.json");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let ev_val = &case["evidence"];
        let evidence: Evidence = serde_json::from_value(ev_val.clone())
            .unwrap_or_else(|e| panic!("Failed to deserialize evidence in case '{name}': {e}"));

        // 1. Recompute id == fixture id
        let computed_id = evidence
            .compute_id()
            .unwrap_or_else(|e| panic!("Failed to compute id in case '{name}': {e}"));
        assert_eq!(
            computed_id, evidence.evidence_id,
            "Case '{name}' ID mismatch: expected {}, got {}",
            evidence.evidence_id, computed_id
        );

        // 2. Verification passes
        assert!(
            evidence.verify().is_ok(),
            "Case '{name}' verification failed"
        );

        // 3. Tampering is rejected
        let mut tampered = evidence.clone();
        tampered.predicate_type = format!("{}.tampered", tampered.predicate_type);
        assert!(
            tampered.verify().is_err(),
            "Case '{name}' should fail after tampering predicate_type"
        );

        let mut tampered_id = evidence.clone();
        tampered_id.evidence_id = "ev_0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(
            tampered_id.verify().is_err(),
            "Case '{name}' should fail after tampering evidence_id"
        );
    }
}

#[test]
fn test_unknown_cases() {
    let raw = std::fs::read_to_string(fixture_path("unknown_cases.json"))
        .expect("Failed to read unknown_cases.json");
    let cases: Value = serde_json::from_str(&raw).expect("Failed to parse unknown_cases.json");

    let record_input: RecordUnknownInput =
        serde_json::from_value(cases["record_input"].clone()).unwrap();
    let mutation_evidence_id = cases["mutation_evidence_id"].as_str().unwrap();
    let scope_digest = cases["scope_digest"].as_str().map(|s| s.to_string());

    // 1. Reproduce revision1
    let rev1 = create_residual_unknown(&record_input, mutation_evidence_id, scope_digest)
        .expect("Failed to create revision1");
    let expected_rev1_val = &cases["revision1"];
    let rev1_val = serde_json::to_value(&rev1).unwrap();
    assert_eq!(
        rev1_val, *expected_rev1_val,
        "revision1 serde_json::Value does not match fixture byte-for-byte"
    );
    assert_eq!(
        rev1.revision_digest,
        expected_rev1_val["revision_digest"].as_str().unwrap()
    );

    // 2. Reproduce contradicted_no_scope
    let mut contradicted_input = record_input.clone();
    contradicted_input.contradicting_evidence_ids = vec![
        "ev_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
    ];
    let contradicted_mutation_id =
        "ev_2222222222222222222222222222222222222222222222222222222222222222";
    let contradicted =
        create_residual_unknown(&contradicted_input, contradicted_mutation_id, None)
            .expect("Failed to create contradicted_no_scope");
    let expected_contradicted_val = &cases["contradicted_no_scope"];
    let contradicted_val = serde_json::to_value(&contradicted).unwrap();
    assert_eq!(
        contradicted_val, *expected_contradicted_val,
        "contradicted_no_scope serde_json::Value does not match fixture byte-for-byte"
    );
    assert_eq!(
        contradicted.revision_digest,
        expected_contradicted_val["revision_digest"].as_str().unwrap()
    );

    // 3. Reproduce revision2
    let expected_rev2_val = &cases["revision2"];
    let update_input = UpdateUnknownInput {
        unknown_id: rev1.unknown_id.clone(),
        expected_revision: 1,
        status: tracewise_domain::unknown::UnknownStatus::Resolved,
        severity: tracewise_domain::unknown::UnknownSeverity::Low,
        supporting_evidence_ids: vec![
            "ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ],
        contradicting_evidence_ids: vec![],
        required_authority: Some(tracewise_domain::evidence::EvidenceAuthority::ShippedArtifact),
        required_confidence: tracewise_domain::evidence::EvidenceConfidence::Derived,
        required_environment: Some(tracewise_domain::unknown::EnvironmentRequirement {
            id: None,
            platform: Some("linux".to_string()),
            architecture: None,
            isolation: Some(tracewise_domain::evidence::IsolationLevel::Process),
        }),
        recommended_probes: vec![],
        relationships: vec![],
        resolution: Some(tracewise_domain::unknown::Resolution {
            disposition: tracewise_domain::unknown::ResolutionDisposition::Verified,
            rationale: "seen".to_string(),
            evidence_ids: vec![
                "ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ],
        }),
    };
    let update_mutation_id = cases["update_mutation_evidence_id"].as_str().unwrap();
    let rev2 = update_residual_unknown(&rev1, &update_input, update_mutation_id)
        .expect("Failed to update to revision2");
    let rev2_val = serde_json::to_value(&rev2).unwrap();
    assert_eq!(
        rev2_val, *expected_rev2_val,
        "revision2 serde_json::Value does not match fixture byte-for-byte"
    );
    assert_eq!(
        rev2.revision_digest,
        expected_rev2_val["revision_digest"].as_str().unwrap()
    );
}

#[test]
fn test_rea_bundle_roundtrip() {
    let path = fixture_path("rea_bundle.json");
    let file_bytes = std::fs::read(&path).expect("Failed to read rea_bundle.json");
    let raw = String::from_utf8(file_bytes.clone()).expect("rea_bundle.json must be UTF-8");

    let bundle = parse_evidence_bundle(&raw).expect("Failed to parse REA evidence bundle");

    let mut ledger = EvidenceLedger::new();
    ledger
        .import(&bundle)
        .expect("Failed to import REA evidence bundle into ledger");

    for record in &bundle.records {
        let computed_id = record
            .compute_id()
            .unwrap_or_else(|e| panic!("Failed to recompute evidence_id for {}: {e}", record.evidence_id));
        assert_eq!(
            computed_id, record.evidence_id,
            "evidence_id re-authentication failed for {}",
            record.evidence_id
        );
        assert!(
            record.verify().is_ok(),
            "evidence verify failed for {}",
            record.evidence_id
        );
    }

    let serialized = canonical_json(&bundle).expect("Failed to serialize evidence bundle");
    assert_eq!(
        serialized.as_bytes(),
        file_bytes.as_slice(),
        "re-serialized bundle must be byte-identical to fixtures/rea_bundle.json"
    );
}

#[test]
fn test_profile_evidence_cases() {
    let raw = std::fs::read_to_string(fixture_path("profile_evidence_cases.json"))
        .expect("Failed to read profile_evidence_cases.json");
    let cases: Vec<Value> =
        serde_json::from_str(&raw).expect("Failed to parse profile_evidence_cases.json");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let ev_val = &case["evidence"];
        let evidence: Evidence = serde_json::from_value(ev_val.clone())
            .unwrap_or_else(|e| panic!("Failed to deserialize evidence in case '{name}': {e}"));

        // 1. Evidence id matches
        let computed_id = evidence
            .compute_id()
            .unwrap_or_else(|e| panic!("Failed to compute id in case '{name}': {e}"));
        assert_eq!(
            computed_id, evidence.evidence_id,
            "Case '{name}' ID mismatch: expected {}, got {}",
            evidence.evidence_id, computed_id
        );

        // 2. Profile digest must be recomputed and verified
        let profile_val = evidence
            .analysis_profile
            .as_ref()
            .expect("profile_evidence_cases must have non-null analysis_profile");
        let profile: tracewise_domain::evidence::AnalysisProfile =
            serde_json::from_value(profile_val.clone())
                .unwrap_or_else(|e| panic!("Failed to deserialize profile in case '{name}': {e}"));
        let computed_digest = profile
            .compute_digest()
            .unwrap_or_else(|e| panic!("Failed to compute profile digest in case '{name}': {e}"));
        assert_eq!(
            computed_digest, profile.digest,
            "Case '{name}' profile digest mismatch: expected {}, got {}",
            profile.digest, computed_digest
        );
        assert!(
            profile.verify().is_ok(),
            "Case '{name}' profile verify failed"
        );

        // 3. Evidence verification passes
        assert!(
            evidence.verify().is_ok(),
            "Case '{name}' evidence verify failed"
        );
    }
}

#[test]
fn test_compare_bundles_cases() {
    let raw = std::fs::read_to_string(fixture_path("compare_bundles_cases.json"))
        .expect("Failed to read compare_bundles_cases.json");
    let cases: Vec<Value> =
        serde_json::from_str(&raw).expect("Failed to parse compare_bundles_cases.json");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let left: tracewise_domain::EvidenceBundle =
            serde_json::from_value(case["left"].clone()).unwrap();
        let right: tracewise_domain::EvidenceBundle =
            serde_json::from_value(case["right"].clone()).unwrap();
        let record_pairs: Vec<tracewise_domain::RecordPair> =
            serde_json::from_value(case["record_pairs"].clone()).unwrap();
        let expected_result = &case["result"];

        let actual = tracewise_domain::compare_bundles(&left, &right, &record_pairs)
            .unwrap_or_else(|e| panic!("compare_bundles failed on case '{name}': {e}"));
        let actual_val = serde_json::to_value(&actual).unwrap();

        assert_eq!(
            actual_val, *expected_result,
            "Case '{name}' compare_bundles result did not match fixture exactly"
        );
    }
}

