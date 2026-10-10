use serde_json::Value;
use tracewise_domain::canonical::canonical_sha256;
use tracewise_domain::evidence::Evidence;
use tracewise_domain::unknown::{
    create_residual_unknown, update_residual_unknown, RecordUnknownInput, UpdateUnknownInput,
};

#[test]
fn test_canonical_cases() {
    let raw = std::fs::read_to_string("/workspace/tracewise/fixtures/canonical_cases.json")
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
    let raw = std::fs::read_to_string("/workspace/tracewise/fixtures/evidence_cases.json")
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
    let raw = std::fs::read_to_string("/workspace/tracewise/fixtures/unknown_cases.json")
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
