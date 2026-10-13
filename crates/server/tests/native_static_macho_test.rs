//! `list_architectures`, `inspect_macho`, `inspect_signature`, `inspect_plist` and
//! `demangle_swift` through the MCP dispatcher.
//!
//! REA's own server reports these tools as `unsupported_host` on Linux, so there is no live
//! oracle. The evidence is, per tool:
//! - golden parity with the ORIGINAL REA parsers on captured Apple tool output
//!   (`crates/native/tests/macho_golden_test.rs`, and `inspect_plist` below);
//! - manual, non-reproducible checks on Mach-O files that exist on the author's machine (LIEF for Mach-O structure, rcodesign for
//!   signatures), recorded in the commit messages and `docs/`;
//! - the assertions below on generated fixtures, plus the tool `outputSchema`.

mod native_support;

use rmcp::model::CallToolResult;
use serde_json::{json, Value};
use tracewise_server::session::BinarySession;

use native_support::{call, fixtures, output_schema, payload};

async fn open(session: &BinarySession, path: &std::path::Path) {
    let result = call(session, "open_binary", &json!({"path": path.to_string_lossy()})).await.unwrap();
    assert_ne!(result.is_error, Some(true), "open_binary failed: {:?}", payload(&result));
}

fn assert_schema(tool: &str, result: &CallToolResult) {
    let structured = result.structured_content.clone().expect("structured content");
    let validator = jsonschema::validator_for(&output_schema(tool).expect("catalog schema")).expect("schema");
    if let Err(error) = validator.validate(&structured) {
        panic!("{tool} violates its outputSchema: {error}\n{structured:#}");
    }
}

async fn ok(session: &BinarySession, tool: &str, arguments: Value) -> Value {
    let result = call(session, tool, &arguments).await.unwrap();
    assert_ne!(result.is_error, Some(true), "{tool}: {:?}", payload(&result));
    assert_schema(tool, &result);
    result.structured_content.unwrap()
}

async fn error_text(session: &BinarySession, tool: &str, arguments: Value) -> String {
    let result = call(session, tool, &arguments).await.unwrap();
    assert_eq!(result.is_error, Some(true), "{tool} should fail");
    result.content.iter().find_map(|c| c.as_text().map(|t| t.text.clone())).unwrap()
}

fn error_json(text: &str) -> Value {
    serde_json::from_str::<Value>(text).unwrap()["error"].clone()
}

fn codesign_fixture(name: &str) -> std::path::PathBuf {
    fixtures().join("codesign").join(name)
}

// ---------------------------------------------------------------------------
// list_architectures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_architectures_reports_thin_and_universal_files() {
    let session = BinarySession::new();
    open(&session, &codesign_fixture("unsigned_arm64.macho")).await;
    let thin = ok(&session, "list_architectures", json!({})).await;
    assert_eq!(
        thin["normalized_result"]["architectures"],
        json!({
            "items": [{"name": "arm64", "cpu_type": null, "cpu_subtype": null, "file_offset": null, "size": null, "alignment": null}],
            "total": 1,
            "exhaustive": true,
            "limitations": [],
        })
    );
    assert_eq!(thin["locations"], json!([]));
    assert_eq!(thin["provider"]["id"], "native-macos");
    assert_eq!(thin["operation"], "list_architectures");

    let session = BinarySession::new();
    open(&session, &codesign_fixture("universal_signed.macho")).await;
    let fat = ok(&session, "list_architectures", json!({})).await;
    let items = fat["normalized_result"]["architectures"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["name"], "x86_64");
    assert_eq!(items[0]["cpu_type"], "CPU_TYPE_X86_64");
    assert_eq!(items[0]["file_offset"], 16384);
    assert_eq!(items[0]["alignment"], 16384);
    assert_eq!(items[1]["name"], "arm64");
    assert_eq!(items[1]["cpu_subtype"], "CPU_SUBTYPE_ARM64_ALL");
    assert_eq!(fat["locations"][0]["kind"], "file-offset-range");
    assert_eq!(fat["locations"][0]["start"], 16384);
}

#[tokio::test]
async fn native_mach_o_tools_refuse_other_targets_and_bad_input() {
    let session = BinarySession::new();
    let text = error_text(&session, "list_architectures", json!({})).await;
    assert_eq!(error_json(&text)["code"], "target_unavailable");
    assert!(error_json(&text)["message"].as_str().unwrap().starts_with("No app is open."));

    open(&session, &fixtures().join("plists/xml_simple.plist")).await;
    for tool in ["list_architectures", "inspect_macho", "inspect_signature"] {
        let error = error_json(&error_text(&session, tool, json!({})).await);
        assert_eq!(error["code"], "capability_unavailable", "{tool}");
        assert_eq!(error["details"]["reason"], "Active artifact is not Mach-O.", "{tool}");
        assert_eq!(error["details"]["provider_id"], "native-macos", "{tool}");
    }
    let rejected = error_text(&session, "inspect_macho", json!({"x": 1})).await;
    assert_eq!(
        rejected,
        "Input validation error: Invalid arguments for tool inspect_macho: Unrecognized key: \"x\""
    );
}

// ---------------------------------------------------------------------------
// inspect_macho
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inspect_macho_decodes_a_universal_file_and_locates_segments() {
    let session = BinarySession::new();
    open(&session, &codesign_fixture("universal_mixed.macho")).await;
    let evidence = ok(&session, "inspect_macho", json!({})).await;
    let result = &evidence["normalized_result"];
    assert_eq!(result["format"], "mach-o");
    assert_eq!(result["architectures"]["items"].as_array().unwrap().len(), 2);
    // The default architecture of a universal target is its first slice.
    assert_eq!(result["word_size"], 64);
    assert_eq!(result["segments"]["items"][1]["name"], "__TEXT");
    let locations = evidence["locations"].as_array().unwrap();
    // Two slice ranges, then the segments of the selected slice offset by the slice position.
    assert_eq!(locations[0]["start"], 16384);
    assert_eq!(locations[2]["kind"], "file-offset-range");
    assert_eq!(locations[2]["start"], 16384);
    assert_eq!(result["provenance"][0]["tool"], "tracewise-native");
}

#[tokio::test]
async fn inspect_macho_reports_a_thin_file_with_segment_locations() {
    let session = BinarySession::new();
    open(&session, &fixtures().join("macho_golden/dyld_inventory.macho")).await;
    let evidence = ok(&session, "inspect_macho", json!({})).await;
    let result = &evidence["normalized_result"];
    assert_eq!(result["uuid"], "DD511BAA-DF23-31EA-A44A-0E09FC69C471");
    assert_eq!(result["entrypoints"]["items"], json!([{"file_offset": 1136}]));
    assert_eq!(result["dependencies"]["items"][1]["path"], "/usr/lib/libSystem.B.dylib");
    // Thin files have no slice offset in lipo's output; segment ranges start at the file start.
    assert!(evidence["locations"].as_array().unwrap().iter().any(|l| l["start"] == 0 && l["end"] == 16384));
}

// ---------------------------------------------------------------------------
// inspect_signature
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inspect_signature_reads_a_certificate_signature() {
    let session = BinarySession::new();
    open(&session, &codesign_fixture("cert_arm64.macho")).await;
    let evidence = ok(&session, "inspect_signature", json!({})).await;
    let result = &evidence["normalized_result"];
    assert_eq!(result["signed"], true);
    assert_eq!(result["identifier"], "com.example.fixture");
    assert_eq!(result["format"], "Mach-O thin (arm64)");
    assert_eq!(result["hash_algorithms"], json!(["sha256"]));
    assert_eq!(result["hardened_runtime"], true);
    assert_eq!(result["authorities"], json!(["Developer ID Application: Fixture Signer (ABCDE12345)"]));
    assert_eq!(
        result["designated_requirement"],
        "identifier \"com.example.fixture\" and certificate root = H\"4bc5df81dd55a1945128170d8712ea0ba364abe7\""
    );
    assert_eq!(
        result["entitlements"],
        json!({
            "com.apple.security.app-sandbox": true,
            "com.apple.security.network.client": true,
            "com.apple.security.application-groups": ["group.example"],
            "count": 3,
        })
    );
    // The Apple time stamp token embedded by the fixture generator.
    assert_eq!(result["timestamp"], "Oct 13, 2026 at 02:10:35");
    // CDHash: first 20 bytes of the SHA-256 of the code directory (`rcodesign
    // print-signature-info` lists the CodeDirectory sha256 f8a41cd3...).
    assert_eq!(result["cdhashes"], json!(["f8a41cd32ad14093888ff2d0a445fd33b408014e"]));
}

#[tokio::test]
async fn inspect_signature_reports_ad_hoc_unsigned_and_mixed_files() {
    let session = BinarySession::new();
    open(&session, &codesign_fixture("adhoc_arm64.macho")).await;
    let adhoc = ok(&session, "inspect_signature", json!({})).await;
    let result = &adhoc["normalized_result"];
    assert_eq!(result["signed"], true);
    assert_eq!(result["identifier"], "com.example.adhoc");
    assert_eq!(result["authorities"], json!([]));
    assert_eq!(result["timestamp"], Value::Null);
    assert_eq!(result["hardened_runtime"], false);
    let cdhash = result["cdhashes"][0].as_str().unwrap();
    assert_eq!(result["designated_requirement"], json!(format!("cdhash H\"{cdhash}\"")));

    let session = BinarySession::new();
    open(&session, &codesign_fixture("unsigned_arm64.macho")).await;
    let unsigned = ok(&session, "inspect_signature", json!({})).await;
    assert_eq!(unsigned["normalized_result"]["signed"], false);
    assert_eq!(unsigned["normalized_result"]["limitations"][0], "Artifact is not signed.");
    assert_eq!(unsigned["normalized_result"]["identifier"], Value::Null);

    // The first slice (x86_64) of the mixed file is unsigned; the arm64 slice is signed.
    let session = BinarySession::new();
    open(&session, &codesign_fixture("universal_mixed.macho")).await;
    let mixed = ok(&session, "inspect_signature", json!({})).await;
    let limitations = mixed["normalized_result"]["limitations"].to_string();
    assert_eq!(mixed["normalized_result"]["signed"], false);
    assert!(limitations.contains("Signed Mach-O slices: arm64."));

    let session = BinarySession::new();
    open(&session, &codesign_fixture("universal_signed.macho")).await;
    let universal = ok(&session, "inspect_signature", json!({})).await;
    assert_eq!(universal["normalized_result"]["format"], "Mach-O universal (x86_64 arm64)");
    assert_eq!(universal["normalized_result"]["signed"], true);
}

#[tokio::test]
async fn inspect_signature_rejects_a_target_whose_bytes_changed() {
    let directory = std::env::temp_dir().join(format!("native-static-sig-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("target.macho");
    std::fs::copy(codesign_fixture("adhoc_arm64.macho"), &path).unwrap();
    let session = BinarySession::new();
    open(&session, &path).await;
    std::fs::copy(codesign_fixture("cert_arm64.macho"), &path).unwrap();
    let error = error_json(&error_text(&session, "inspect_signature", json!({})).await);
    assert_eq!(error["code"], "artifact_changed");
    assert!(error["details"]["reason"].as_str().unwrap().contains("digest changed"));
    std::fs::remove_dir_all(&directory).ok();
}

// ---------------------------------------------------------------------------
// inspect_plist (golden: the original REA on the plutil view of each file)
// ---------------------------------------------------------------------------

const REA_XML_SENTENCE_PREFIX: &str = "plutil cannot express this plist as JSON";

#[tokio::test]
async fn inspect_plist_matches_rea_on_plutil_equivalent_input() {
    let session = BinarySession::new();
    open(&session, &fixtures().join("bundles/Rich.app")).await;
    for name in ["xml_simple", "binary_simple", "xml_typed", "binary_typed", "xml_bigint"] {
        let dir = fixtures().join("plists");
        let expected: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join(format!("{name}.expected.json"))).unwrap()).unwrap();
        assert_eq!(expected["ok"], true, "{name}");
        let path = dir.join(format!("{name}.plist"));
        let evidence = ok(&session, "inspect_plist", json!({"path": path.to_string_lossy()})).await;
        let got = &evidence["normalized_result"];
        let want = &expected["result"];
        assert_eq!(got["format"], want["format"], "{name}: format");
        assert_eq!(got["value"], want["value"], "{name}: value");
        assert_eq!(got["bundle"], want["bundle"], "{name}: bundle");
        // The native decoder states the same facts without naming plutil.
        let adapt = |limitations: &Value| -> Vec<String> {
            limitations
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l.as_str().unwrap().to_string())
                .map(|l| {
                    if l.starts_with(REA_XML_SENTENCE_PREFIX)
                        || l.starts_with("This plist contains data, date or non-finite real values")
                    {
                        "typed".to_string()
                    } else {
                        l
                    }
                })
                .collect()
        };
        assert_eq!(adapt(&got["limitations"]), adapt(&want["limitations"]), "{name}: limitations");
        assert_eq!(evidence["locations"], json!([{"kind": "artifact-path", "path": path.to_string_lossy()}]), "{name}");
    }
}

#[tokio::test]
async fn inspect_plist_resolves_the_default_and_relative_paths_and_reports_failures() {
    let session = BinarySession::new();
    open(&session, &fixtures().join("bundles/Rich.app")).await;
    let default = ok(&session, "inspect_plist", json!({})).await;
    assert_eq!(default["normalized_result"]["bundle"]["executable"], "Rich");
    assert!(default["normalized_result"]["source_path"].as_str().unwrap().ends_with("Rich.app/Contents/Info.plist"));
    assert_eq!(default["parameters"], json!({}));

    let relative = ok(&session, "inspect_plist", json!({"path": "Contents/XPCServices/Helper.xpc/Contents/Info.plist"})).await;
    assert!(relative["normalized_result"]["source_path"].as_str().unwrap().ends_with("Helper.xpc/Contents/Info.plist"));

    let missing = error_json(&error_text(&session, "inspect_plist", json!({"path": "Contents/Nope.plist"})).await);
    assert_eq!(missing["code"], "invalid_request");
    assert!(missing["details"]["issues"][0]["message"].as_str().unwrap().ends_with("no file exists there."));
    assert_eq!(missing["details"]["issues"][0]["path"], json!(["path"]));
    let directory = error_json(&error_text(&session, "inspect_plist", json!({"path": "Contents"})).await);
    assert!(directory["details"]["issues"][0]["message"].as_str().unwrap().ends_with("it is not a regular file."));

    let plists = fixtures().join("plists");
    for name in ["not_plist.txt", "empty.plist", "truncated.plist"] {
        let path = plists.join(name);
        let error = error_json(&error_text(&session, "inspect_plist", json!({"path": path.to_string_lossy()})).await);
        assert_eq!(error["code"], "invalid_request", "{name}");
        assert!(
            error["details"]["issues"][0]["message"].as_str().unwrap().contains("could not be decoded as a property list"),
            "{name}"
        );
    }
    let json_plist = ok(&session, "inspect_plist", json!({"path": plists.join("json.plist").to_string_lossy()})).await;
    assert_eq!(json_plist["normalized_result"]["format"], "json");
    assert_eq!(json_plist["normalized_result"]["bundle"]["name"], "Json");

    let proto = ok(&session, "inspect_plist", json!({"path": plists.join("proto.plist").to_string_lossy()})).await;
    assert_eq!(proto["normalized_result"]["value"], json!({"CFBundleName": "P"}));
    assert!(proto["normalized_result"]["limitations"][0].as_str().unwrap().contains("__proto__"));

    // A bundle without the default plist is reported as a capability gap with a user message.
    let session = BinarySession::new();
    open(&session, &fixtures().join("bundles/plain/Info.plist")).await;
    let error = error_json(&error_text(&session, "inspect_plist", json!({})).await);
    assert_eq!(error["code"], "capability_unavailable");
    assert!(error["message"].as_str().unwrap().starts_with("The target has no readable Contents/Info.plist at "));

    assert_eq!(
        error_text(&session, "inspect_plist", json!({"path": ""})).await,
        "Input validation error: Invalid arguments for tool inspect_plist: path: Too small: expected string to have >=1 characters"
    );
}

// ---------------------------------------------------------------------------
// demangle_swift
// ---------------------------------------------------------------------------

#[tokio::test]
async fn demangle_swift_reports_demangled_unchanged_and_invalid_names() {
    let session = BinarySession::new();
    open(&session, &codesign_fixture("unsigned_arm64.macho")).await;
    let evidence = ok(
        &session,
        "demangle_swift",
        json!({"symbols": ["$s4Test3fooyyF", "plain_symbol", "_$s4Test3fooyyF", "$sbogus"]}),
    )
    .await;
    let rows = evidence["normalized_result"]["symbols"].as_array().unwrap();
    let summary: Vec<(&str, &str)> =
        rows.iter().map(|r| (r["output"].as_str().unwrap(), r["status"].as_str().unwrap())).collect();
    assert_eq!(
        summary,
        vec![
            ("Test.foo() -> ()", "demangled"),
            ("plain_symbol", "unchanged"),
            ("Test.foo() -> ()", "demangled"),
            ("$sbogus", "invalid"),
        ]
    );
    assert_eq!(evidence["parameters"], json!({"symbols": ["$s4Test3fooyyF", "plain_symbol", "_$s4Test3fooyyF", "$sbogus"]}));

    let cases = [
        (json!({}), "symbols: Invalid input: expected array, received undefined"),
        (json!({"symbols": []}), "symbols: Too small: expected array to have >=1 items"),
        (json!({"symbols": [""]}), "symbols.0: Too small: expected string to have >=1 characters"),
        (json!({"symbols": ["a\nb"]}), "symbols.0: Each Swift symbol must be one line."),
        (json!({"symbols": ["a\u{0}b"]}), "symbols.0: Swift symbols cannot contain NUL."),
        (json!({"symbols": [1]}), "symbols.0: Invalid input: expected string, received number"),
        (json!({"symbols": ["a"], "x": 1}), "Unrecognized key: \"x\""),
    ];
    for (arguments, message) in cases {
        assert_eq!(
            error_text(&session, "demangle_swift", arguments).await,
            format!("Input validation error: Invalid arguments for tool demangle_swift: {message}")
        );
    }
}

// ---------------------------------------------------------------------------
// Hostile property lists through inspect_plist (debug build: the stack is the small one).
// ---------------------------------------------------------------------------

fn scratch_file(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tracewise-hostile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[tokio::test]
async fn inspect_plist_refuses_4000_nested_xml_arrays_without_overflowing_the_stack() {
    let mut xml = String::from("<?xml version=\"1.0\"?><plist version=\"1.0\">");
    xml.push_str(&"<array>".repeat(4000));
    xml.push_str(&"</array>".repeat(4000));
    xml.push_str("</plist>");
    let path = scratch_file("nested.plist", xml.as_bytes());
    let session = BinarySession::new();
    open(&session, &fixtures().join("bundles/Rich.app")).await;
    let error = error_json(&error_text(&session, "inspect_plist", json!({"path": path.to_string_lossy()})).await);
    let text = error.to_string();
    assert!(text.contains("nesting exceeds"), "{text}");
}

#[tokio::test]
async fn inspect_plist_refuses_4000_nested_json_arrays() {
    let json_text = format!("{}{}", "[".repeat(4000), "]".repeat(4000));
    let path = scratch_file("nested-json.plist", json_text.as_bytes());
    let session = BinarySession::new();
    open(&session, &fixtures().join("bundles/Rich.app")).await;
    let error = error_json(&error_text(&session, "inspect_plist", json!({"path": path.to_string_lossy()})).await);
    assert_eq!(error["code"], "invalid_request");
}

/// A binary plist of `levels` arrays whose two elements both reference the next level.
fn binary_plist_with_fan_out(levels: u8) -> Vec<u8> {
    let mut out = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    for level in 0..levels {
        offsets.push(out.len() as u16);
        out.extend_from_slice(&[0xa2, level + 1, level + 1]);
    }
    offsets.push(out.len() as u16);
    out.extend_from_slice(&[0x10, 0x00]);
    let table = out.len() as u64;
    for offset in &offsets {
        out.extend_from_slice(&offset.to_be_bytes());
    }
    out.extend_from_slice(&[0u8; 6]);
    out.extend_from_slice(&[2, 1]);
    out.extend_from_slice(&(offsets.len() as u64).to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&table.to_be_bytes());
    out
}

#[tokio::test]
async fn inspect_plist_refuses_a_binary_plist_that_expands_to_two_to_the_fiftieth_objects() {
    let path = scratch_file("bomb.plist", &binary_plist_with_fan_out(50));
    let session = BinarySession::new();
    open(&session, &fixtures().join("bundles/Rich.app")).await;
    // Baseline: refusing a plist that does not exist costs the same fixed dispatch overhead (schema, session,
    // blocking-pool hop) with no decoding at all. Taking the faster of two calls drops one-time costs.
    let mut baseline = std::time::Duration::MAX;
    for _ in 0..2 {
        let started = std::time::Instant::now();
        let _ = error_text(&session, "inspect_plist", json!({"path": "Contents/Nope.plist"})).await;
        baseline = baseline.min(started.elapsed());
    }
    let started = std::time::Instant::now();
    let error = error_json(&error_text(&session, "inspect_plist", json!({"path": path.to_string_lossy()})).await);
    let elapsed = started.elapsed();
    println!("bplist 2^50 refused in {elapsed:?} (baseline call without any decoding: {baseline:?})");
    // Refusing is linear in the size of the FILE (294 bytes), not in the 2M-object decode budget: it must cost
    // about what a call that decodes nothing costs, and stay far below the old 10 s bound whatever the load.
    assert!(elapsed < std::time::Duration::from_secs(10), "refusal took {elapsed:?}");
    assert!(elapsed < baseline * 4 + std::time::Duration::from_millis(250), "refusal took {elapsed:?} vs baseline {baseline:?}");
    assert_eq!(error["code"], "invalid_request");
}

#[tokio::test]
async fn inspect_plist_refuses_a_binary_plist_whose_array_contains_itself() {
    let mut out = b"bplist00".to_vec();
    out.extend_from_slice(&[0xa2, 0x00, 0x00]);
    let table = out.len() as u64;
    out.extend_from_slice(&8u16.to_be_bytes());
    out.extend_from_slice(&[0u8; 6]);
    out.extend_from_slice(&[2, 1]);
    out.extend_from_slice(&1u64.to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&table.to_be_bytes());
    let path = scratch_file("self.plist", &out);
    let session = BinarySession::new();
    open(&session, &fixtures().join("bundles/Rich.app")).await;
    let error = error_json(&error_text(&session, "inspect_plist", json!({"path": path.to_string_lossy()})).await);
    assert!(error.to_string().contains("cycle"), "{error}");
}
