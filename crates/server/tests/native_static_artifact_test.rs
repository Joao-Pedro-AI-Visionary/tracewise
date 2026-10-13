//! Parity of `trace_dylib_resolution`, `inspect_keyed_archive` and
//! `decode_interface_builder` with the REA oracle (Linux, no macOS tools needed).
//! See `native_support/mod.rs` for the scenario files and the normalization.

mod native_support;

use native_support::run_scenarios;

#[tokio::test]
async fn trace_dylib_resolution_matches_oracle() {
    assert!(run_scenarios("dylib_", &[]).await >= 18);
}

#[tokio::test]
async fn inspect_keyed_archive_matches_oracle() {
    assert!(run_scenarios("ka_", &[]).await >= 25);
}

#[tokio::test]
async fn decode_interface_builder_matches_oracle() {
    assert!(run_scenarios("ib_", &[]).await >= 6);
}

// ---------------------------------------------------------------------------
// project_apple_application_graph
//
// Two replays of the same scenarios (`scenarios.json`, oracle results in `oracle/<id>.json`):
//
// * `project_apple_application_graph_matches_oracle`: only the projection is replayed; its input is the ORACLE's
//   `inspect_artifact` Evidence (`only` in scenarios.json), so the comparison isolates this tool
//   from the Phase 2 inventory.
// * `project_apple_application_graph_from_own_inventory_matches_oracle`: EVERY call is replayed with tracewise's tools, so the
//   projection is fed with tracewise's own `open_binary` + `inspect_artifact` Evidence, and each
//   of those answers is compared with the oracle's too, Evidence ids included. This is what
//   became possible once `open_binary` resolved app bundles and the artifact inventory classified
//   Mach-O libraries and hashed nested directories the way REA does.
//
// Evidence ids hash the record, paths included. The oracle ran in /workspace/wt/native_static; in any
// other checkout the oracle's Evidence gets its paths rewritten and its ids recomputed
// (`native_support::retarget_evidence`), the ids the tool copies follow, and only `projection_id`
// (a hash over those ids) is left out of the comparison. In the oracle's own checkout everything
// is compared byte for byte.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn project_apple_application_graph_matches_oracle() {
    assert!(run_scenarios("apple_", &[]).await >= 20);
}

#[tokio::test]
async fn project_apple_application_graph_from_own_inventory_matches_oracle() {
    // Every call of the 24 apple_ scenarios (68): open_binary, inspect_artifact and the projection.
    assert_eq!(native_support::run_scenarios_full("apple_", &[]).await, 68);
}
