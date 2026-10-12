#!/usr/bin/env python3
"""Regenerate b10 reconstruction fixtures by chaining the ORIGINAL REA MCP server.

Every fixture written here is real REA output. Process captures are timing
dependent, so rerunning this script produces new snapshots; the Rust tests
consume the stored snapshots (bundles + oracle outputs) as one consistent set.
"""
import hashlib, json, os, subprocess, sys

NODE = "/tmp/node-v22.20.0-linux-x64/bin/node"
HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "reconstruction_app")


class Rea:
    def __init__(self):
        self.p = subprocess.Popen([NODE, "/workspace/rea-map/src/scripts/rea.mjs", "mcp"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, cwd="/workspace/rea-map/src")
        self.i = 0
        self.rq("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "oracle", "version": "1"}})
        self.rq("notifications/initialized", notify=True)

    def rq(self, m, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": m}
        if params is not None:
            msg["params"] = params
        if not notify:
            self.i += 1
            msg["id"] = self.i
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        if notify:
            return None
        while True:
            r = json.loads(self.p.stdout.readline())
            if r.get("id") == self.i:
                return r

    def call(self, name, args, allow_error=False):
        res = self.rq("tools/call", {"name": name, "arguments": args})
        res = res.get("result", res)
        if res.get("isError") and not allow_error:
            raise SystemExit(f"{name} failed: {json.dumps(res)[:2000]}")
        return res

    def sc(self, name, args):
        return self.call(name, args)["structuredContent"]

    def export(self, path):
        self.call("export_evidence_bundle", {"path": path, "overwrite": True})
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)

    def close(self):
        self.p.kill()


def write(name, value):
    with open(os.path.join(HERE, name), "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def inventory(rea, path, policy="fail"):
    rea.sc("open_binary", {"path": path})
    inspected = rea.sc("inspect_artifact", {"integrity_policy": policy})
    return inspected["normalized_result"]["substeps"][0]["evidence"]


def capture(rea, script):
    return rea.sc("capture_process_scenario", {
        "executable": NODE, "arguments": [script], "working_directory": APP,
        "normalization": {"time_bucket_ms": 1000}})


def contract_sha(base):
    return hashlib.sha256(json.dumps(base, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def session_verify_pass():
    rea = Rea()
    left = inventory(rea, os.path.join(HERE, "app-a.zip"), "fail")
    right = inventory(rea, os.path.join(HERE, "app-a.zip"), "record-and-continue")
    same = rea.sc("compare_artifacts", {"left": left, "right": right})
    rea.export(os.path.join(HERE, "reconstruction_verify_pass_bundle.json"))
    spec = {"specification": {"name": "Rebuilt package matches original", "claims": [
        {"claim_id": "package.contents", "title": "  Package contents are identical  ",
         "kind": "structural-artifact", "dimension": "overall",
         "comparison_evidence_id": same["evidence_id"]}]}}
    write("reconstruction_verify_pass_input.json", spec)
    write("oracle_verify_reconstruction.json", rea.call("verify_reconstruction", spec))
    rea.close()


def session_investigation():
    rea = Rea()
    inv_a = inventory(rea, os.path.join(HERE, "app-a.zip"))
    inv_b = inventory(rea, os.path.join(HERE, "app-b.zip"))
    art_changed = rea.sc("compare_artifacts", {"left": inv_a, "right": inv_b})
    original = capture(rea, "original.js")
    regression = capture(rea, "regression.js")
    reimpl = capture(rea, "reimplementation.js")
    proc_bad = rea.sc("compare_process_captures", {"left": original, "right": regression})
    proc_ok = rea.sc("compare_process_captures", {"left": original, "right": reimpl})
    bundle = rea.export(os.path.join(HERE, "reconstruction_investigation_bundle.json"))
    write("reconstruction_investigation_comparisons.json", {
        "artifact_changed": art_changed, "process_regression": proc_bad,
        "process_reimplementation": proc_ok, "original_capture": original})

    spec = {"specification": {"name": "Invoice feature reconstruction", "claims": [
        {"claim_id": "invoice.output", "title": "Invoice total output", "kind": "behavioral",
         "dimension": "terminal", "comparison_evidence_id": proc_ok["evidence_id"]},
        {"claim_id": "invoice.regression", "title": "Regression build output", "kind": "behavioral",
         "dimension": "overall", "comparison_evidence_id": proc_bad["evidence_id"]},
        {"claim_id": "package.contents", "title": "Package contents", "kind": "structural-artifact",
         "dimension": "overall", "comparison_evidence_id": art_changed["evidence_id"]}]}}
    write("reconstruction_verify_fail_input.json", spec)
    write("oracle_verify_reconstruction_fail.json", rea.call("verify_reconstruction", spec))

    fcb = {"comparisons": [art_changed, proc_bad]}
    write("oracle_find_changed_behavior.json", rea.call("find_changed_behavior", fcb))

    changed_path = art_changed["normalized_result"]["changes"][0]["logical_path"]
    corr = {"static_comparisons": [art_changed],
            "runtime_comparisons": [proc_bad, proc_ok],
            "mappings": [
                {"static": {"comparison_evidence_id": art_changed["evidence_id"],
                            "selector": {"kind": "artifact", "logical_path": changed_path}},
                 "runtime": {"comparison_evidence_id": proc_bad["evidence_id"], "dimension": "terminal"},
                 "side_alignment": "left_to_left",
                 "hypothesis": {"statement": "  The changed module changes the printed total. ",
                                "expected_pattern": "cochanged"}},
                {"static": {"comparison_evidence_id": art_changed["evidence_id"],
                            "selector": {"kind": "artifact", "logical_path": changed_path}},
                 "runtime": {"comparison_evidence_id": proc_ok["evidence_id"], "dimension": "terminal"},
                 "side_alignment": "left_to_right",
                 "hypothesis": {"statement": "The module change is invisible on the terminal.",
                                "expected_pattern": "cochanged"}},
                {"static": {"comparison_evidence_id": art_changed["evidence_id"],
                            "selector": {"kind": "artifact", "logical_path": changed_path}},
                 "runtime": {"comparison_evidence_id": proc_ok["evidence_id"], "dimension": "filesystem"},
                 "side_alignment": "left_to_left",
                 "hypothesis": {"statement": "Filesystem effects follow the module.",
                                "expected_pattern": "static_only"}}]}
    write("reconstruction_correlate_input.json", corr)
    write("oracle_correlate_static_and_runtime.json", rea.call("correlate_static_and_runtime", corr))

    # A function comparison whose source dossiers are absent from the session fails closed.
    with open(os.path.join(HERE, "investigation_function_comparison.json"), encoding="utf-8") as handle:
        dangling = json.load(handle)
    write("oracle_find_changed_behavior_dangling.json",
          rea.call("find_changed_behavior", {"comparisons": [dangling]}, allow_error=True))

    coverage_cases(rea, bundle, inv_a, inv_b, art_changed, proc_ok, original)
    rea.close()


def coverage_cases(rea, bundle, inv_a, inv_b, art_changed, proc_ok, original):
    owner_sha = "a" * 64
    norm = "b" * 64
    base = {"verifier_id": "verifier.invoice", "claim_ids": ["claim.invoice-total"],
            "dimensions": ["terminal", "exit"], "authority": "controlled-replay",
            "max_age_ms": 315360000000, "minimum_repeats": 2,
            "normalization_sha256": norm, "normalization_removes_dimensions": False}
    contract = dict(base, contract_sha256=contract_sha(base))
    base2 = dict(base, verifier_id="verifier.package", claim_ids=["claim.package"],
                 dimensions=["content"], authority="shipped-artifact")
    contract2 = dict(base2, contract_sha256=contract_sha(base2))
    root_a = inv_a["subject"]["digest"]["sha256"]
    root_b = inv_b["subject"]["digest"]["sha256"]
    unknown_id = bundle["unknowns"][0]["unknown_id"]
    coverage = {
        "evidence_bundle": bundle,
        "artifacts": [
            {"artifact_id": "artifact.original", "artifact_sha256": root_a, "version": "1.0.0",
             "environment_sha256": "c" * 64, "evidence_ids": [inv_a["evidence_id"]]},
            {"artifact_id": "artifact.next", "artifact_sha256": root_b, "version": " 1.1.0 ",
             "environment_sha256": "c" * 64, "evidence_ids": [inv_b["evidence_id"]]}],
        "surfaces": [
            {"surface_id": "surface.invoice-total", "family": "cli", "artifact_id": "artifact.original",
             "occurrence_id": None, "location": "src/app.js", "authority": "observed",
             "dependency_surface_ids": ["surface.package"], "evidence_ids": [original["evidence_id"]]},
            {"surface_id": "surface.package", "family": "packaging", "artifact_id": "artifact.original",
             "occurrence_id": "occ-root", "location": "/", "authority": "derived",
             "dependency_surface_ids": ["surface.absent"], "evidence_ids": [inv_a["evidence_id"]]},
            {"surface_id": "surface.readme", "family": "docs", "artifact_id": "artifact.next",
             "occurrence_id": None, "location": "README.txt", "authority": "observed",
             "dependency_surface_ids": [], "evidence_ids": [inv_b["evidence_id"]]},
            {"surface_id": "surface.routing", "family": "ipc", "artifact_id": "artifact.next",
             "occurrence_id": None, "location": "src/app.js", "authority": "inferred",
             "dependency_surface_ids": [], "evidence_ids": [inv_b["evidence_id"]]}],
        "owners": [
            {"surface_id": "surface.invoice-total", "ownership": {
                "disposition": "implemented", "owner_path": "src/invoice.rs", "owner_export": "invoice_total",
                "owner_sha256": owner_sha, "path_state": "present", "package_state": "distributed",
                "authority_route": "none"}},
            {"surface_id": "surface.package", "ownership": {
                "disposition": "implemented", "owner_path": "Cargo.toml", "owner_export": None,
                "owner_sha256": "d" * 64, "path_state": "unknown", "package_state": "missing",
                "authority_route": "detected"}},
            {"surface_id": "surface.readme", "ownership": {"disposition": "non-goal", "rationale": "Docs are out of scope."}},
            {"surface_id": "surface.routing", "ownership": {"disposition": "external", "rationale": "Handled by host."}},
            {"surface_id": "surface.routing", "ownership": {"disposition": "non-goal", "rationale": "Duplicate."}}],
        "claims": [
            {"claim_id": "claim.invoice-total", "title": "Invoice total", "kind": "behavioral",
             "surface_ids": ["surface.invoice-total"], "required_dimensions": ["terminal"],
             "required_authority": "controlled-replay"},
            {"claim_id": "claim.package", "title": "Package", "kind": "structural",
             "surface_ids": ["surface.package"], "required_dimensions": ["content"],
             "required_authority": "shipped-artifact"},
            {"claim_id": "claim.unverified", "title": "Unverified", "kind": "behavioral",
             "surface_ids": ["surface.readme"], "required_dimensions": ["terminal"],
             "required_authority": "controlled-replay"}],
        "verifier_contracts": [contract, contract2],
        "verifier_results": [
            {"verifier_id": "verifier.invoice", "contract_sha256": contract["contract_sha256"],
             "observed_at": "2026-01-01T00:00:00.000Z", "status": "fail",
             "covered_claim_ids": ["claim.invoice-total"], "covered_dimensions": ["terminal"],
             "artifact_sha256s": [root_a], "owner_sha256s": [owner_sha], "normalization_sha256": norm,
             "repeats": 2, "evidence_ids": [proc_ok["evidence_id"]]},
            {"verifier_id": "verifier.invoice", "contract_sha256": contract["contract_sha256"],
             "observed_at": "2026-02-01T00:00:00+02:00", "status": "pass",
             "covered_claim_ids": ["claim.invoice-total"], "covered_dimensions": ["terminal", "exit"],
             "artifact_sha256s": [root_a], "owner_sha256s": [owner_sha], "normalization_sha256": norm,
             "repeats": 3, "evidence_ids": [proc_ok["evidence_id"]]},
            {"verifier_id": "verifier.package", "contract_sha256": contract2["contract_sha256"],
             "observed_at": "2026-02-01T00:00:00Z", "status": "unsupported",
             "covered_claim_ids": ["claim.package"], "covered_dimensions": ["content"],
             "artifact_sha256s": [root_a], "owner_sha256s": [], "normalization_sha256": norm,
             "repeats": 1, "evidence_ids": [art_changed["evidence_id"]]}],
        "residual_unknown_ids": [unknown_id],
        "contradictions": [
            {"contradiction_id": "contradiction.package", "status": "active",
             "surface_ids": ["surface.package"], "claim_ids": [],
             "evidence_ids": [inv_a["evidence_id"], inv_b["evidence_id"]]},
            {"contradiction_id": "contradiction.resolved", "status": "resolved",
             "surface_ids": ["surface.invoice-total"], "claim_ids": [],
             "evidence_ids": [inv_a["evidence_id"], inv_b["evidence_id"]]}],
        "package_proofs": [
            {"proof_id": "proof.build", "kind": "build", "status": "pass",
             "artifact_sha256s": [root_a, root_b], "evidence_ids": [art_changed["evidence_id"]]},
            {"proof_id": "proof.install", "kind": "clean-install", "status": "fail",
             "artifact_sha256s": [root_a], "evidence_ids": [art_changed["evidence_id"]]},
            {"proof_id": "proof.routing", "kind": "runtime-routing", "status": "skipped",
             "artifact_sha256s": [root_a], "evidence_ids": [art_changed["evidence_id"]]}],
        "boundaries": [
            {"boundary_id": "boundary.ready", "title": "Invoice core",
             "required_surface_ids": ["surface.invoice-total"], "required_claim_ids": ["claim.invoice-total"],
             "required_package_proof_kinds": ["build"], "allowed_dispositions": [],
             "allowed_unknown_ids": [unknown_id]},
            {"boundary_id": "boundary.full", "title": "Everything",
             "required_surface_ids": ["surface.invoice-total", "surface.package", "surface.readme",
                                      "surface.routing", "surface.missing"],
             "required_claim_ids": ["claim.invoice-total", "claim.package", "claim.unverified", "claim.missing"],
             "required_package_proof_kinds": ["build", "clean-install", "runtime-routing", "package-contents"],
             "allowed_dispositions": ["external"], "allowed_unknown_ids": []},
            {"boundary_id": "boundary.unknown", "title": "Package claim",
             "required_surface_ids": ["surface.readme"], "required_claim_ids": ["claim.package"],
             "required_package_proof_kinds": ["runtime-routing"], "allowed_dispositions": ["non-goal"],
             "allowed_unknown_ids": [unknown_id]},
            {"boundary_id": "boundary.partial", "title": "Docs",
             "required_surface_ids": ["surface.readme", "surface.gone"], "required_claim_ids": ["claim.unverified"],
             "required_package_proof_kinds": ["authority-independence"], "allowed_dispositions": ["non-goal"],
             "allowed_unknown_ids": [unknown_id]}]}
    write("reconstruction_coverage_input.json", coverage)
    cases = []
    for boundary in ["boundary.ready", "boundary.full", "boundary.unknown", "boundary.partial"]:
        cases.append({"boundary_id": boundary, "result": rea.call(
            "evaluate_reconstruction_coverage", {"coverage": coverage, "boundary_id": boundary})})
    write("oracle_evaluate_reconstruction_coverage.json", {"cases": cases})


def session_ledger():
    rea = Rea()
    application = rea.sc("analyze_javascript_application",
                         {"input_path": os.path.join(APP, "electron-app")})
    capture(rea, "original.js")
    bundle = rea.export(os.path.join(HERE, "reconstruction_ledger_bundle.json"))
    empty_manifest = {"bindings": [], "contradictions": []}
    first = rea.sc("build_reconstruction_obligation_ledger",
                   {"evidence_bundle": bundle, "reviewed_obligations": [], "manifest": empty_manifest})
    obligations = first["normalized_result"]["obligations"]
    by_family = {}
    for item in obligations:
        by_family.setdefault(item["family"], []).append(item)
    endpoint = by_family["endpoint"][0]
    process = by_family["packaged-process-lifecycle"][0]
    ipc = by_family["ipc"][0]
    proc_ev = process["authority_references"][0]["evidence_id"]
    app_ev = application["evidence_id"]
    reviewed = [{
        "obligation_id": "reviewed.invoice-export", "obligation_version": 2,
        "title": "  Export invoice as PDF ", "application_layer": "electron", "family": "invoice-export",
        "target": {"artifact_sha256": None, "application_node_id": None, "semantic_node_id": None,
                   "location": "src/main.js"},
        "required": True, "required_case_kinds": ["positive", "negative"],
        "required_original_authority": "process", "required_fixture_authority": "unit",
        "required_verifier_authority": "integration", "requires_parser_type": False,
        "dependency_obligation_ids": [endpoint["obligation_id"], "reviewed.absent"],
        "residual_unknown_ids": [], "unavailable_authority": [],
        "required_next_evidence": ["Capture the export round trip."], "disposition": "active",
        "review_evidence_ids": [proc_ev, app_ev]},
        {"obligation_id": "reviewed.printing", "obligation_version": 1, "title": "Printing",
         "application_layer": "process", "family": "printing",
         "target": {"artifact_sha256": None, "application_node_id": None, "semantic_node_id": None,
                    "location": "src/main.js"},
         "required": False, "required_case_kinds": ["positive"],
         "required_original_authority": "external", "required_fixture_authority": "external",
         "required_verifier_authority": "external", "requires_parser_type": False,
         "dependency_obligation_ids": [], "residual_unknown_ids": ["unk.printer"],
         "unavailable_authority": ["No printer was available."], "required_next_evidence": [],
         "disposition": "out-of-scope", "review_evidence_ids": [app_ev]}]
    manifest = {"bindings": [
        {"obligation_id": endpoint["obligation_id"],
         "owner": {"module_path": "src/invoice/render.rs", "symbol": "render_invoice", "owner_sha256": "e" * 64},
         "parser_type": None,
         "original_cases": [{"kind": "positive", "evidence_id": proc_ev, "location": "/normalized_result/exit"},
                            {"kind": "malformed", "evidence_id": app_ev, "location": "/normalized_result/graph"}],
         "fixtures": [{"fixture_id": "fixture.positive", "case_kind": "positive", "authority": "protocol",
                       "evidence_ids": [proc_ev]},
                      {"fixture_id": "fixture.negative", "case_kind": "negative", "authority": "unit",
                       "evidence_ids": [app_ev]}],
         "verifier": {"verifier_id": "verifier.endpoint", "claim_id": "claim.endpoint",
                      "command": "cargo test endpoint", "authority": "protocol", "status": "fail",
                      "result_evidence_id": proc_ev,
                      "enumerated_obligation_ids": ["reviewed.invoice-export"],
                      "nondeterminism": {"mode": "total-order", "specification": "single request"}}},
        {"obligation_id": process["obligation_id"],
         "owner": {"module_path": "src/process.rs", "symbol": "run", "owner_sha256": "f" * 64},
         "parser_type": {"parser": "clap", "schema": "Cli", "domain_type": "Command"},
         "original_cases": [], "fixtures": [], "verifier": None},
        {"obligation_id": process["obligation_id"],
         "owner": {"module_path": "src/process2.rs", "symbol": "run", "owner_sha256": "f" * 64},
         "parser_type": None, "original_cases": [], "fixtures": [], "verifier": None},
        {"obligation_id": "orphan.binding",
         "owner": {"module_path": "src/orphan.rs", "symbol": "x", "owner_sha256": "0" * 64},
         "parser_type": None, "original_cases": [], "fixtures": [], "verifier": None}],
        "contradictions": [
            {"obligation_id": ipc["obligation_id"], "evidence_ids": [proc_ev, app_ev]},
            {"obligation_id": endpoint["obligation_id"], "evidence_ids": [proc_ev, "ev_" + "1" * 64]}]}
    request = {"evidence_bundle": bundle, "reviewed_obligations": reviewed, "manifest": manifest}
    write("reconstruction_ledger_input.json", {"reviewed_obligations": reviewed, "manifest": manifest})
    write("oracle_build_reconstruction_obligation_ledger.json",
          rea.call("build_reconstruction_obligation_ledger", request))
    write("oracle_build_reconstruction_obligation_ledger_empty.json",
          rea.call("build_reconstruction_obligation_ledger",
                   {"evidence_bundle": {"artifacts": [], "providers": [], "environments": [], "scenarios": [],
                                        "captures": [], "unknowns": [], "records": []},
                    "reviewed_obligations": [], "manifest": empty_manifest}, allow_error=True))
    rea.close()


if __name__ == "__main__":
    selected = sys.argv[1:] or ["verify", "investigation", "ledger"]
    if "verify" in selected:
        session_verify_pass()
    if "investigation" in selected:
        session_investigation()
    if "ledger" in selected:
        session_ledger()
