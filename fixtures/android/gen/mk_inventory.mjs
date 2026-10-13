import { createEvidence } from "/workspace/rea-map/src/dist/domain/evidence.js";
import { artifactIdForContent, occurrenceIdForLocation, artifactGraphDigest, artifactManifestId } from "/workspace/rea-map/src/dist/domain/artifactIdentity.js";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const real = JSON.parse(readFileSync("/tmp/tracewise-oracle/apk_inspect_artifact.json", "utf8"));
const sha = (text) => createHash("sha256").update(text).digest("hex");
const provider = real.provider;

/** Re-wrap an inventory result in fresh, correctly identified outer and inner Evidence. */
const wrap = (inventory, { rootFormat = "apk", subjectPath = "/targets/Synthetic.apk", architecture = null } = {}) => {
  const rootSha = inventory.manifest.root_sha256;
  const target = { path: subjectPath, sha256: rootSha, format: rootFormat, ...(architecture ? { architecture } : {}) };
  const innerReal = real.normalized_result.substeps[0].evidence;
  const inner = createEvidence(target, { id: innerReal.provider.id, name: innerReal.provider.name, version: innerReal.provider.version }, {
    predicateType: innerReal.predicate_type,
    operation: "inventory_artifact",
    parameters: innerReal.parameters,
    result: inventory,
    rawResult: null,
    confidence: innerReal.confidence,
    authority: innerReal.authority,
    environment: null,
    limitations: innerReal.limitations,
    locations: [],
    evidenceLinks: [],
  });
  const result = JSON.parse(JSON.stringify(real.normalized_result));
  result.subject = { ...result.subject, manifest_id: inventory.manifest.manifest_id, root_artifact_id: inventory.manifest.root_artifact_id, root_sha256: rootSha, root_format: inventory.manifest.root_format };
  result.substeps[0].evidence_id = inner.evidence_id;
  result.substeps[0].evidence = inner;
  result.evidence_links = [inner.evidence_id];
  return createEvidence(target, { id: real.provider.id, name: real.provider.name, version: real.provider.version }, {
    predicateType: real.predicate_type,
    operation: "inspect_artifact",
    parameters: real.parameters,
    result,
    rawResult: null,
    confidence: real.confidence,
    authority: real.authority,
    environment: null,
    limitations: real.limitations,
    locations: [],
    evidenceLinks: [inner.evidence_id],
  });
};

const out = { real };

// 1. Partial: drop occurrences so the counts no longer match the manifest.
{
  const inventory = JSON.parse(JSON.stringify(real.normalized_result.substeps[0].evidence.normalized_result));
  inventory.occurrences = inventory.occurrences.slice(0, inventory.occurrences.length - 40);
  inventory.edges = inventory.edges.slice(0, inventory.edges.length - 40);
  out.partial = wrap(inventory, { subjectPath: real.subject.local_path });
}

// 2. Synthetic APK inventories.
const synthetic = (entries, { rootFormat = "apk", name = "Synthetic", complete = false, badFormat = false } = {}) => {
  const rootSha = sha(`root-${name}`);
  const rootId = artifactIdForContent(rootSha);
  const nodes = new Map();
  const occurrences = [];
  const rootOccurrence = occurrenceIdForLocation({ rootArtifactId: rootId, logicalPath: ".", entryKind: "file" });
  nodes.set(rootId, { artifact_id: rootId, format: "zip", sha256: rootSha, size: 1000, media_type: null, architecture: null, content_state: "materialized", limitations: [] });
  occurrences.push({
    occurrence_id: rootOccurrence, artifact_id: rootId, parent_occurrence_id: null, logical_path: ".", entry_kind: "file",
    artifact_kind: "container", artifact_format: rootFormat, declared_size: 1000, compressed_size: null, executable: false,
    encrypted: false, hash_status: "verified", source_location: null, limitations: [],
  });
  entries.forEach(([path, format, kind], index) => {
    const content = sha(`${name}-${index}-${path}`);
    const id = artifactIdForContent(content);
    nodes.set(id, { artifact_id: id, format: badFormat && format === "javascript-bundle" ? "javascript" : format === "javascript-bundle" ? "file" : format === "elf" ? "elf" : "unknown", sha256: content, size: 10 + index, media_type: null, architecture: null, content_state: "embedded", limitations: [] });
    occurrences.push({
      occurrence_id: occurrenceIdForLocation({ rootArtifactId: rootId, logicalPath: path, entryKind: "file" }), artifact_id: id,
      parent_occurrence_id: rootOccurrence, logical_path: path, entry_kind: "file", artifact_kind: kind ?? "resource",
      artifact_format: format, declared_size: 10 + index, compressed_size: null, executable: false, encrypted: false,
      hash_status: "not-hashed", source_location: null, limitations: [],
    });
  });
  const sortedNodes = [...nodes.values()].sort((a, b) => (a.artifact_id < b.artifact_id ? -1 : a.artifact_id > b.artifact_id ? 1 : 0));
  const sortedOccurrences = [...occurrences].sort((a, b) => (a.logical_path < b.logical_path ? -1 : a.logical_path > b.logical_path ? 1 : 0));
  const graph = artifactGraphDigest({ nodes: sortedNodes, occurrences: sortedOccurrences, edges: [], contradictions: [] });
  const inventory = {
    manifest: complete ? {
      manifest_id: artifactManifestId(rootId, graph), root_artifact_id: rootId, root_sha256: rootSha, root_format: rootFormat,
      graph_sha256: graph, node_count: sortedNodes.length, occurrence_count: sortedOccurrences.length, edge_count: 0,
    } : {
      manifest_id: "agm_" + sha(`manifest-${name}`), root_artifact_id: rootId, root_sha256: rootSha, root_format: rootFormat,
      graph_sha256: sha(`graph-${name}`), node_count: nodes.size + (complete ? 0 : 5), occurrence_count: occurrences.length + (complete ? 0 : 5), edge_count: 0,
    },
    nodes: complete ? sortedNodes : [...nodes.values()], occurrences: complete ? sortedOccurrences : occurrences, edges: [], provenance: [], integrity_contradictions: [], limitations: ["synthetic page"],
  };
  return wrap(inventory, { rootFormat, subjectPath: `/targets/${name}.apk` });
};

out.conventions = synthetic([
  ["AndroidManifest.xml", "unknown"],
  ["classes.dex", "unknown"],
  ["classes2.DEX", "unknown"],
  ["com/example/Main.class", "unknown"],
  ["resources.arsc", "unknown"],
  ["assets/AndroidManifest.xml", "unknown"],
  ["lib/arm64-v8a/libnative.so", "elf", "dynamic-library"],
  ["lib/arm64-v8a/libreactnativejni.so", "elf", "dynamic-library"],
  ["lib/x86_64/libflutter.so", "elf", "dynamic-library"],
  ["lib/armeabi-v7a/libunity.so", "elf", "dynamic-library"],
  ["lib/arm64-v8a/libhermes.so", "elf", "dynamic-library"],
  ["lib/arm64-v8a/libcommunity.so", "elf", "dynamic-library"],
  ["lib/arm64-v8a/libreactivity.so", "elf", "dynamic-library"],
  ["assets/index.android.bundle", "javascript-bundle", "javascript"],
  ["META-INF/MANIFEST.MF", "unknown"],
  ["META-INF/CERT.RSA", "unknown"],
  ["META-INF/CERT.SF", "unknown"],
  ["META-INF/services/x.MF", "unknown"],
  ["res/raw/Ünicode ✓.dex", "unknown"],
], { name: "Conventions" });

out.badformat = synthetic([["assets/index.android.bundle", "javascript-bundle", "javascript"]], { name: "BadFormat", badFormat: true });
out.nomanifest = synthetic([["classes.dex", "unknown"], ["lib/arm64-v8a/libfoo.so", "elf", "dynamic-library"]], { name: "NoManifest" });
out.notapk = synthetic([["classes.dex", "unknown"]], { rootFormat: "zip", name: "NotApk" });
out.complete_synthetic = synthetic([["AndroidManifest.xml", "unknown"], ["classes.dex", "unknown"]], { name: "CompleteSynthetic", complete: true });

// 3. Bridge-candidate budget: a few hundred managed x native components exceed 2 MiB.
{
  const entries = [];
  for (let i = 0; i < 260; i += 1) entries.push([`dex/part-${String(i).padStart(4, "0")}/classes${i}.dex`, "unknown"]);
  for (let i = 0; i < 260; i += 1) entries.push([`lib/arm64-v8a/libgenerated-library-${String(i).padStart(4, "0")}.so`, "elf", "dynamic-library"]);
  out.big_bridge = synthetic(entries, { name: "BigBridge" });
}

// 4. Wrong operation / tampering.
out.tampered = { ...real, limitations: ["tampered"] };

writeFileSync("/tmp/tracewise-oracle/graph_inputs.json", JSON.stringify(out));
console.log(Object.keys(out).join(","));
