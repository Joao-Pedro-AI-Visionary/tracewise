// Run REA's compiled `trace_native_ui_action` workflow against a scripted analysis
// port. usage: node oracle_trace.mjs <scenarios.json> <out.json>
//
// A scenario is { name, input, responses }. `responses[operation]` is a list of
// rules tried in order: { match?: {param: value}, ok?: result, provider?, subject?,
// profile?, error?: {kind, ...} }. The first rule whose `match` equals the call
// parameters answers; a call nobody answers throws, like REA's own test fake.
// The output records the final Result (errors projected with REA's own
// projectAnalysisError) and every port call in order.
import { readFileSync, writeFileSync } from "node:fs";

const root = "/workspace/rea-map/src/dist";
const { EnhancedTools } = await import(`${root}/application/EnhancedTools.js`);
const { createAnalysisExecution } = await import(`${root}/application/AnalysisProvider.js`);
const errors = await import(`${root}/domain/analysisErrorCore.js`);
const { err, ok } = await import(`${root}/domain/result.js`);
const { projectAnalysisError } = await import(`${root}/domain/analysisErrorProjection.js`);

const makeError = (spec, operation) => {
  switch (spec.kind) {
    case "capability":
      return new errors.AnalysisCapabilityUnavailableError(spec.provider ?? "fixture", spec.operation ?? operation, spec.reason ?? "unavailable");
    case "cancelled":
      return new errors.AnalysisCancelledError(spec.operation ?? operation);
    case "output":
      return new errors.AnalysisOutputError(spec.operation ?? operation, spec.reason ?? "bad output");
    case "protocol":
      return new errors.AnalysisProtocolError(spec.message ?? "protocol");
    case "unsupported":
      return new errors.AnalysisUnsupportedTargetError(spec.operation ?? operation, spec.path ?? "/x", spec.reason ?? "unsupported");
    case "timeout":
      return new errors.AnalysisTimeoutError(spec.operation ?? operation, spec.timeout_ms ?? 1000);
    default:
      throw new Error(`unknown error kind ${spec.kind}`);
  }
};

const matches = (rule, parameters) =>
  rule.match === undefined || Object.entries(rule.match).every(([key, value]) => JSON.stringify(parameters[key]) === JSON.stringify(value));

const run = async (scenario) => {
  const calls = [];
  const analysis = {
    execute: async (operation, parameters) => {
      calls.push({ operation, parameters });
      const rule = (scenario.responses[operation] ?? []).find((candidate) => matches(candidate, parameters));
      if (rule === undefined) throw new Error(`Unexpected provider operation: ${operation} ${JSON.stringify(parameters)}`);
      if (rule.error !== undefined) return err(makeError(rule.error, operation));
      const provider = rule.provider ?? { id: "fixture", name: "Fixture", version: "1" };
      const options = {};
      if (rule.subject !== undefined && rule.subject !== null) options.subject = rule.subject;
      return ok(createAnalysisExecution(rule.ok, provider, options));
    },
  };
  let outcome;
  try {
    const result = await new EnhancedTools(analysis).execute("trace_native_ui_action", scenario.input);
    outcome = result.ok ? { ok: true, value: result.value } : { ok: false, error: projectAnalysisError(result.error) };
  } catch (cause) {
    outcome = { ok: false, thrown: String(cause instanceof Error ? cause.message : cause) };
  }
  return { name: scenario.name, ...outcome, calls };
};

const scenarios = JSON.parse(readFileSync(process.argv[2], "utf8"));
const results = [];
for (const scenario of scenarios) results.push(await run(scenario));
writeFileSync(process.argv[3], JSON.stringify(results));
