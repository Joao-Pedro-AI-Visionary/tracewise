// Replays captured Apple tool output through the ORIGINAL REA native provider and prints the result
// (the oracle for the pure-Rust inspect_macho / list_architectures / demangle_swift / inspect_plist
// / inspect_signature parsers).
//
// usage: node replay_rea.mjs <scenario.json>
// scenario: { operation, parameters?, target?, outputs: { "<tool>[:<first-arg>]": "text" , ... },
//             exitCodes?: { "<tool>[:<first-arg>]": n } }

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REA = "/workspace/rea-map/src/dist";
const { NativeMacOSProvider } = await import(`${REA}/native/NativeMacOSProvider.js`);

const scenario = JSON.parse(readFileSync(process.argv[2], "utf8"));

const capture = (tool, args, output, exitCode) => {
  const stderr =
    tool === "codesign" && !args.includes("-r-") && !args.includes("--entitlements");
  return {
    tool,
    executable: `/usr/bin/${tool}`,
    executableSha256: "a".repeat(64),
    toolVersion: null,
    versionReason: "fixture",
    arguments: [...args],
    stdout: stderr ? "" : output,
    stderr: stderr ? output : "",
    stdoutBytes: Buffer.byteLength(stderr ? "" : output),
    stderrBytes: Buffer.byteLength(stderr ? output : ""),
    exitCode,
    signal: null,
  };
};

const runner = {
  async run(tool, args, options) {
    const variant = args.includes("json") ? "json" : args.includes("xml1") ? "xml1" : undefined;
    const key = variant === undefined ? `${tool}:${args[0] ?? ""}` : `${tool}:${variant}`;
    const output = scenario.outputs[key] ?? scenario.outputs[`${tool}:${args[0] ?? ""}`] ?? scenario.outputs[tool];
    if (output === undefined) throw new Error(`no captured output for ${key}`);
    const exitCode = scenario.exitCodes?.[key] ?? scenario.exitCodes?.[tool] ?? 0;
    const result = capture(tool, args, output, exitCode);
    if (scenario.stderr?.[key] !== undefined) {
      result.stderr = scenario.stderr[key];
      result.stderrBytes = Buffer.byteLength(result.stderr);
    }
    if (exitCode !== 0 && options?.acceptNonZero !== true) {
      const { NativeCommandFailure } = await import(`${REA}/native/CommandRunner.js`);
      return { ok: false, error: new NativeCommandFailure(tool, "nonzero-exit", exitCode) };
    }
    return { ok: true, value: result };
  },
};

const target = {
  path: scenario.target?.path ?? "/private/fixture",
  sha256: "0".repeat(64),
  kind: "executable",
  format: scenario.target?.format ?? "mach-o",
  architecture: scenario.target?.architecture ?? "arm64",
  availableArchitectures: scenario.target?.availableArchitectures ?? ["arm64"],
  ...(scenario.target?.sourcePath ? { sourcePath: scenario.target.sourcePath } : {}),
  ...(scenario.target?.bundleInfoPlist ? { bundleInfoPlist: scenario.target.bundleInfoPlist } : {}),
};

const provider = new NativeMacOSProvider({}, runner, "darwin");
const client = provider.createClient(target);
const execution = await client.execute(scenario.operation, scenario.parameters ?? {});
await client.close();
const output = execution.ok
  ? { ok: true, result: execution.value.result, limitations: execution.value.limitations, locations: execution.value.locations }
  : { ok: false, error: { tag: execution.error._tag, message: execution.error.message, reason: execution.error.reason } };
writeFileSync(process.argv[3] ?? "/dev/stdout", JSON.stringify(output, null, 1));
