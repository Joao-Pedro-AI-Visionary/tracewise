// Regenerates the synthetic managed PE fixtures in this directory.
//
// The bytes come from REA's own test builder (src/dotnet/ManagedPe.fixture.ts at
// morluto/rea@0fa0b04, MIT), so the oracle and the Rust port see identical inputs.
//
//   node gen.mjs <REA checkout> <output directory>
//
// Requires Node >= 22.18 (native type stripping). The real assemblies
// (Microsoft.Extensions.Primitives, Microsoft.Win32.SystemEvents) are NuGet
// packages and are copied separately; see PROVENANCE.txt.
import { pathToFileURL } from "node:url";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const [rea, out] = process.argv.slice(2);
if (!rea || !out) throw new Error("usage: node gen.mjs <REA checkout> <output directory>");
const { buildManagedPeFixture, buildNativePeFixture } = await import(
  pathToFileURL(join(rea, "src/dotnet/ManagedPe.fixture.ts")).href
);
mkdirSync(out, { recursive: true });

const u16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b; };
const i32 = (v) => { const b = Buffer.alloc(4); b.writeInt32LE(v); return b; };
const fatHeader = (ilLength, { flags = 0x13, maxStack = 8, localSig = 0 } = {}) =>
  Buffer.concat([u16(0x3000 | flags), u16(maxStack), u32(ilLength), u32(localSig)]);
const withFat = (il, extra = [], flags = 0x13) => {
  const pad = Buffer.alloc((4 - ((12 + il.length) % 4)) % 4);
  return Buffer.concat([fatHeader(il.length, { flags }), il, ...(extra.length ? [pad, ...extra] : [])]);
};

// A body that touches most operand shapes.
const rich = Buffer.concat([
  Buffer.from([0x00, 0x02, 0x03, 0x1f, 0xf6]), // nop ldarg.0 ldarg.1 ldc.i4.s -10
  Buffer.from([0x20]), i32(0x01020304), // ldc.i4
  Buffer.from([0x21]), Buffer.from("0100000000000080", "hex"), // ldc.i8
  Buffer.from([0x22]), Buffer.from("cdcc8c3f", "hex"), // ldc.r4 1.1
  Buffer.from([0x23]), Buffer.from("9a9999999999f13f", "hex"), // ldc.r8 1.1
  Buffer.from([0xfe, 0x13]), // volatile.
  Buffer.from([0xfe, 0x12, 0x04]), // unaligned. 4
  Buffer.from([0x7b]), u32(0x04000001), // ldfld
  Buffer.from([0x28]), u32(0x06000001), // call MethodDef
  Buffer.from([0x6f]), u32(0x0a000001), // callvirt MemberRef
  Buffer.from([0x73]), u32(0x2b000001), // newobj MethodSpec
  Buffer.from([0x72]), u32(0x70000001), // ldstr
  Buffer.from([0xd0]), u32(0x04000001), // ldtoken field
  Buffer.from([0xd0]), u32(0x02000001), // ldtoken type
  Buffer.from([0xd0]), u32(0x06000001), // ldtoken method
  Buffer.from([0xd0]), u32(0x99000001), // ldtoken unknown
  Buffer.from([0x8c]), u32(0x01000001), // box
  Buffer.from([0x29]), u32(0x11000001), // calli
  Buffer.from([0x45]), u32(2), i32(0), i32(1), // switch (2 targets)
  Buffer.from([0x2b, 0x00]), // br.s +0
  Buffer.from([0x38]), i32(-5), // br -5
  Buffer.from([0xfe, 0x0c]), u16(2), // ldloc 2
  Buffer.from([0x0e, 0x01]), // ldarg.s 1
  Buffer.from([0xfe, 0x16]), u32(0x01000002), // constrained.
  Buffer.from([0x6f]), u32(0x0a000001),
  Buffer.from([0xfe, 0x06]), u32(0x06000001), // ldftn
  Buffer.from([0x26, 0x2a]), // pop ret
]);

// Fat body with a catch clause (small section) and a finally (fat section) over a longer method.
const ehIl = Buffer.concat([Buffer.alloc(8, 0x00), Buffer.from([0xdd]), i32(1), Buffer.from([0x26, 0xdc, 0x2a])]);
const smallSection = Buffer.concat([
  Buffer.from([0x01, 4 + 12, 0, 0]),
  u16(0), u16(0), Buffer.from([8]), u16(13), Buffer.from([2]), u32(0x01000001),
]);
const fatSection = Buffer.concat([
  Buffer.from([0x41, 4 + 24 & 0xff, 0, 0]),
  u32(2), u32(0), u32(8), u32(13), u32(2), u32(0),
]);
const fatSectionBad = Buffer.concat([
  Buffer.from([0x41, 4 + 24 & 0xff, 0, 0]),
  u32(0), u32(1), u32(500), u32(9), u32(3), u32(0x01000001),
]);
const filterSection = Buffer.concat([
  Buffer.from([0x41, 4 + 24 & 0xff, 0, 0]),
  u32(1), u32(0), u32(8), u32(13), u32(2), u32(8),
]);

const variants = {
  basic: {},
  pinvoke: { pinvoke: {} },
  pinvoke_cdecl: { pinvoke: { importName: "puts", moduleName: "libc.so.6", mappingFlags: 0x0252 } },
  pinvoke_bad_forwarded: { pinvoke: { memberForwardedRaw: 0x0000_00f1 } },
  pinvoke_null_forwarded: { pinvoke: { memberForwardedRaw: 0 } },
  r2r: { readyToRun: true },
  mixed: { cliFlags: 0 },
  x86_required: { cliFlags: 3 },
  prefer32: { cliFlags: 0x0002_0001 },
  strong_flags: { cliFlags: 0x19 },
  framework: { targetFramework: ".NETFramework,Version=v4.8", references: ["mscorlib", "System.Core"] },
  netstandard: { targetFramework: ".NETStandard,Version=v2.0" },
  unity: { references: ["UnityEngine.CoreModule", "mscorlib"] },
  noframework: { targetFramework: null },
  multi_ref: { references: ["System.Runtime", "System.Collections", "System.Runtime", "Åpple"] },
  modrows: { moduleRowCount: 2, assemblyRowCount: 2 },
  badsig: { corruptMetadataSignature: true },
  badref: { malformedAssemblyReferenceRows: [1] },
  badattr: { malformedCustomAttributeRows: [1] },
  attrtype_bad: { customAttributeTypeRaw: 0xfff0 },
  extends_bad: { extendsRaw: 0xfff9 },
  memberref_bad_parent: { memberRefParentRaw: 0 },
  memberref_far_parent: { memberRefParentRaw: 0xfff9 },
  validmask: { metadataValidMaskExtra: 1n << 50n },
  resource_ext: { resourceImplementationRaw: (1 << 2) | 1 },
  resource_badimpl: { resourceImplementationRaw: 0x00f3 },
  resource_big: { resourceData: Buffer.alloc(3000, 7) },
  mvid: { mvid: Buffer.from("00112233445566778899aabbccddeeff", "hex"), typeName: "Äpfel", typeNamespace: "" },
  names: { typeName: "Gen`1", typeNamespace: "A.B", fieldName: "<>c__DisplayClass", methodName: ".ctor" },
  il_rich: { ilBody: withFat(rich) },
  il_tiny: { ilBody: Buffer.from([0x0a, 0x02, 0x2a]) },
  il_unknown_op: { ilBody: Buffer.from([0x0a, 0x24, 0x2a]) },
  il_truncated_call: { ilBody: Buffer.from([0x0e, 0x00, 0x28, 0x01, 0x00]) },
  il_truncated_ldc8: { ilBody: Buffer.concat([Buffer.from([(10 << 2) | 2, 0x21]), Buffer.alloc(8)]).subarray(0, 11) },
  il_switch_overflow: { ilBody: Buffer.concat([Buffer.from([(8 << 2) | 2, 0x45]), u32(100), Buffer.from([0x2a, 0x2a])]) },
  il_prefix_only: { ilBody: Buffer.from([(2 << 2) | 2, 0xfe, 0x13]) },
  il_fe_truncated: { ilBody: Buffer.from([(1 << 2) | 2, 0xfe]) },
  il_empty: { ilBody: Buffer.from([2]) },
  eh_small: { ilBody: withFat(ehIl, [smallSection], 0x1b) },
  eh_fat: { ilBody: withFat(ehIl, [fatSection], 0x1b) },
  eh_bad: { ilBody: withFat(ehIl, [fatSectionBad], 0x1b) },
  eh_filter: { ilBody: withFat(ehIl, [filterSection], 0x1b) },
  eh_missing: { ilBody: withFat(ehIl, [], 0x1b) },
  fat_header_short: { ilBody: Buffer.from([0x03, 0x30, 0x08, 0x00]) },
  fat_small_dwords: { ilBody: Buffer.concat([u16(0x2013), u16(8), u32(1), u32(0)]) },
  sig_field_ptr: { fieldSignature: Buffer.from([0x06, 0x0f, 0x08]) },
  sig_field_trailing: { fieldSignature: Buffer.from([0x06, 0x08, 0x08]) },
  sig_field_generic: { fieldSignature: Buffer.from([0x06, 0x15, 0x12, 0x05, 0x01, 0x08]) },
  sig_field_empty_class: { fieldSignature: Buffer.from([0x06, 0x12, 0x09]) },
  sig_method_generic: { methodSignature: Buffer.from([0x30, 0x02, 0x01, 0x1e, 0x00, 0x13, 0x01]) },
  sig_method_szarray: { methodSignature: Buffer.from([0x20, 0x02, 0x0e, 0x1d, 0x08, 0x10, 0x11, 0x05]) },
  sig_method_vararg: { methodSignature: Buffer.from([0x25, 0x01, 0x01, 0x0e]) },
  sig_method_truncated: { methodSignature: Buffer.from([0x00, 0x03, 0x01, 0x08]) },
  sig_method_reserved: { methodSignature: Buffer.from([0x00, 0xff, 0x01]) },
  sig_method_trailing: { methodSignature: Buffer.from([0x00, 0x00, 0x01, 0x00]) },
};
for (const [name, options] of Object.entries(variants))
  writeFileSync(join(out, `${name}.dll`), buildManagedPeFixture(options));
writeFileSync(join(out, "native.dll"), buildNativePeFixture());

// Truncations of the basic image.
const basic = buildManagedPeFixture({});
writeFileSync(join(out, "trunc_pe.dll"), basic.subarray(0, 0x200));
writeFileSync(join(out, "trunc_meta.dll"), basic.subarray(0, 0x340));
writeFileSync(join(out, "dos_only.dll"), Buffer.concat([Buffer.from("MZ"), Buffer.alloc(62)]));
const badCli = Buffer.from(basic);
badCli.writeUInt32LE(0x10, 0x200); // CLI header size < 72
writeFileSync(join(out, "bad_cli_header.dll"), badCli);
const badMachine = Buffer.from(basic);
badMachine.writeUInt16LE(0x1234, 0x84);
writeFileSync(join(out, "bad_machine.dll"), badMachine);
const pe64 = Buffer.from(basic);
pe64.writeUInt16LE(0x8664, 0x84);
writeFileSync(join(out, "x64_header.dll"), pe64);
const arm = Buffer.from(basic);
arm.writeUInt16LE(0x01c4, 0x84);
writeFileSync(join(out, "arm_header.dll"), arm);
