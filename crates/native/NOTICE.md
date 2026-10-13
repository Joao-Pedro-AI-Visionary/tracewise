# Third-party material used by tracewise-native

Dependencies (see Cargo.lock for exact versions):

| Component | Use | License |
| --- | --- | --- |
| cms 0.2.3, x509-cert 0.2.5, der 0.7.10, spki, const-oid, flagset, pem-rfc7468, base64ct, zeroize (RustCrypto Formats) | CMS SignedData and X.509 certificates of the code signature (inspect_signature); https://github.com/RustCrypto/formats | Apache-2.0 OR MIT |
| sha1 0.10.7 (RustCrypto Hashes) | code directory hash (inspect_signature); https://github.com/RustCrypto/hashes | Apache-2.0 OR MIT |
| symbolic-demangle / symbolic-common 12.18.3 (Sentry) | Swift demangling (demangle_swift); bundles the Swift project demangler | MIT; Apache-2.0 with Runtime Library Exception (Swift) |
| evmole 0.9.3 (Maxim Andreev) | EVM selector/argument/mutability inference (inspect_evm_interface) | MIT |
| iced-x86 1.21.0 | x86 instruction decoding for PLT discovery (inspect_binary_layout) | MIT |
| icu_collator 2 (Unicode) | ICU root collation, equal to JavaScript localeCompare (inspect_macho export order) | Unicode-3.0 |
| roxmltree, regex, base64, chrono, indexmap, unicode-normalization | parsing helpers | MIT / Apache-2.0 |

Derived knowledge and test material:

- The Mach-O/otool/dyld_info/plist/IPA behaviours are ports of REA (morluto/rea, MIT); see the
  repository THIRD_PARTY_NOTICES.md.
- The compiled asset catalog layout (BOM store, CARHEADER, KEYFORMAT, FACETKEYS, RENDITIONS, CSI) follows
  the community reverse engineering in skytoup/car-parser (MIT, Copyright (c) 2026 skytoup) and
  bartoszj/acextract (MIT, Copyright (c) 2014 Bartosz Janda). No source was copied.
- fixtures/native_static/assets/vendor/assets_mac.car and assets_tv.car are test catalogs of
  bartoszj/acextract (MIT; license text in LICENSE-acextract).
- ELF enumerations in crates/native/data/elf_enums.json are dumped from pyelftools 0.33 (public domain).

Test tooling that is not linked or distributed:

- `rcodesign` / apple-codesign 0.29.0 (Gregory Szorc, MPL-2.0, https://github.com/indygreg/apple-platform-rs)
  signed the fixtures in `fixtures/native_static/codesign/` and served as a manual cross-check. It was the signature
  parser of earlier commits of this branch and was replaced by `sigparse.rs`, which reads the documented blob
  layouts directly; no source of apple-codesign was copied. Its transitive MPL-2.0 crates
  (cryptographic-message-syntax, x509-certificate, apple-xar, apple-bundles, apple-flat-package, option-ext), the
  CDLA-Permissive webpki-roots and ring are therefore no longer in Cargo.lock.
- pwntools 4.15.0 / pyelftools 0.33 / unicorn 2.1.2 (the REA oracle environment), LIEF 1.0.0 and the Python
  `plistlib` (plutil emulation) are used only to produce goldens or manual checks.
