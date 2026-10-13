# Local validation helpers (not run by cargo test)

- tw_session.py: runs tool calls in one tracewise MCP session (target/debug/tracewise mcp).
- oracle_session.py: the same against the original REA server (the oracle).
- lief_check.py: compares inspect_macho with LIEF (an independent Mach-O implementation) on a real binary:
  segments, sections, dependencies, UUID, entry point, imports, exports.
  Setup: python3 -m venv v && v/bin/pip install lief==1.0.0 ; v/bin/python lief_check.py <macho>.
- For signatures the independent reference is rcodesign (cargo install apple-codesign --locked --version 0.29.0):
  compare identifier, CDHash and signed state with rcodesign print-signature-info.

Results of the runs on the development machine are listed in docs/progress/native_static.md.

Status: lief_check.py and rcodesign_check.py are manual cross-checks over Mach-O files that exist on the
author machine (not versioned); their results are not CI evidence. rcodesign_check.py compares signed state,
identifier, CDHash and the hardened-runtime flag. REA_NODE selects the node binary of oracle_session.py.
