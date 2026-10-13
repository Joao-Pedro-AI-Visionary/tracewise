//! Inputs where REA's Babel parser *recovers* from an error (so the static layer still runs and
//! reports `parse_status: "partial"` with `parse_error_count > 0`) but the Rust AST layer
//! (`jsgraph::ast::parse_babel`, owned by the AST track) either fails the parse or does not count
//! the error. The static analysis itself is identical on these; only the three parser-derived
//! fields can differ. File names start with `astgap_` so the test treats them specially.

pub const PREFIX: &str = "astgap_";

pub fn snippets() -> Vec<(String, String)> {
    let sources: &[(&str, &str)] = &[
        // Babel: invalid escape in an untagged template is recoverable (REA: Electron options test).
        ("template_escape_window", "new BrowserWindow({ webPreferences: { sandbox: `\\unicode` } });"),
        (
            "template_escape_paths",
            "const options = { preload: `\\unicode` };\nnew BrowserWindow({ webPreferences: { preload: `\\unicode` } });\nutilityProcess.fork(`\\unicode`);\n",
        ),
        // Babel: private name outside a class body is recoverable.
        ("private_name", "if (#p in obj) {}\nipcMain.on('c', (e) => { if (#q in e.senderFrame) {} });\n"),
        // Babel: `export { d }` of an undeclared binding is recoverable.
        ("undefined_export", "import a from './a.js';\nexport { d };\n"),
        // Babel: import() with a spread or no argument is recoverable.
        ("import_arguments", "import(...a);\nimport();\nrequire('./after.js');\n"),
        // Babel: redeclaration is recoverable (REA: source map test).
        ("redeclaration", "let value; let value;\n//# sourceMappingURL=recovered.map"),
    ];
    sources
        .iter()
        .map(|(name, source)| (format!("{PREFIX}{name}.js"), (*source).to_string()))
        .collect()
}
