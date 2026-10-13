//! `demangle_swift` (REA `parsers/demangle.ts`): Swift symbol demangling without the
//! `swift-demangle` tool. The demangler is the Swift project's own C++ implementation, built
//! into the `symbolic-demangle` crate.

use serde_json::{json, Value};
use symbolic_common::{Language, Name, NameMangling};
use symbolic_demangle::{Demangle, DemangleOptions};

use crate::macho_tools::native_provenance;

pub const OPERATION: &str = "demangle_swift";

/// Demangled text of one symbol, or the input unchanged when it is not a mangled Swift name.
pub fn demangle_symbol(symbol: &str) -> String {
    let name = Name::new(symbol, NameMangling::Mangled, Language::Swift);
    name.demangle(DemangleOptions::complete()).unwrap_or_else(|| symbol.to_string())
}

pub fn demangle_symbols(symbols: &[String], alias: &str) -> Value {
    let rows: Vec<Value> = symbols
        .iter()
        .map(|input| {
            let output = demangle_symbol(input);
            let status = if &output == input {
                if input.starts_with("$s") || input.starts_with("_$s") {
                    "invalid"
                } else {
                    "unchanged"
                }
            } else {
                "demangled"
            };
            json!({"input": input, "output": output, "status": status})
        })
        .collect();
    json!({
        "symbols": rows,
        "provenance": [native_provenance(OPERATION, alias)],
        "limitations": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_captured_swift_demangle_output() {
        // tests/fixtures/native-macos/demangle.txt of REA: `Test.foo() -> ()` and `plain_symbol`.
        let result = demangle_symbols(&["$s4Test3fooyyF".to_string(), "plain_symbol".to_string()], "$ARTIFACT");
        assert_eq!(result["symbols"][0]["output"], "Test.foo() -> ()");
        assert_eq!(result["symbols"][0]["status"], "demangled");
        assert_eq!(result["symbols"][1]["output"], "plain_symbol");
        assert_eq!(result["symbols"][1]["status"], "unchanged");
    }

    #[test]
    fn a_swift_looking_name_that_does_not_demangle_is_invalid() {
        let result = demangle_symbols(&["$sbogus".to_string(), "_$sbogus".to_string()], "$ARTIFACT");
        assert_eq!(result["symbols"][0]["status"], "invalid");
        assert_eq!(result["symbols"][1]["status"], "invalid");
    }
}
