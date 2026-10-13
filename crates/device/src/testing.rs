//! Shared guard for tests that need the original REA or an external tool.
//!
//! A test that cannot find its oracle must never turn green by returning early
//! when the environment promises one. With `TRACEWISE_REQUIRE_ORACLE=1` (set by the
//! development environment script) a missing prerequisite panics and says what is
//! missing; without it the test prints the reason and skips, so contributors
//! without a local REA can still run the rest of the suite.

use std::path::Path;

pub const REQUIRE_ENV: &str = "TRACEWISE_REQUIRE_ORACLE";

/// The listed paths that do not exist.
pub fn missing_paths<'a>(needed: &[&'a str]) -> Vec<&'a str> {
    needed.iter().copied().filter(|path| !Path::new(path).exists()).collect()
}

/// Whether the oracle is mandatory in this environment.
pub fn oracle_required() -> bool {
    std::env::var(REQUIRE_ENV).map(|value| value == "1").unwrap_or(false)
}

/// Decide whether a test may run. `Ok` prerequisites return `true`; missing
/// ones panic when the oracle is required and otherwise print a skip notice
/// and return `false`.
pub fn require_or_skip(test: &str, missing: &[&str]) -> bool {
    if missing.is_empty() {
        return true;
    }
    let reason = format!("{test}: missing prerequisites {missing:?} (needs Node 22 and a compiled REA checkout at the listed paths; set {REQUIRE_ENV}=1 to turn this skip into a failure)");
    assert!(!oracle_required(), "{REQUIRE_ENV}=1 but {reason}");
    eprintln!("SKIP: {reason}");
    false
}

/// The REA MCP oracle: node plus the compiled entry point.
pub fn rea_oracle_missing() -> Vec<&'static str> {
    missing_paths(&["/tmp/node-v22.20.0-linux-x64/bin/node", "/workspace/rea-map/src/scripts/rea.mjs"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_prerequisites_skip_or_panic_by_environment() {
        // One test owns the variable: both behaviours are checked in sequence.
        std::env::set_var(REQUIRE_ENV, "0");
        assert!(!require_or_skip("t", &["/definitely/not/here"]));
        std::env::set_var(REQUIRE_ENV, "1");
        let outcome = std::panic::catch_unwind(|| require_or_skip("t", &["/definitely/not/here"]));
        let message = *outcome.expect_err("must panic when the oracle is required").downcast::<String>().unwrap();
        assert!(message.contains("TRACEWISE_REQUIRE_ORACLE=1") && message.contains("/definitely/not/here"), "{message}");
        std::env::remove_var(REQUIRE_ENV);
    }

    #[test]
    fn nothing_missing_runs() {
        assert!(require_or_skip("t", &[]));
        assert_eq!(missing_paths(&["/definitely/not/here"]), vec!["/definitely/not/here"]);
    }
}
