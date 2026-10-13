//! Audited releases, resource limits and `--version` admission
//! (port of REA `FirmwareRelease.ts` and `FirmwareVersion.ts`).

use std::sync::OnceLock;

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Binwalk,
    Unblob,
}

impl Engine {
    pub fn id(self) -> &'static str {
        match self {
            Engine::Binwalk => "binwalk",
            Engine::Unblob => "unblob",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Engine::Binwalk => "Binwalk",
            Engine::Unblob => "Unblob",
        }
    }

    /// Audited upstream release the report parser is verified against.
    pub fn verified_version(self) -> &'static str {
        match self {
            Engine::Binwalk => "3.1.0",
            Engine::Unblob => "26.6.4",
        }
    }

    pub fn command_variable(self) -> &'static str {
        match self {
            Engine::Binwalk => "REA_BINWALK_COMMAND",
            Engine::Unblob => "REA_UNBLOB_COMMAND",
        }
    }
}

pub const INPUT_BYTES: u64 = 128 * 1024 * 1024;
pub const REPORT_BYTES: usize = 8 * 1024 * 1024;
pub const DIAGNOSTIC_BYTES: usize = 8 * 1024 * 1024;
pub const ADDRESS_SPACE_BYTES: u64 = 1024 * 1024 * 1024;
pub const TIMEOUT_MS: u64 = 120_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Release {
    major: u64,
    minor: u64,
    token: String,
}

fn parse_token(token: &str) -> Option<(Release, String)> {
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    let pattern = TOKEN
        .get_or_init(|| Regex::new(r"^([0-9]+)\.([0-9]+)\.([0-9]+)([-+][0-9A-Za-z.-]+)?$").expect("release pattern"));
    let c = pattern.captures(token)?;
    let safe = |s: &str| s.parse::<u64>().ok().filter(|n| *n <= 9_007_199_254_740_991);
    let (major, minor, _patch) = (safe(&c[1])?, safe(&c[2])?, safe(&c[3])?);
    let suffix = c.get(4).map(|m| m.as_str().to_string()).unwrap_or_default();
    Some((Release { major, minor, token: token.to_string() }, suffix))
}

fn verified(engine: Engine) -> Release {
    parse_token(engine.verified_version()).expect("verified release").0
}

/// `Binwalk 3.1.x`.
pub fn release_line(engine: Engine) -> String {
    let v = verified(engine);
    format!("{} {}.{}.x", engine.label(), v.major, v.minor)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Verified { version: String },
    Compatible { version: String, limitation: String },
    Unsupported { message: String },
    Unresolved { message: String },
}

fn version_token(engine: Engine, banner: &str) -> Option<String> {
    match engine {
        Engine::Binwalk => banner.strip_prefix("binwalk ").map(str::to_string),
        Engine::Unblob => Some(banner.to_string()),
    }
}

/// `admitFirmwareVersion`.
pub fn admit_version(engine: Engine, banner: &str) -> Admission {
    let token = version_token(engine, banner);
    let parsed = token.as_deref().and_then(parse_token);
    let ver = verified(engine);
    let accepted = format!("accepted releases are {} (verified with {})", release_line(engine), ver.token);
    let Some((release, _suffix)) = parsed else {
        let shown = if banner.is_empty() { "missing" } else { banner };
        return Admission::Unresolved { message: format!("Unsupported tool version {shown}; {accepted}.") };
    };
    if release.major != ver.major || release.minor != ver.minor {
        return Admission::Unsupported { message: format!("Unsupported tool version {banner}; {accepted}.") };
    }
    if release.token == ver.token {
        return Admission::Verified { version: release.token };
    }
    let line = format!("{}.{}.x", ver.major, ver.minor);
    Admission::Compatible {
        version: release.token.clone(),
        limitation: format!(
            "This session uses {} {}. The report parser is verified against {}; other {line} builds are accepted and the observed version is reported.",
            engine.label(),
            release.token,
            ver.token
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_like_rea() {
        assert_eq!(admit_version(Engine::Binwalk, "binwalk 3.1.0"), Admission::Verified { version: "3.1.0".into() });
        assert!(matches!(admit_version(Engine::Binwalk, "binwalk 3.1.7"), Admission::Compatible { .. }));
        assert!(matches!(admit_version(Engine::Binwalk, "binwalk 3.2.0"), Admission::Unsupported { .. }));
        assert!(matches!(admit_version(Engine::Binwalk, "3.1.0"), Admission::Unresolved { .. }));
        assert!(matches!(admit_version(Engine::Unblob, ""), Admission::Unresolved { .. }));
        assert_eq!(release_line(Engine::Unblob), "Unblob 26.6.x");
    }
}
