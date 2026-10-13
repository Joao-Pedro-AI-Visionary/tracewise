//! Structured failures of the application analysis (REA `AnalysisInputError`,
//! `AnalysisUnsupportedTargetError`, `AnalysisAccessDeniedError`, `ArtifactOperationError`), so the
//! MCP layer can return REA's error envelope instead of a free-form message.

use crate::error::JsError;

/// `ArtifactReaderFailure` reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactFailure {
    Cancelled,
    Format,
    Integrity,
    Limit,
    Path,
    Unavailable,
    Io,
}

#[derive(Debug)]
pub enum AnalysisFailure {
    /// `AnalysisInputError` for one argument.
    Input {
        path: &'static str,
        message: String,
        expected: Option<Vec<String>>,
    },
    /// `AnalysisUnsupportedTargetError`.
    UnsupportedTarget {
        path: String,
        reason: String,
        remediation: String,
    },
    /// `AnalysisAccessDeniedError`.
    AccessDenied { path: String, system_code: String },
    /// `ArtifactOperationError`.
    Artifact { reason: ArtifactFailure },
    /// A feature of the REA pipeline this port does not reproduce (never a made-up result).
    Unsupported { what: String },
    /// Anything else.
    Other(JsError),
}

pub const CANCELLED_MESSAGE: &str = "JavaScript application analysis cancelled";

impl From<JsError> for AnalysisFailure {
    fn from(error: JsError) -> Self {
        match &error {
            JsError::Integrity(_) => AnalysisFailure::Artifact { reason: ArtifactFailure::Integrity },
            JsError::Format(_) => AnalysisFailure::Artifact { reason: ArtifactFailure::Format },
            JsError::Path(_) => AnalysisFailure::Artifact { reason: ArtifactFailure::Path },
            JsError::Io(message) if message == CANCELLED_MESSAGE => {
                AnalysisFailure::Artifact { reason: ArtifactFailure::Cancelled }
            }
            JsError::Io(_) => AnalysisFailure::Artifact { reason: ArtifactFailure::Io },
            _ => AnalysisFailure::Other(error),
        }
    }
}

impl From<std::io::Error> for AnalysisFailure {
    fn from(error: std::io::Error) -> Self {
        AnalysisFailure::from(JsError::from(error))
    }
}

impl From<AnalysisFailure> for JsError {
    fn from(failure: AnalysisFailure) -> Self {
        match failure {
            AnalysisFailure::Input { message, .. } => JsError::InvalidInput(message),
            AnalysisFailure::UnsupportedTarget { path, reason, .. } => {
                JsError::InvalidInput(format!("Unsupported target at {path}: {reason}"))
            }
            AnalysisFailure::AccessDenied { path, system_code } => {
                JsError::Io(format!("Access denied ({system_code}): {path}"))
            }
            AnalysisFailure::Artifact { reason } => match reason {
                ArtifactFailure::Integrity => JsError::Integrity("Artifact is invalid or has changed".into()),
                ArtifactFailure::Format => JsError::Format("Artifact is invalid".into()),
                ArtifactFailure::Path => JsError::Path("Artifact path conflict".into()),
                ArtifactFailure::Cancelled => JsError::Io(CANCELLED_MESSAGE.into()),
                _ => JsError::Io("Artifact could not be read".into()),
            },
            AnalysisFailure::Unsupported { what } => JsError::InvalidInput(what),
            AnalysisFailure::Other(error) => error,
        }
    }
}

impl std::fmt::Display for AnalysisFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error: JsError = match self {
            AnalysisFailure::Input { message, .. } => JsError::InvalidInput(message.clone()),
            AnalysisFailure::UnsupportedTarget { path, reason, .. } => {
                JsError::InvalidInput(format!("Unsupported target at {path}: {reason}"))
            }
            AnalysisFailure::AccessDenied { path, system_code } => {
                JsError::Io(format!("Access denied ({system_code}): {path}"))
            }
            AnalysisFailure::Artifact { reason } => JsError::Io(format!("artifact operation failed: {reason:?}")),
            AnalysisFailure::Unsupported { what } => JsError::InvalidInput(what.clone()),
            AnalysisFailure::Other(error) => return write!(f, "{error}"),
        };
        write!(f, "{error}")
    }
}

impl std::error::Error for AnalysisFailure {}
