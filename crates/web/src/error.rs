use thiserror::Error;

#[derive(Debug, Error)]
pub enum WebError {
    #[error("Analysis input is invalid: {message}")]
    Input {
        operation: String,
        path: Vec<String>,
        reason: String,
        message: String,
    },

    #[error("Capability unavailable: {user_message}")]
    CapabilityUnavailable {
        capability: String,
        operation: String,
        reason: String,
        user_message: String,
    },

    #[error("Browser observation {operation} failed: {reason}")]
    BrowserObservation {
        operation: String,
        reason: String,
        code: String,
        user_message: String,
    },

    #[error("CDP command rejected during {operation}: {code} {message}")]
    CdpCommandRejected {
        operation: String,
        code: i64,
        message: String,
    },

    #[error("Format error: {0}")]
    Format(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Domain error: {0}")]
    Domain(#[from] tracewise_domain::error::DomainError),
}
