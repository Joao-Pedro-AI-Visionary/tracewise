use thiserror::Error;

#[derive(Debug, Error)]
pub enum JsError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("integrity: {0}")]
    Integrity(String),
    #[error("format: {0}")]
    Format(String),
    #[error("path: {0}")]
    Path(String),
    #[error("io: {0}")]
    Io(String),
    #[error("{0}")]
    Domain(String),
}

impl From<tracewise_domain::error::DomainError> for JsError {
    fn from(value: tracewise_domain::error::DomainError) -> Self {
        JsError::Domain(value.to_string())
    }
}

impl From<std::io::Error> for JsError {
    fn from(value: std::io::Error) -> Self {
        JsError::Io(value.to_string())
    }
}

impl From<serde_json::Error> for JsError {
    fn from(value: serde_json::Error) -> Self {
        JsError::Domain(value.to_string())
    }
}
