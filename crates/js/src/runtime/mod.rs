//! Passive Node/Electron V8 Inspector observation and static/runtime reconciliation.

pub mod inspector;
mod location;
mod reconcile;

pub use reconcile::reconcile_javascript_runtime;
