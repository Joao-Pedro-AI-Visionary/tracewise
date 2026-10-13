//! Execution-free ECMA-335 / PE-CLI static inspection (port of REA `src/dotnet`).
//!
//! The three public inspectors take the raw bytes of a PE image and return the
//! `normalized_result` object REA records as Evidence. Nothing is loaded or
//! executed. Behaviour (field values, budgets, coverage issues, exact error
//! strings that leak into results) follows REA @0fa0b04.

pub mod artifact;
pub mod budget;
pub mod cil;
pub mod common;
pub mod graph;
pub mod heaps;
pub mod inventory;
pub mod layout;
pub mod member_rows;
pub mod members;
pub mod native;
mod opcodes;
pub mod pe;
pub mod target;
pub mod workflows;

pub use artifact::inspect_managed_artifact_bytes;
pub use common::{Failure, Issue};
pub use members::inspect_managed_members_bytes;
pub use native::inspect_managed_native_boundaries_bytes;

/// The artifact identity REA passes to every inspector.
#[derive(Debug, Clone)]
pub struct ManagedTarget {
    pub path: String,
    pub sha256: String,
}
