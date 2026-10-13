// `NativeError` mirrors REA's typed errors (several strings and a JSON value per variant); results are
// returned once per tool call, so boxing them would only add churn.
#![allow(clippy::result_large_err)]

//! Native static analysis for the tracewise port (Phase 4, track native_static).
//!
//! Pure Rust ports of the REA native/artifact tools. The crate returns the
//! `normalized_result` values plus limitations and locations; the server track
//! wraps them into Evidence.

pub mod apple_app;
pub mod asset_catalog;
pub mod bounded_read;
pub mod bundle;
pub mod cancel;
pub mod car;
pub mod codesig;
pub mod core_dump;
pub mod dylib;
pub mod elf_layout;
pub mod error;
pub mod evm;
pub mod ib;
pub mod keyed_archive;
pub mod macho_dyld;
pub mod nib;
pub mod pe_resources;
pub mod dyld_syms;
pub mod macho_image;
pub mod macho_tools;
pub mod otool;
pub mod demangle;
pub mod plist_tool;
pub mod plistjs;
pub mod sigparse;

pub use error::{ArtifactReason, InputIssue, NativeError, NativeResult};
