//! Native analysis engines for tracewise (phases 5 and 5b).
//!
//! One provider abstraction serves Ghidra (headless, ephemeral database), Hopper
//! (GUI with annotation) and IDA (read-only MCP client). The server crate turns
//! provider executions into Evidence and MCP results.

// Errors carry rich diagnostics and only exist on cold paths; boxing them would add noise
// to every constructor without a measurable benefit.
#![allow(clippy::result_large_err)]

pub mod contract_input;
pub mod error;
pub mod ghidra;
pub mod hopper;
pub mod ida;
pub mod provider;
pub mod target;
pub mod config;
pub mod derived;
pub mod session;
pub mod workflows;
pub mod process;
