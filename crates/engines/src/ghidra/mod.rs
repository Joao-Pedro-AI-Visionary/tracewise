//! Ghidra (phase 5): headless analysis behind the provider abstraction.

pub mod capabilities;
pub mod client;
pub mod install;
pub mod profile;
pub mod provider;
pub mod values;

pub use provider::{GhidraConfig, GhidraProvider};
