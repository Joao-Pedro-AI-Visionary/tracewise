//! Hopper (phases 5 and 5b): GUI disassembler driven through REA's private Python bridge.

pub mod capabilities;
pub mod client;
pub mod config;
pub mod profile;
pub mod provider;

pub use config::HopperConfig;
pub use provider::HopperProvider;
