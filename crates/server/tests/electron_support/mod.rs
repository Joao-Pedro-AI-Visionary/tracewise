//! Helpers of the active-Electron tests. `basic` is std-only (the CLI tests include it by
//! path); `setup` builds scenarios with the tracewise crates.
#![allow(dead_code)]

mod basic;
mod setup;

pub use basic::*;
pub use setup::*;
