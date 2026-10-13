//! Static Android analysis providers (JADX bridge, Apktool, JEB) and the
//! execution-free Android application projection (REA `src/android`,
//! `src/apktool`, `src/jeb`, `src/domain/android`).

#![allow(clippy::result_large_err)]

pub mod analysis;
pub mod appgraph;
pub mod config;
pub mod error;
pub mod apktool;
pub mod cancel;
pub mod jadx;
pub mod jeb;
pub mod schema;
