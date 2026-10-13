//! Application graph construction (port of `JavaScriptArtifactGraph*.ts`, `JavaScriptModuleRelationships.ts`,
//! `JavaScriptArtifactPathResolution.ts`, `ElectronBoundary*.ts` and friends).

pub mod analysis;
pub mod build;
pub mod bundlers;
pub mod context;
pub mod documents;
pub mod domain;
pub mod electron;
pub mod files;
pub mod findings;
pub mod html;
pub mod model;
pub mod module_relationships;
pub mod path_resolution;
pub mod posix;
pub mod reconstruct;
pub mod structure;
