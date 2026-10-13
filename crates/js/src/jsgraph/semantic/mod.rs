//! Semantic IR analysis (port of `domain/javascript/javascriptSemantic*.ts`).
//!
//! The public API mirrors REA's entry points:
//! - [`analyze_semantics`] = `analyzeParsedJavaScriptSemantics`
//! - [`classify_open_receivers`] = `classifyParsedJavaScriptOpenReceivers` (keys: call start)
//! - [`classify_electron_bindings`] = `classifyParsedJavaScriptElectronBindings` (keys: root
//!   identifier start)
//! - [`analyze_references`] = `analyzeParsedJavaScriptReferences`
//!
//! Module map (TS file -> module):
//! `javascriptSemanticAnalysis` -> [`analysis`], `State` -> [`state`], `Projection` ->
//! [`projection`], `Returns` -> [`returns`], `ReturnedReferences` -> [`returned_references`],
//! `RequireOrigin` -> [`require_origin`], `Provenance` -> [`provenance`], `Values` -> [`values`],
//! `ValueTypes` -> [`value_types`], `Primitives` -> [`primitives`], `Slots` -> [`slots`],
//! `PropertyPaths` -> [`property_paths`], `MutationValues` -> [`mutation_values`],
//! `MutationInitializers` -> [`mutation_initializers`], `MemberMutations` -> [`member_mutations`],
//! `IterationSources` -> [`iteration_sources`], `CallableResults` -> [`callable_results`],
//! `CallResolution` -> [`call_resolution`], `Coverage` -> [`coverage`], `ResourceLimits` ->
//! [`resource_limits`], `Traversal` -> [`traversal`], `DerivedAnalysis` -> [`derived`].

pub mod analysis;
pub mod ast_util;
pub mod async_effects;
pub mod call_resolution;
pub mod callable_results;
pub mod calls;
pub mod child_processes;
pub mod coverage;
pub mod data_effect_helpers;
pub mod data_effects;
pub mod derived;
pub mod fingerprints;
pub mod iteration_sources;
pub mod member_mutations;
pub mod mutation_initializers;
pub mod mutation_values;
pub mod objects;
pub mod primitives;
pub mod projection;
pub mod promises;
pub mod property_paths;
pub mod provenance;
pub mod require_origin;
pub mod resource_limits;
pub mod resources;
pub mod returned_references;
pub mod returns;
pub mod slots;
pub mod state;
pub mod traversal;
pub mod value_types;
pub mod values;

pub use analysis::{analyze_references, analyze_semantics, classify_electron_bindings, classify_open_receivers};
pub use state::SemanticAnalysisState;
