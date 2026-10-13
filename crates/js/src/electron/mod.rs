//! Electron tools (`list_electron_targets`, `inspect_electron_page`,
//! `capture_electron_scenario`), port of REA server/registerElectronTools.ts.
//!
//! The CDP work lives in `tracewise_web::electron_*` beside the shared CDP
//! client; this module is the JS-crate facade the server dispatches to.
//! Errors stay `WebError` so the server can project browser failures as
//! `isError` results exactly like the other CDP tools.
//!
//! `capture_electron_scenario` validates and canonicalizes its input, then runs
//! the active provider (`tracewise_web::electron_active`: Electron launched with
//! REA's `electron-active-hook.cjs` and controlled over CDP) when an Electron is
//! configured through `TRACEWISE_ELECTRON_EXECUTABLE`; otherwise it reports REA's
//! "provider is not configured" error. Its error type also carries the REA
//! `cleanup_incomplete` failure, which keeps the collected observations.
//!
//! The passive tools' tests use headless Google Chrome as a CDP stand-in for
//! Electron; they speak only standard CDP, so the protocol is identical.

use serde_json::{Map, Value};
use tracewise_domain::evidence::Evidence;
use tracewise_web::electron_active::ElectronCaptureError;
use tracewise_web::electron_inspection::{inspect_electron_page, InspectElectronPageInput};
use tracewise_web::electron_scenario::capture_electron_scenario;
use tracewise_web::electron_targets::list_electron_targets;
use tracewise_web::error::WebError;

/// List local `file://` page targets at a loopback CDP endpoint.
pub async fn list_electron_targets_tool(cdp_endpoint: &str) -> Result<Evidence, WebError> {
    list_electron_targets(cdp_endpoint).await
}

/// Passively inspect one local file page.
pub async fn inspect_electron_page_tool(input: &InspectElectronPageInput) -> Result<Evidence, WebError> {
    inspect_electron_page(input).await
}

/// Run one owned Electron scenario (validated input from
/// `parse_capture_electron_scenario_input`).
pub async fn capture_electron_scenario_tool(input: &Map<String, Value>) -> Result<Evidence, ElectronCaptureError> {
    capture_electron_scenario(input).await
}
