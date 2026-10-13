//! Cancellation and shutdown of an owned Electron.
//!
//! The MCP dispatcher cancels a request by dropping the tool's future (`tokio::select!` in
//! `handlers.rs`). Electron has to be gone, and so does its private profile directory, by
//! the time the drop returns: nothing can be left to a later cleanup. Three places the future can be
//! dropped are covered, each with the real Electron 44.7.0:
//! - during startup, before Electron published its endpoints;
//! - in a click whose target never appears (REA: "remains pending until cancelled");
//! - in a long `wait` action.
//!
//! A fourth test simulates `process::exit` (the signal handler of `run_stdio_server`) by calling
//! the `atexit` hook while a run is in flight. The real server binary, with SIGTERM, a closed
//! stdin and `notifications/cancelled`, is covered by `crates/cli/tests/electron_shutdown_test.rs`.
//!
//! Skips (printing why) without Electron or Xvfb; fails instead when `TRACEWISE_REQUIRE_ORACLE=1`.

mod electron_support;

use std::time::Duration;

use electron_support::*;
use serde_json::json;
use tracewise_web::electron_active::process::{live_runs, shutdown_all_blocking};
use tracewise_web::electron_scenario::capture_electron_scenario_with;

/// Number of processes that belong to runs below `setup`'s runtime directory.
fn run_processes(setup: &Setup) -> Vec<i32> {
    processes_with_cmdline(&setup.scratch.0.to_string_lossy())
}

/// Poll until Electron is really up: its helper processes exist and then `settle` has passed.
///
/// Never block here: the capture future shares this thread (`current_thread` runtime), and a
/// blocking poll loop would starve it, so Electron would never start.
async fn electron_is_up(setup: &Setup, settle: Duration) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while run_processes(setup).len() < 4 {
        assert!(std::time::Instant::now() < deadline, "Electron never started: {:?}", run_processes(setup));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(settle).await;
}

fn assert_gone(setup: &Setup, what: &str) {
    // `Drop` is synchronous: no waiting is needed for the directory, and the processes were
    // waited for inside it. A short grace only absorbs `/proc` reporting of dying tasks.
    assert!(run_directories(&setup.scratch.0).is_empty(), "{what}: directory left: {:?}", run_directories(&setup.scratch.0));
    assert!(wait_until(Duration::from_secs(3), || run_processes(setup).is_empty()), "{what}: processes left: {:?}", run_processes(setup));
    assert_eq!(live_runs(), 0, "{what}: the run is still registered for the exit hook");
}

#[tokio::test]
async fn dropping_the_future_during_startup_leaves_nothing() {
    let _serial = SERIAL.lock().await;
    let Some(setup) = Setup::new("cancel-startup") else { return };
    let scenario = setup.scenario(json!([]));
    let config = setup.config();
    let environment = setup.environment();
    let capture = capture_electron_scenario_with(&scenario, Some(&config), &environment);
    tokio::select! {
        _ = capture => panic!("a capture cannot finish within 150 ms"),
        _ = tokio::time::sleep(Duration::from_millis(150)) => {}
    }
    assert_gone(&setup, "cancelled during startup");
}

#[tokio::test]
async fn dropping_the_future_in_a_click_that_never_resolves_leaves_nothing() {
    let _serial = SERIAL.lock().await;
    let Some(setup) = Setup::new("cancel-click") else { return };
    let scenario = setup.scenario(json!([{ "step_id": "missing", "kind": "click", "selector": "#does-not-exist" }]));
    let config = setup.config();
    let environment = setup.environment();
    let capture = capture_electron_scenario_with(&scenario, Some(&config), &environment);
    tokio::select! {
        _ = capture => panic!("a click on a missing element never completes"),
        _ = electron_is_up(&setup, Duration::from_secs(8)) => {}
    }
    assert_gone(&setup, "cancelled in a pending click");
}

#[tokio::test]
async fn dropping_the_future_in_a_long_wait_leaves_nothing() {
    let _serial = SERIAL.lock().await;
    let Some(setup) = Setup::new("cancel-wait") else { return };
    let scenario = setup.scenario(json!([{ "step_id": "long", "kind": "wait", "duration_ms": 600000 }]));
    let config = setup.config();
    let environment = setup.environment();
    let capture = capture_electron_scenario_with(&scenario, Some(&config), &environment);
    tokio::select! {
        _ = capture => panic!("a ten-minute wait cannot finish"),
        _ = electron_is_up(&setup, Duration::from_secs(8)) => {}
    }
    assert_gone(&setup, "cancelled in a wait");
}

#[tokio::test]
async fn the_exit_hook_cleans_a_run_that_is_still_in_flight() {
    let _serial = SERIAL.lock().await;
    let Some(setup) = Setup::new("exit-hook") else { return };
    let scenario = setup.scenario(json!([{ "step_id": "missing", "kind": "click", "selector": "#does-not-exist" }]));
    let config = setup.config();
    let environment = setup.environment();
    // The future stays alive (spawned), so `Drop` cannot be what cleans up: this is the path of
    // `std::process::exit`, which runs `atexit` handlers but drops no futures.
    let task = tokio::spawn(async move { capture_electron_scenario_with(&scenario, Some(&config), &environment).await.map(|_| ()) });
    electron_is_up(&setup, Duration::from_secs(8)).await;
    assert_eq!(live_runs(), 1);
    shutdown_all_blocking();
    assert!(run_directories(&setup.scratch.0).is_empty());
    assert!(wait_until(Duration::from_secs(3), || run_processes(&setup).is_empty()), "{:?}", run_processes(&setup));
    assert_eq!(live_runs(), 0);
    // The orphaned future now fails (its Electron is gone) instead of hanging.
    let outcome = tokio::time::timeout(Duration::from_secs(30), task).await.expect("the capture ends once Electron is gone");
    assert!(outcome.expect("task joined").is_err(), "the capture cannot succeed after its Electron was killed");
    assert_gone(&setup, "after the exit hook and the failed capture");
}
