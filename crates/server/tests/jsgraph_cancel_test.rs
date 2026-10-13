//! Dropping an in-flight `analyze_javascript_application` call (what an MCP cancellation does)
//! stops the blocking analysis at its next checkpoint instead of letting it run to the end, and
//! the next call works.
//!
//! The analysis runs on a dedicated thread named `jsgraph-analysis`; the test watches the live
//! thread names of this process (`/proc/self/task/*/comm`), so it is Linux-only.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rmcp::model::CallToolRequestParam;
use serde_json::json;
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

fn analysis_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| {
                    std::fs::read_to_string(entry.path().join("comm"))
                        .map(|name| name.starts_with("jsgraph-analysi"))
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

fn big_app(label: &str, files: usize) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("jsgraph-cancel-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("package.json"), r#"{"name":"cancel","main":"index.js"}"#).unwrap();
    let mut index = String::new();
    for n in 0..files {
        let mut body = String::new();
        for k in 0..60 {
            body.push_str(&format!(
                "function f{k}(a, b) {{ const c = a + b + {n}; return [c, {{ k: {k}, v: c * 2 }}].map((x) => x && x.k); }}\nexports.f{k} = f{k};\n"
            ));
        }
        std::fs::write(dir.join(format!("src/m{n}.js")), body).unwrap();
        index.push_str(&format!("require('./src/m{n}.js');\n"));
    }
    std::fs::write(dir.join("index.js"), index).unwrap();
    dir
}

async fn analyze(session: &BinarySession, path: &Path) {
    let _ = call_tool_local(
        session,
        CallToolRequestParam {
            name: "analyze_javascript_application".into(),
            arguments: json!({"input_path": path.to_string_lossy(), "format": "directory"})
                .as_object()
                .cloned(),
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_the_call_stops_the_analysis_thread() {
    // Sized so that one full analysis takes tens of seconds in a debug build (about 2.7 s and 115 MB per
    // file here, like REA, whose result for 25 of these files already exceeds the 10 MB MCP budget):
    // 1_500 files needed more than 15 GB of memory and never finished.
    let app = big_app("drop", 8);
    let session = BinarySession::new();
    assert_eq!(analysis_threads(), 0);

    // Full run, for scale.
    let full_started = Instant::now();
    analyze(&session, &app).await;
    let full = full_started.elapsed();
    assert_eq!(analysis_threads(), 0, "a finished call leaves no analysis thread");

    // Abandon the call once the analysis thread really exists.
    let started = async {
        let deadline = Instant::now() + Duration::from_secs(30);
        while analysis_threads() == 0 {
            assert!(Instant::now() < deadline, "the analysis thread never started");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    };
    tokio::select! {
        _ = started => {}
        _ = analyze(&session, &app) => panic!("the call finished before the abandon point"),
    }
    let abandoned = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(60);
    while analysis_threads() > 0 {
        assert!(Instant::now() < deadline, "the analysis thread kept running after the call was dropped");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let stopped_after = abandoned.elapsed();
    eprintln!("full run {full:?}, stopped {stopped_after:?} after the call was dropped");
    assert!(
        stopped_after * 3 < full,
        "cancellation should stop the work well before a full run ({stopped_after:?} vs {full:?})"
    );

    // The next call is unaffected.
    analyze(&session, &app).await;
    assert_eq!(analysis_threads(), 0);
    let _ = std::fs::remove_dir_all(&app);
}
