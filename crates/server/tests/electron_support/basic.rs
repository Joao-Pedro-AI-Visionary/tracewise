//! Shared helpers of the active-Electron tests: the pinned Electron, a private
//! Xvfb display (so no window ever reaches the developer's desktop), the fixture
//! application and a process scanner for the "no orphans" assertions.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Pinned Electron (`/workspace/tools/electron-44.7.0`, the version REA documents
/// as verified). `TRACEWISE_TEST_ELECTRON` overrides the path.
pub const DEFAULT_ELECTRON: &str = "/workspace/tools/electron-44.7.0/electron";

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

pub fn readiness_app() -> PathBuf {
    repo_root().join("fixtures/electron/readiness_app")
}

/// Skip with a printed reason, or panic when `TRACEWISE_REQUIRE_ORACLE=1`.
pub fn skip_or_fail(reason: &str) {
    if std::env::var("TRACEWISE_REQUIRE_ORACLE").map(|v| v == "1").unwrap_or(false) {
        panic!("TRACEWISE_REQUIRE_ORACLE=1 but {reason}");
    }
    eprintln!("SKIP: {reason}");
}

pub fn electron_executable() -> Option<PathBuf> {
    let path = std::env::var("TRACEWISE_TEST_ELECTRON").unwrap_or_else(|_| DEFAULT_ELECTRON.to_string());
    let path = PathBuf::from(path);
    if path.is_file() {
        path.canonicalize().ok()
    } else {
        skip_or_fail(&format!("Electron is not installed at {}", path.display()));
        None
    }
}

/// A private X server on an abstract socket; killed on drop.
pub struct Xvfb {
    child: Child,
    pub display: String,
}

impl Xvfb {
    /// `-displayfd` picks a free display; where the filesystem socket directory is
    /// not writable (WSLg mounts `/tmp/.X11-unix` read-only) that fails, so fall
    /// back to a fixed display number served over the abstract socket only.
    pub fn start() -> Option<Self> {
        if which("Xvfb").is_none() {
            skip_or_fail("Xvfb is not available");
            return None;
        }
        if let Some(server) = Self::start_with_displayfd() {
            return Some(server);
        }
        let first = 300 + (std::process::id() % 400);
        for offset in 0..40 {
            let number = first + offset;
            if Path::new(&format!("/tmp/.X{number}-lock")).exists() {
                continue;
            }
            let mut command = Command::new("Xvfb");
            command
                .args([&format!(":{number}"), "-screen", "0", "1280x800x24", "-nolisten", "tcp"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let Ok(mut child) = die_with_parent(&mut command).spawn() else { continue };
            if wait_until(Duration::from_secs(5), || {
                matches!(child.try_wait(), Ok(Some(_))) || display_accepts(number)
            }) && matches!(child.try_wait(), Ok(None))
            {
                return Some(Self {
                    child,
                    display: format!(":{number}"),
                });
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        skip_or_fail("Xvfb could not start on any display");
        None
    }

    fn start_with_displayfd() -> Option<Self> {
        let mut command = Command::new("Xvfb");
        command
            .args(["-displayfd", "1", "-screen", "0", "1280x800x24", "-nolisten", "tcp"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = die_with_parent(&mut command).spawn().ok()?;
        let mut line = String::new();
        let read = BufReader::new(child.stdout.take()?).read_line(&mut line);
        let number = line.trim().to_string();
        if read.is_err() || number.is_empty() {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        Some(Self {
            child,
            display: format!(":{number}"),
        })
    }
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

fn display_accepts(number: u32) -> bool {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixStream};
    let path = format!("/tmp/.X11-unix/X{number}");
    UnixStream::connect(&path).is_ok()
        || SocketAddr::from_abstract_name(path.as_bytes())
            .and_then(|address| UnixStream::connect_addr(&address))
            .is_ok()
}

impl Drop for Xvfb {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Environment handed to the launched Electron (REA copies only a few names).
pub fn launch_environment(display: &str) -> HashMap<String, String> {
    let mut environment = HashMap::new();
    for name in ["HOME", "LANG", "PATH", "USER"] {
        if let Ok(value) = std::env::var(name) {
            environment.insert(name.to_string(), value);
        }
    }
    environment.insert("DISPLAY".to_string(), display.to_string());
    environment
}

/// Chromium switches every test run needs here: no setuid sandbox helper and no
/// GPU process under Xvfb. They are request arguments, not provider behavior.
pub fn base_args() -> Vec<String> {
    ["--no-sandbox", "--disable-gpu"].iter().map(|s| s.to_string()).collect()
}

/// Live pids whose command line mentions `needle` (excluding this process).
pub fn processes_with_cmdline(needle: &str) -> Vec<i32> {
    let me = std::process::id() as i32;
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: i32 = entry.file_name().to_str()?.parse().ok()?;
            if pid == me {
                return None;
            }
            let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            let state = stat.rsplit(')').next()?.trim().chars().next()?;
            if matches!(state, 'Z' | 'X') {
                return None;
            }
            let cmdline = std::fs::read(entry.path().join("cmdline")).ok()?;
            String::from_utf8_lossy(&cmdline).replace('\0', " ").contains(needle).then_some(pid)
        })
        .collect()
}

/// Entries of `root` that belong to an Electron run (`tracewise-electron-*`).
pub fn run_directories(root: &Path) -> Vec<String> {
    std::fs::read_dir(root)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter(|name| name.starts_with("tracewise-electron-"))
                .collect()
        })
        .unwrap_or_default()
}

pub fn wait_until(limit: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    condition()
}

/// A unique directory below the system temp dir, removed on drop.
pub struct ScratchDir(pub PathBuf);

impl ScratchDir {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("tw-{label}-{}-{}", std::process::id(), nanos()));
        std::fs::create_dir_all(&path).expect("scratch dir");
        Self(path)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

extern "C" {
    fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
}

/// Make the child die with the test process (`PR_SET_PDEATHSIG`, `SIGKILL`), so an X server
/// is never left behind even when a test is killed.
pub fn die_with_parent(command: &mut Command) -> &mut Command {
    use std::os::unix::process::CommandExt;
    // SAFETY: `prctl` is async-signal-safe and the closure does nothing else between fork and exec.
    unsafe {
        command.pre_exec(|| {
            prctl(1, 9, 0, 0, 0);
            Ok(())
        });
    }
    command
}
