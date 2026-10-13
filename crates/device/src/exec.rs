//! Bounded child-process execution (port of REA `ExecFileOutput.ts` and the
//! `runAdbBinary` helper of `AdbProvider.ts`).
//!
//! Semantics kept from Node's `execFile`: the child is spawned without a shell,
//! stdout and stderr are each capped at `max_buffer` bytes (exceeding the cap
//! stops the child and marks the failure as truncated), a deadline stops the
//! child with SIGTERM and a 5 second grace before SIGKILL, and the result
//! settles only after the child has exited.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

const STOP_GRACE: Duration = Duration::from_secs(5);

/// How a captured run ended when it did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureCode {
    /// Non-zero exit status.
    Exit(i32),
    /// Node-style error code (`ENOENT`, `EACCES`, `ETIMEDOUT`, ...).
    Name(String),
    /// Terminated by a signal that the caller did not request.
    None,
}

#[derive(Debug, Clone)]
pub struct ExecFailure {
    pub stdout: String,
    pub stderr: String,
    pub code: FailureCode,
    pub killed: bool,
    pub output_truncated: bool,
    /// Node's `error.message`, e.g. `Command failed: <cmd>\n<stderr>`.
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ExecSuccess {
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug)]
pub struct RawRun {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: Option<std::process::ExitStatus>,
    pub timed_out: bool,
    pub truncated: bool,
    /// Which stream exceeded the cap (`stdout` or `stderr`), when `truncated`.
    pub truncated_stream: &'static str,
}

/// Node's error code for a spawn failure.
pub fn spawn_error_code(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(1) => "EPERM",
        Some(2) => "ENOENT",
        Some(7) => "E2BIG",
        Some(8) => "ENOEXEC",
        Some(12) => "ENOMEM",
        Some(13) => "EACCES",
        Some(20) => "ENOTDIR",
        Some(21) => "EISDIR",
        Some(24) => "EMFILE",
        Some(26) => "ETXTBSY",
        Some(36) => "ENAMETOOLONG",
        Some(40) => "ELOOP",
        Some(other) => return format!("E{other}"),
        None => "UNKNOWN",
    }
    .to_string()
}

#[cfg(unix)]
fn terminate(child: &Child) {
    if let Some(pid) = child.id() {
        // SAFETY: plain signal delivery to a child process this function owns.
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
}

#[cfg(not(unix))]
fn terminate(child: &mut Child) {
    let _ = child.start_kill();
}

/// Run `binary` with `args`, capturing both pipes.
pub async fn run_raw(
    binary: &str,
    args: &[String],
    timeout_ms: u64,
    max_buffer: usize,
) -> Result<RawRun, std::io::Error> {
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let deadline = tokio::time::sleep(Duration::from_millis(timeout_ms));
    tokio::pin!(deadline);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut out_chunk = vec![0u8; 16 * 1024];
    let mut err_chunk = vec![0u8; 16 * 1024];
    let (mut out_done, mut err_done) = (false, false);
    let mut timed_out = false;
    let mut truncated = false;
    let mut truncated_stream = "stdout";
    while !(out_done && err_done) {
        tokio::select! {
            read = stdout_pipe.read(&mut out_chunk), if !out_done => match read {
                Ok(0) | Err(_) => out_done = true,
                Ok(n) => {
                    stdout.extend_from_slice(&out_chunk[..n]);
                    if stdout.len() > max_buffer {
                        stdout.truncate(max_buffer);
                        truncated = true;
                        break;
                    }
                }
            },
            read = stderr_pipe.read(&mut err_chunk), if !err_done => match read {
                Ok(0) | Err(_) => err_done = true,
                Ok(n) => {
                    stderr.extend_from_slice(&err_chunk[..n]);
                    if stderr.len() > max_buffer {
                        stderr.truncate(max_buffer);
                        truncated = true;
                        truncated_stream = "stderr";
                        break;
                    }
                }
            },
            _ = &mut deadline, if timeout_ms > 0 => {
                timed_out = true;
                break;
            }
        }
    }
    if timed_out || truncated {
        #[cfg(unix)]
        terminate(&child);
        #[cfg(not(unix))]
        terminate(&mut child);
        let status = match tokio::time::timeout(STOP_GRACE, child.wait()).await {
            Ok(status) => status.ok(),
            Err(_) => {
                let _ = child.start_kill();
                child.wait().await.ok()
            }
        };
        return Ok(RawRun { stdout, stderr, status, timed_out, truncated, truncated_stream });
    }
    let status = child.wait().await.ok();
    Ok(RawRun { stdout, stderr, status, timed_out, truncated, truncated_stream })
}

fn command_text(binary: &str, args: &[String]) -> String {
    if args.is_empty() {
        binary.to_string()
    } else {
        format!("{binary} {}", args.join(" "))
    }
}

/// `execFileOutput`: shell-free command with complete UTF-8 output.
pub async fn exec_file_output(
    binary: &str,
    args: &[String],
    timeout_ms: u64,
    max_buffer: usize,
) -> Result<ExecSuccess, ExecFailure> {
    let run = match run_raw(binary, args, timeout_ms, max_buffer).await {
        Ok(run) => run,
        Err(error) => {
            let code = spawn_error_code(&error);
            return Err(ExecFailure {
                stdout: String::new(),
                stderr: String::new(),
                message: format!("spawn {binary} {code}"),
                code: FailureCode::Name(code),
                killed: false,
                output_truncated: false,
            });
        }
    };
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
    if run.timed_out {
        return Err(ExecFailure {
            message: format!("Command timed out after {timeout_ms} ms: {}", command_text(binary, args)),
            stdout,
            stderr,
            code: FailureCode::Name("ETIMEDOUT".to_string()),
            killed: true,
            output_truncated: false,
        });
    }
    if run.truncated {
        return Err(ExecFailure {
            message: format!("{} maxBuffer length exceeded", run.truncated_stream),
            stdout,
            stderr,
            code: FailureCode::Name("ERR_CHILD_PROCESS_STDIO_MAXBUFFER".to_string()),
            killed: true,
            output_truncated: true,
        });
    }
    match run.status {
        Some(status) if status.success() => Ok(ExecSuccess { stdout, stderr }),
        Some(status) => Err(ExecFailure {
            message: format!("Command failed: {}\n{stderr}", command_text(binary, args)),
            code: match status.code() {
                Some(code) => FailureCode::Exit(code),
                None => FailureCode::None,
            },
            stdout,
            stderr,
            killed: false,
            output_truncated: false,
        }),
        None => Err(ExecFailure {
            message: format!("Command failed: {}\n{stderr}", command_text(binary, args)),
            stdout,
            stderr,
            code: FailureCode::None,
            killed: false,
            output_truncated: false,
        }),
    }
}

/// Outcome of `runAdbBinary` (raw stdout bytes).
#[derive(Debug)]
pub enum BinaryRun {
    Output(Vec<u8>),
    Timeout,
    /// `AnalysisProtocolError` text: `adb failed for <op>: <error.message>`.
    Failed(String),
}

/// Capture one invocation's raw binary stdout.
pub async fn exec_file_binary(binary: &str, args: &[String], timeout_ms: u64, max_buffer: usize) -> BinaryRun {
    match run_raw(binary, args, timeout_ms, max_buffer).await {
        Err(error) => BinaryRun::Failed(format!("spawn {binary} {}", spawn_error_code(&error))),
        Ok(run) if run.timed_out => BinaryRun::Timeout,
        Ok(run) if run.truncated => BinaryRun::Failed(format!("{} maxBuffer length exceeded", run.truncated_stream)),
        Ok(run) => match run.status {
            Some(status) if status.success() => BinaryRun::Output(run.stdout),
            _ => {
                let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
                BinaryRun::Failed(format!("Command failed: {}\n{stderr}", command_text(binary, args)))
            }
        },
    }
}
