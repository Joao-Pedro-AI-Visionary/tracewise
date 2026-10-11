use std::ffi::OsStr;
use std::path::Path;
use std::process::ExitStatus;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("Command execution timed out after {0:?}")]
    Timeout(Duration),

    #[error("Command cancelled")]
    Cancelled,

    #[error("Output cap exceeded: {0} bytes")]
    OutputCapExceeded(usize),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

pub struct SupervisedChild {
    child: Option<Child>,
    pgid: Option<u32>,
    reaped: bool,
}

impl SupervisedChild {
    pub fn id(&self) -> Option<u32> {
        self.child.as_ref().and_then(|c| c.id())
    }

    pub fn pgid(&self) -> Option<u32> {
        self.pgid
    }

    /// Explicitly kill the entire process group with SIGKILL.
    pub fn kill_group(&mut self) -> std::io::Result<()> {
        if let Some(pgid) = self.pgid {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(pgid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        Ok(())
    }

    pub async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(ref mut child) = self.child {
            let status = child.wait().await?;
            self.reaped = true;
            Ok(status)
        } else {
            Err(std::io::Error::other("Child already reaped"))
        }
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.kill_group();
        }
    }
}

pub struct ProcessSupervisor {
    command: Command,
    timeout: Option<Duration>,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
    fail_on_cap: bool,
}

impl ProcessSupervisor {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        let mut command = Command::new(program);
        command.process_group(0);
        Self {
            command,
            timeout: None,
            max_stdout_bytes: usize::MAX,
            max_stderr_bytes: usize::MAX,
            fail_on_cap: false,
        }
    }

    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.command.arg(arg);
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command.args(args);
        self
    }

    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.command.current_dir(dir);
        self
    }

    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.command.env(key, val);
        self
    }

    pub fn timeout(&mut self, duration: Duration) -> &mut Self {
        self.timeout = Some(duration);
        self
    }

    pub fn max_stdout_bytes(&mut self, limit: usize) -> &mut Self {
        self.max_stdout_bytes = limit;
        self
    }

    pub fn max_stderr_bytes(&mut self, limit: usize) -> &mut Self {
        self.max_stderr_bytes = limit;
        self
    }

    pub fn fail_on_cap(&mut self, fail: bool) -> &mut Self {
        self.fail_on_cap = fail;
        self
    }

    /// Discard the child's stdin, stdout, and stderr.
    ///
    /// Long-running processes such as headless Chrome keep writing logs. An
    /// inherited pipe that nobody reads will eventually stall the child.
    pub fn null_stdio(&mut self) -> &mut Self {
        self.command.stdin(std::process::Stdio::null());
        self.command.stdout(std::process::Stdio::null());
        self.command.stderr(std::process::Stdio::null());
        self
    }

    /// Spawns the child in its own process group, returning a `SupervisedChild`
    pub fn spawn(&mut self) -> Result<SupervisedChild, std::io::Error> {
        self.command.process_group(0);
        let child = self.command.spawn()?;
        let pgid = child.id();
        Ok(SupervisedChild {
            child: Some(child),
            pgid,
            reaped: false,
        })
    }

    /// Spawns and runs the command with bounded output capture and optional timeout.
    /// Kills the entire process group if dropped, cancelled, or on timeout.
    pub async fn run(&mut self) -> Result<Output, SupervisorError> {
        self.command.process_group(0);
        self.command.stdout(std::process::Stdio::piped());
        self.command.stderr(std::process::Stdio::piped());

        let mut child = self.command.spawn()?;
        let pgid = child.id();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let mut supervised = SupervisedChild {
            child: Some(child),
            pgid,
            reaped: false,
        };

        let max_stdout = self.max_stdout_bytes;
        let max_stderr = self.max_stderr_bytes;
        let fail_on_cap = self.fail_on_cap;

        let execution_fut = async {
            let stdout_fut = async {
                if let Some(r) = stdout {
                    read_bounded(r, max_stdout).await
                } else {
                    Ok((Vec::new(), false))
                }
            };

            let stderr_fut = async {
                if let Some(r) = stderr {
                    read_bounded(r, max_stderr).await
                } else {
                    Ok((Vec::new(), false))
                }
            };

            let (stdout_res, stderr_res) = tokio::join!(stdout_fut, stderr_fut);
            let (stdout_bytes, stdout_truncated) = stdout_res?;
            let (stderr_bytes, stderr_truncated) = stderr_res?;

            if fail_on_cap {
                if stdout_truncated {
                    let _ = supervised.kill_group();
                    return Err(SupervisorError::OutputCapExceeded(max_stdout));
                }
                if stderr_truncated {
                    let _ = supervised.kill_group();
                    return Err(SupervisorError::OutputCapExceeded(max_stderr));
                }
            }

            let status = supervised.wait().await?;

            Ok(Output {
                status,
                stdout: stdout_bytes,
                stderr: stderr_bytes,
                stdout_truncated,
                stderr_truncated,
            })
        };

        if let Some(timeout_dur) = self.timeout {
            match tokio::time::timeout(timeout_dur, execution_fut).await {
                Ok(res) => res,
                Err(_) => {
                    let _ = supervised.kill_group();
                    let _ = supervised.wait().await;
                    Err(SupervisorError::Timeout(timeout_dur))
                }
            }
        } else {
            execution_fut.await
        }
    }
}

async fn read_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    max_bytes: usize,
) -> Result<(Vec<u8>, bool), SupervisorError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut truncated = false;

    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() + n <= max_bytes {
            buf.extend_from_slice(&chunk[..n]);
        } else {
            let remaining = max_bytes.saturating_sub(buf.len());
            if remaining > 0 {
                buf.extend_from_slice(&chunk[..remaining]);
            }
            truncated = true;
            break;
        }
    }

    Ok((buf, truncated))
}
