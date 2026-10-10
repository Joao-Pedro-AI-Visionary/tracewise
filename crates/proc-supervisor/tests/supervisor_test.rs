use std::time::Duration;
use proc_supervisor::{ProcessSupervisor, SupervisorError};

#[tokio::test]
async fn test_timeout_kills_sleep_grandchild_group() {
    let temp_dir = std::env::temp_dir();
    let pid_file = temp_dir.join(format!("test_gc_pid_{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&pid_file);

    let script = format!(
        "sleep 60 & GC=$!; echo $GC > {}; wait $GC",
        pid_file.display()
    );

    let mut supervisor = ProcessSupervisor::new("sh");
    supervisor
        .arg("-c")
        .arg(&script)
        .timeout(Duration::from_millis(250));

    let res = supervisor.run().await;
    match res {
        Err(SupervisorError::Timeout(_)) => {}
        other => panic!("Expected timeout error, got {:?}", other),
    }

    // Read grandchild PID
    let pid_str = std::fs::read_to_string(&pid_file).expect("PID file should exist");
    let gc_pid: i32 = pid_str.trim().parse().expect("Grandchild PID must be an integer");

    // Give kernel a few milliseconds to process signal
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Check if grandchild is dead
    let signal_res = nix::sys::signal::kill(nix::unistd::Pid::from_raw(gc_pid), None);
    assert!(
        signal_res.is_err(),
        "Grandchild process {} should be killed, but kill(pid, 0) succeeded",
        gc_pid
    );
    assert_eq!(
        signal_res.unwrap_err(),
        nix::errno::Errno::ESRCH,
        "Expected ESRCH (no such process)"
    );

    let _ = std::fs::remove_file(&pid_file);
}

#[tokio::test]
async fn test_output_cap_truncation() {
    let mut supervisor = ProcessSupervisor::new("sh");
    supervisor
        .arg("-c")
        .arg("for i in $(seq 1 1000); do echo '1234567890'; done")
        .max_stdout_bytes(100);

    let output = supervisor.run().await.expect("Run should succeed");
    assert_eq!(output.stdout.len(), 100);
    assert!(output.stdout_truncated);
}

#[tokio::test]
async fn test_output_cap_error_when_configured() {
    let mut supervisor = ProcessSupervisor::new("sh");
    supervisor
        .arg("-c")
        .arg("for i in $(seq 1 1000); do echo '1234567890'; done")
        .max_stdout_bytes(100)
        .fail_on_cap(true);

    let res = supervisor.run().await;
    match res {
        Err(SupervisorError::OutputCapExceeded(limit)) => {
            assert_eq!(limit, 100);
        }
        other => panic!("Expected OutputCapExceeded, got {:?}", other),
    }
}

#[tokio::test]
async fn test_drop_kills_process_group() {
    let temp_dir = std::env::temp_dir();
    let pid_file = temp_dir.join(format!("test_drop_gc_pid_{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&pid_file);

    let script = format!(
        "sleep 60 & GC=$!; echo $GC > {}; wait $GC",
        pid_file.display()
    );

    let mut supervisor = ProcessSupervisor::new("sh");
    supervisor.arg("-c").arg(&script);

    let child = supervisor.spawn().expect("Spawn should succeed");

    // Wait until pid_file is written
    for _ in 0..50 {
        if pid_file.exists() && std::fs::metadata(&pid_file).unwrap().len() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let pid_str = std::fs::read_to_string(&pid_file).expect("PID file should exist");
    let gc_pid: i32 = pid_str.trim().parse().expect("Grandchild PID must be integer");

    // Now drop the child (which triggers Drop -> kill_group)
    drop(child);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let signal_res = nix::sys::signal::kill(nix::unistd::Pid::from_raw(gc_pid), None);
    assert_eq!(
        signal_res.unwrap_err(),
        nix::errno::Errno::ESRCH,
        "Grandchild should be killed upon supervisor drop"
    );

    let _ = std::fs::remove_file(&pid_file);
}
