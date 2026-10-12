//! Linux procfs subset of REA `process/ProcessOwnership*.ts` and
//! `process/capture/ProcessSampling.ts`: run-token ownership, settlement
//! observation, owned-group cleanup and process-tree sampling.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use super::normalization::ProcessSample;

pub const RUN_ID_VARIABLE: &str = "REA_PROCESS_RUN_ID";

#[derive(Debug, Clone)]
pub struct ProcStat {
    pub pid: u64,
    pub parent_pid: u64,
    pub process_group_id: u64,
    pub session_id: u64,
    pub state: char,
    pub start_time: String,
}

/// Parse `/proc/<pid>/stat` the way REA does (fields after the last `)`).
pub fn read_stat(pid: u64) -> Option<ProcStat> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = text.rfind(')')?;
    let fields: Vec<&str> = text.get(end + 2..)?.split_whitespace().collect();
    let state = fields.first()?.chars().next()?;
    let parent_pid = fields.get(1)?.parse().ok()?;
    let process_group_id: u64 = fields.get(2)?.parse().ok()?;
    let session_id: u64 = fields.get(3)?.parse().ok()?;
    let start_time = fields.get(19)?.to_string();
    if process_group_id == 0 || session_id == 0 || !start_time.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(ProcStat { pid, parent_pid, process_group_id, session_id, state, start_time })
}

/// Live (non-zombie) process table.
pub fn live_processes() -> std::io::Result<Vec<ProcStat>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u64>().ok()) else { continue };
        if let Some(stat) = read_stat(pid) {
            if stat.state != 'Z' {
                out.push(stat);
            }
        }
    }
    out.sort_by_key(|s| s.pid);
    Ok(out)
}

pub enum TokenObservation {
    Readable(Option<String>),
    Unreadable,
}

/// Read the run token from `/proc/<pid>/environ`.
pub fn read_run_token(pid: u64) -> TokenObservation {
    match std::fs::read(format!("/proc/{pid}/environ")) {
        Ok(bytes) => {
            let prefix = format!("{RUN_ID_VARIABLE}=");
            let token = bytes
                .split(|b| *b == 0)
                .filter_map(|entry| std::str::from_utf8(entry).ok())
                .find_map(|entry| entry.strip_prefix(&prefix).map(str::to_string));
            TokenObservation::Readable(token)
        }
        Err(_) => TokenObservation::Unreadable,
    }
}

fn process_is_gone(pid: u64) -> bool {
    read_stat(pid).is_none_or(|s| s.state == 'Z')
}

/// Select the PTY root group and groups led by an observed captured process.
pub fn captured_process_group_ids(root_pid: u64, samples: &[ProcessSample]) -> Vec<u64> {
    let mut ids = vec![root_pid];
    for sample in samples {
        if Some(sample.pid) == sample.process_group_id && !ids.contains(&sample.pid) {
            ids.push(sample.pid);
        }
    }
    ids
}

#[derive(Debug, Clone, PartialEq)]
pub enum GroupState {
    Empty,
    Alive,
    Unverifiable,
}

/// `observeOwnedProcessGroups`: group membership with token revalidation.
pub fn observe_owned_groups(run_id: &str, group_ids: &[u64]) -> Vec<GroupState> {
    let processes = match live_processes() {
        Ok(p) => p,
        Err(_) => return vec![GroupState::Unverifiable; group_ids.len()],
    };
    group_ids
        .iter()
        .map(|group| {
            let members: Vec<&ProcStat> = processes.iter().filter(|p| p.process_group_id == *group).collect();
            if members.is_empty() {
                return GroupState::Empty;
            }
            for member in members {
                match read_run_token(member.pid) {
                    TokenObservation::Readable(token) => {
                        if token.as_deref() != Some(run_id) {
                            return GroupState::Unverifiable;
                        }
                    }
                    TokenObservation::Unreadable => {
                        if !process_is_gone(member.pid) {
                            return GroupState::Unverifiable;
                        }
                    }
                }
            }
            GroupState::Alive
        })
        .collect()
}

/// Observed settlement state and elapsed time.
pub fn observe_settlement(
    run_id: &str,
    group_ids: &[u64],
    settle_ms: u64,
    on_tick: &mut dyn FnMut(),
) -> (&'static str, u64) {
    let started = Instant::now();
    let mut consecutive_empty = 0;
    loop {
        on_tick();
        let observations = observe_owned_groups(run_id, group_ids);
        let elapsed = started.elapsed().as_millis() as u64;
        if observations.contains(&GroupState::Unverifiable) {
            return ("unverifiable", elapsed);
        }
        if observations.iter().all(|s| *s == GroupState::Empty) {
            consecutive_empty += 1;
            if consecutive_empty >= 2 {
                return ("quiesced", elapsed);
            }
        } else {
            consecutive_empty = 0;
        }
        if elapsed >= settle_ms {
            return ("alive_at_deadline", elapsed);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn descendants(root: u64, processes: &[ProcStat]) -> HashSet<u64> {
    let mut out = HashSet::new();
    let mut pending = vec![root];
    while let Some(parent) = pending.pop() {
        for p in processes.iter().filter(|p| p.parent_pid == parent) {
            if out.insert(p.pid) {
                pending.push(p.pid);
            }
        }
    }
    out
}

/// Token-validate and SIGKILL every owned process group, then sweep and
/// verify that no live process still carries the run token.
pub fn cleanup_owned_processes(run_id: &str, root_pid: u64, sampled_group_ids: &[u64]) -> Result<(), String> {
    let processes = live_processes().map_err(|e| format!("process table could not be inspected: {e}"))?;
    let token_owned: Vec<&ProcStat> = processes
        .iter()
        .filter(|p| matches!(read_run_token(p.pid), TokenObservation::Readable(Some(ref t)) if t == run_id))
        .collect();
    let mut groups: Vec<u64> = vec![root_pid];
    let root_alive = processes.iter().any(|p| p.pid == root_pid);
    if root_alive {
        let desc = descendants(root_pid, &processes);
        for p in processes.iter().filter(|p| desc.contains(&p.pid)) {
            if !groups.contains(&p.process_group_id) {
                groups.push(p.process_group_id);
            }
        }
    }
    for g in token_owned.iter().map(|p| p.process_group_id).chain(sampled_group_ids.iter().copied()) {
        if g > 0 && !groups.contains(&g) {
            groups.push(g);
        }
    }
    let owned_pids: HashSet<u64> = token_owned.iter().map(|p| p.pid).collect();
    for group in &groups {
        let members: Vec<&ProcStat> = processes.iter().filter(|p| p.process_group_id == *group).collect();
        if members.is_empty() {
            continue;
        }
        // Signal a group only when every live member proves ownership.
        let all_owned = members.iter().all(|m| owned_pids.contains(&m.pid) || process_is_gone(m.pid));
        if all_owned {
            // SAFETY: plain syscall with integer arguments.
            let rc = unsafe { libc::killpg(*group as libc::pid_t, libc::SIGKILL) };
            if rc != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(format!("owned process group signal failed: {error}"));
                }
            }
        }
    }
    for pid in &owned_pids {
        // SAFETY: plain syscall with integer arguments.
        unsafe { libc::kill(*pid as libc::pid_t, libc::SIGKILL) };
    }
    let deadline = Instant::now() + Duration::from_millis(1_000);
    loop {
        let remaining: Vec<u64> = live_processes()
            .map_err(|e| format!("process table could not be inspected: {e}"))?
            .iter()
            .filter(|p| matches!(read_run_token(p.pid), TokenObservation::Readable(Some(ref t)) if t == run_id))
            .map(|p| p.pid)
            .collect();
        if remaining.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("token-owned process remained after cleanup".into());
        }
        for pid in remaining {
            // SAFETY: plain syscall with integer arguments.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

// ---------------------------------------------------------------------------
// Sampling (`ProcessSampling.ts`, Linux branch)
// ---------------------------------------------------------------------------

fn read_children(pid: u64) -> Option<Vec<u64>> {
    let tasks = std::fs::read_dir(format!("/proc/{pid}/task")).ok()?;
    let mut task_ids: Vec<u64> = tasks.filter_map(|t| t.ok()?.file_name().to_str()?.parse().ok()).collect();
    task_ids.sort_unstable();
    let mut children = HashSet::new();
    let mut successful = 0;
    for task in task_ids {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/task/{task}/children")) else { continue };
        successful += 1;
        children.extend(text.split_whitespace().filter_map(|v| v.parse::<u64>().ok()).filter(|v| *v > 0));
    }
    if successful == 0 {
        return None;
    }
    let mut out: Vec<u64> = children.into_iter().collect();
    out.sort_unstable();
    Some(out)
}

struct Node {
    stat: ProcStat,
    command: String,
    children: Vec<u64>,
}

fn inspect(pid: u64, expected_parent: Option<u64>, identities: &HashMap<u64, String>) -> Option<Node> {
    let before = read_stat(pid)?;
    if identities.get(&pid).is_some_and(|s| *s != before.start_time) {
        return None;
    }
    if expected_parent.is_some_and(|p| p != before.parent_pid) {
        return None;
    }
    let command_bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok();
    let children = read_children(pid);
    let after = read_stat(pid)?;
    if before.start_time != after.start_time || before.parent_pid != after.parent_pid {
        return None;
    }
    let command = command_bytes
        .map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string())
        .unwrap_or_default();
    Some(Node { stat: before, command, children: children.unwrap_or_default() })
}

/// Breadth-first process-tree sample rooted at the PTY process.
fn sample_tree(root_pid: u64, limit: u64, identities: &HashMap<u64, String>) -> Vec<Node> {
    if limit == 0 || read_stat(root_pid).is_none() {
        return Vec::new();
    }
    let mut rows = Vec::new();
    let mut visited: HashSet<u64> = HashSet::from([root_pid]);
    let mut level: Vec<(u64, Option<u64>)> = vec![(root_pid, None)];
    while !level.is_empty() && (rows.len() as u64) < limit {
        let batch: Vec<(u64, Option<u64>)> = level.drain(..level.len().min(64)).collect();
        let mut next = Vec::new();
        for (pid, parent) in batch {
            let Some(node) = inspect(pid, parent, identities) else { continue };
            if rows.len() as u64 >= limit {
                break;
            }
            for child in &node.children {
                if visited.insert(*child) {
                    next.push((*child, Some(node.stat.pid)));
                }
            }
            rows.push(node);
            if rows.len() as u64 >= limit {
                break;
            }
        }
        level.extend(next);
    }
    rows
}

/// Prove that forkpty completed session setup and installed the run token.
fn initialized_root(root_pid: u64, run_id: &str) -> Option<String> {
    let before = read_stat(root_pid)?;
    if before.process_group_id != root_pid || before.session_id != root_pid {
        return None;
    }
    let token = match read_run_token(root_pid) {
        TokenObservation::Readable(t) => t,
        TokenObservation::Unreadable => return None,
    };
    let after = read_stat(root_pid)?;
    (after.pid == root_pid
        && after.parent_pid == before.parent_pid
        && after.process_group_id == root_pid
        && after.session_id == root_pid
        && after.start_time == before.start_time
        && token.as_deref() == Some(run_id))
    .then_some(after.start_time)
}

/// Mutable sampler state shared with the capture loop.
pub struct Sampler {
    root_pid: u64,
    run_id: String,
    limit: u64,
    identities: HashMap<u64, String>,
    last_observations: HashMap<u64, String>,
    root_initialized: bool,
    pub partial: bool,
    pub limit_reached: bool,
    pub failures: u64,
    pub first_failure: Option<String>,
}

impl Sampler {
    pub fn new(root_pid: u64, run_id: &str, limit: u64) -> Self {
        Self {
            root_pid,
            run_id: run_id.to_string(),
            limit,
            identities: HashMap::new(),
            last_observations: HashMap::new(),
            root_initialized: false,
            partial: false,
            limit_reached: false,
            failures: 0,
            first_failure: None,
        }
    }

    /// Take one sample; returns newly retained samples.
    pub fn sample(&mut self, elapsed_ms: u64, retained: usize) -> Vec<ProcessSample> {
        if !self.root_initialized {
            match initialized_root(self.root_pid, &self.run_id) {
                None => return Vec::new(),
                Some(start) => {
                    self.identities.insert(self.root_pid, start);
                    self.root_initialized = true;
                }
            }
        }
        let rows = sample_tree(self.root_pid, self.limit + 1, &self.identities);
        let mut retained_now = Vec::new();
        for row in rows {
            if self.identities.get(&row.stat.pid).is_some_and(|s| *s != row.stat.start_time) {
                continue;
            }
            self.identities.insert(row.stat.pid, row.stat.start_time.clone());
            let observation = format!(
                "{}\0{}\0{}\0{}",
                row.stat.parent_pid, row.command, row.stat.process_group_id, row.stat.session_id
            );
            if self.last_observations.get(&row.stat.pid) == Some(&observation) {
                continue;
            }
            if (retained + retained_now.len()) as u64 >= self.limit {
                self.partial = true;
                self.limit_reached = true;
                continue;
            }
            self.last_observations.insert(row.stat.pid, observation);
            retained_now.push(ProcessSample {
                at_ms: elapsed_ms,
                pid: row.stat.pid,
                parent_pid: row.stat.parent_pid,
                command: row.command,
                process_group_id: Some(row.stat.process_group_id),
                session_id: Some(row.stat.session_id),
            });
        }
        retained_now
    }
}
