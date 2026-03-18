use super::shell::collect_allowed_shell_env_vars;
use super::traits::{Tool, ToolResult};
use super::{action_command_preflight_for, ActionCommandPreflight};
use crate::config::ResourceLimitsConfig;
use crate::runtime::RuntimeAdapter;
use crate::security::policy::ToolOperation;
use crate::security::SecurityPolicy;
use crate::security::SyscallAnomalyDetector;
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::io::AsyncReadExt;

/// Maximum output bytes kept per stream (stdout/stderr): 512KB.
const MAX_OUTPUT_BYTES: usize = 524_288;

/// Maximum concurrent background processes.
const DEFAULT_MAX_PROCESSES: usize = 8;

#[derive(Debug, Default, Clone)]
struct OutputBuffer {
    data: String,
    dropped_prefix_bytes: u64,
}

struct ProcessEntry {
    id: usize,
    command: String,
    pid: u32,
    started_at: Instant,
    child: Mutex<tokio::process::Child>,
    stdout_buf: Arc<Mutex<OutputBuffer>>,
    stderr_buf: Arc<Mutex<OutputBuffer>>,
    analyzed_offsets: Mutex<(u64, u64)>,
}

/// Background process management tool.
///
/// Allows the agent to spawn long-running commands, check their output,
/// and terminate them. Complements the synchronous `ShellTool` for commands
/// that need to run beyond the 60-second shell timeout.
pub struct ProcessTool {
    security: Arc<SecurityPolicy>,
    runtime: Arc<dyn RuntimeAdapter>,
    syscall_detector: Option<Arc<SyscallAnomalyDetector>>,
    processes: Arc<RwLock<HashMap<usize, ProcessEntry>>>,
    next_id: Mutex<usize>,
    resource_limits: ResourceLimitsConfig,
    max_processes: usize,
}

impl ProcessTool {
    pub fn new(security: Arc<SecurityPolicy>, runtime: Arc<dyn RuntimeAdapter>) -> Self {
        Self::new_with_limits(security, runtime, None, ResourceLimitsConfig::default())
    }

    pub fn new_with_resource_limits(
        security: Arc<SecurityPolicy>,
        runtime: Arc<dyn RuntimeAdapter>,
        resource_limits: ResourceLimitsConfig,
    ) -> Self {
        Self::new_with_limits(security, runtime, None, resource_limits)
    }

    pub fn new_with_syscall_detector(
        security: Arc<SecurityPolicy>,
        runtime: Arc<dyn RuntimeAdapter>,
        syscall_detector: Option<Arc<SyscallAnomalyDetector>>,
    ) -> Self {
        Self::new_with_limits(
            security,
            runtime,
            syscall_detector,
            ResourceLimitsConfig::default(),
        )
    }

    fn new_with_limits(
        security: Arc<SecurityPolicy>,
        runtime: Arc<dyn RuntimeAdapter>,
        syscall_detector: Option<Arc<SyscallAnomalyDetector>>,
        resource_limits: ResourceLimitsConfig,
    ) -> Self {
        let max_processes = usize::try_from(resource_limits.max_subprocesses)
            .unwrap_or(DEFAULT_MAX_PROCESSES)
            .max(1);
        Self {
            security,
            runtime,
            syscall_detector,
            processes: Arc::new(RwLock::new(HashMap::new())),
            next_id: Mutex::new(0),
            resource_limits,
            max_processes,
        }
    }

    fn handle_spawn(&self, args: &serde_json::Value) -> anyhow::Result<ToolResult> {
        if !self.runtime.supports_long_running() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Runtime does not support long-running processes".into()),
            });
        }

        let command = args
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'command' parameter for spawn action"))?;

        // Check concurrent running process count.
        {
            let processes = self.processes.read().unwrap();
            let running = processes
                .values()
                .filter(|e| {
                    e.child
                        .lock()
                        .map(|mut c| matches!(c.try_wait(), Ok(None)))
                        .unwrap_or(false)
                })
                .count();
            if running >= self.max_processes {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!(
                        "Maximum concurrent processes ({}) reached",
                        self.max_processes
                    )),
                });
            }
        }

        let approved = args
            .get("approved")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Keep process tool aligned with shell tool security preflight behavior.
        if let Some(blocked_result) = action_command_preflight_for(
            self.security.as_ref(),
            ActionCommandPreflight::new("process.spawn", Some(command), approved),
        ) {
            return Ok(blocked_result);
        }

        let (command, resource_limits_warning) =
            crate::tools::resource_limits::prepare_shell_command(command, &self.resource_limits)?;

        // Build command via runtime adapter.
        let mut cmd = match self
            .runtime
            .build_shell_command(&command, &self.security.workspace_dir)
        {
            Ok(cmd) => cmd,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to build runtime command: {e}")),
                });
            }
        };

        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.env_clear();

        for var in collect_allowed_shell_env_vars(&self.security) {
            if let Ok(val) = std::env::var(&var) {
                cmd.env(&var, val);
            }
        }
        #[cfg(windows)]
        if std::env::var("HOME").is_err() {
            if let Ok(user_profile) = std::env::var("USERPROFILE") {
                cmd.env("HOME", user_profile);
            }
        }

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to spawn process: {e}")),
                });
            }
        };

        let pid = child.id().unwrap_or(0);

        // Set up background output readers.
        let stdout_buf = Arc::new(Mutex::new(OutputBuffer::default()));
        let stderr_buf = Arc::new(Mutex::new(OutputBuffer::default()));

        if let Some(stdout) = child.stdout.take() {
            spawn_reader_task(stdout, stdout_buf.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_reader_task(stderr, stderr_buf.clone());
        }

        let id = {
            let mut next = self.next_id.lock().unwrap();
            let id = *next;
            *next += 1;
            id
        };

        let entry = ProcessEntry {
            id,
            command: command.clone(),
            pid,
            started_at: Instant::now(),
            child: Mutex::new(child),
            stdout_buf,
            stderr_buf,
            analyzed_offsets: Mutex::new((0, 0)),
        };

        self.processes.write().unwrap().insert(id, entry);

        Ok(ToolResult {
            success: true,
            output: json!({
                "id": id,
                "pid": pid,
                "message": format!("Process started: {command}"),
                "resource_limits_warning": resource_limits_warning
            })
            .to_string(),
            error: None,
        })
    }

    fn handle_list(&self) -> anyhow::Result<ToolResult> {
        if let Err(e) = self
            .security
            .enforce_tool_operation(ToolOperation::Read, "process")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e),
            });
        }

        let processes = self.processes.read().unwrap();
        let mut entries = Vec::new();

        for entry in processes.values() {
            let status = match entry.child.lock() {
                Ok(mut child) => match child.try_wait() {
                    Ok(Some(status)) => {
                        format!("exited ({})", status.code().unwrap_or(-1))
                    }
                    Ok(None) => "running".to_string(),
                    Err(e) => format!("error: {e}"),
                },
                Err(_) => "unknown".to_string(),
            };

            entries.push(json!({
                "id": entry.id,
                "command": entry.command,
                "pid": entry.pid,
                "status": status,
                "uptime_secs": entry.started_at.elapsed().as_secs(),
            }));
        }

        Ok(ToolResult {
            success: true,
            output: serde_json::to_string_pretty(&entries).unwrap_or_default(),
            error: None,
        })
    }

    async fn handle_output(&self, args: &serde_json::Value) -> anyhow::Result<ToolResult> {
        const SNAPSHOT_RETRIES: usize = 20;
        const SNAPSHOT_RETRY_DELAY_MS: u64 = 50;

        if let Err(e) = self
            .security
            .enforce_tool_operation(ToolOperation::Read, "process")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e),
            });
        }

        let id = parse_id(args, "output")?;
        let mut snapshots = None;
        for _ in 0..=SNAPSHOT_RETRIES {
            let current = {
                let processes = self.processes.read().unwrap();
                let Some(entry) = processes.get(&id) else {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("No process with id {id}")),
                    });
                };
                (
                    snapshot_output_buffer(&entry.stdout_buf),
                    snapshot_output_buffer(&entry.stderr_buf),
                )
            };

            if !current.0.data.is_empty() || !current.1.data.is_empty() {
                snapshots = Some(current);
                break;
            }

            snapshots = Some(current);
            tokio::time::sleep(std::time::Duration::from_millis(SNAPSHOT_RETRY_DELAY_MS)).await;
        }

        let (stdout_snapshot, stderr_snapshot) = snapshots.expect("snapshot loop must run");
        let stdout = stdout_snapshot.data;
        let stderr = stderr_snapshot.data;

        if let Some(detector) = &self.syscall_detector {
            let processes = self.processes.read().unwrap();
            let Some(entry) = processes.get(&id) else {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("No process with id {id}")),
                });
            };

            let mut offsets = entry.analyzed_offsets.lock().unwrap();
            let stdout_delta = slice_unseen_output(
                &stdout,
                stdout_snapshot.dropped_prefix_bytes,
                &mut offsets.0,
            );
            let stderr_delta = slice_unseen_output(
                &stderr,
                stderr_snapshot.dropped_prefix_bytes,
                &mut offsets.1,
            );

            if !stdout_delta.is_empty() || !stderr_delta.is_empty() {
                let _ = detector.inspect_command_output(
                    &entry.command,
                    stdout_delta,
                    stderr_delta,
                    None,
                );
            }
        }

        Ok(ToolResult {
            success: true,
            output: json!({
                "stdout": stdout,
                "stderr": stderr,
            })
            .to_string(),
            error: None,
        })
    }

    fn handle_kill(&self, args: &serde_json::Value) -> anyhow::Result<ToolResult> {
        if let Err(e) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, "process")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e),
            });
        }

        let id = parse_id(args, "kill")?;

        let (pid, kill_result) = {
            let processes = self.processes.read().unwrap();
            let Some(entry) = processes.get(&id) else {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("No process with id {id}")),
                });
            };

            let pid = entry.pid;
            let result = entry
                .child
                .lock()
                .map_err(|_| anyhow::anyhow!("Failed to lock process {id}"))?
                .start_kill();
            (pid, result)
        };

        match kill_result {
            Ok(()) => Ok(ToolResult {
                success: true,
                output: format!("Sent termination signal to process {id} (pid {pid})"),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Failed to kill process {id} (pid {pid}): {e}")),
            }),
        }
    }
}

/// Parse the `id` field from action args, returning a usize.
fn parse_id(args: &serde_json::Value, action: &str) -> anyhow::Result<usize> {
    args.get("id")
        .and_then(|v| v.as_u64())
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(|| anyhow::anyhow!("Missing 'id' parameter for {action} action"))
}

/// Append data to a bounded buffer, draining oldest bytes when over limit.
fn append_bounded(buf: &Mutex<OutputBuffer>, new_data: &str) {
    let mut guard = buf.lock().unwrap();
    guard.data.push_str(new_data);
    if guard.data.len() > MAX_OUTPUT_BYTES {
        let excess = guard.data.len() - MAX_OUTPUT_BYTES;
        // Find the first valid char boundary at or after `excess`.
        let mut drain_to = excess;
        while drain_to < guard.data.len() && !guard.data.is_char_boundary(drain_to) {
            drain_to += 1;
        }
        guard.data.drain(..drain_to);
        guard.dropped_prefix_bytes = guard
            .dropped_prefix_bytes
            .saturating_add(u64::try_from(drain_to).unwrap_or(u64::MAX));
    }
}

/// Spawn a background task that reads from an async reader into a bounded buffer.
fn spawn_reader_task<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    mut reader: R,
    buf: Arc<Mutex<OutputBuffer>>,
) {
    tokio::spawn(async move {
        let mut chunk = vec![0u8; 8192];
        loop {
            match reader.read(&mut chunk).await {
                Ok(n) if n > 0 => {
                    let text = String::from_utf8_lossy(&chunk[..n]);
                    append_bounded(&buf, &text);
                }
                _ => break,
            }
        }
    });
}

fn snapshot_output_buffer(buf: &Mutex<OutputBuffer>) -> OutputBuffer {
    buf.lock().unwrap().clone()
}

fn slice_unseen_output<'a>(
    current: &'a str,
    dropped_prefix_bytes: u64,
    analyzed: &mut u64,
) -> &'a str {
    let len_u64 = u64::try_from(current.len()).unwrap_or(u64::MAX);
    let available_end = dropped_prefix_bytes.saturating_add(len_u64);

    let start = if *analyzed <= dropped_prefix_bytes {
        0
    } else {
        usize::try_from(analyzed.saturating_sub(dropped_prefix_bytes))
            .unwrap_or(current.len())
            .min(current.len())
    };

    let mut boundary = start;
    while boundary < current.len() && !current.is_char_boundary(boundary) {
        boundary += 1;
    }

    *analyzed = available_end;
    &current[boundary..]
}

#[async_trait]
impl Tool for ProcessTool {
    fn name(&self) -> &str {
        "process"
    }

    fn description(&self) -> &str {
        "Manage background processes: spawn long-running commands, check output, and terminate them"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["spawn", "list", "output", "kill"],
                    "description": "Action to perform: spawn a process, list all, get output, or kill"
                },
                "command": {
                    "type": "string",
                    "description": "Shell command to run in background (required for 'spawn')"
                },
                "id": {
                    "type": "integer",
                    "description": "Process ID returned by spawn (required for 'output' and 'kill')"
                },
                "approved": {
                    "type": "boolean",
                    "description": "Approve medium/high-risk commands (for 'spawn')",
                    "default": false
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("");

        match action {
            "spawn" => self.handle_spawn(&args),
            "list" => self.handle_list(),
            "output" => self.handle_output(&args).await,
            "kill" => self.handle_kill(&args),
            other => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Unknown action '{other}'. Use: spawn, list, output, kill"
                )),
            }),
        }
    }
}

impl Drop for ProcessTool {
    fn drop(&mut self) {
        if let Ok(processes) = self.processes.read() {
            for entry in processes.values() {
                if let Ok(mut child) = entry.child.lock() {
                    let _ = child.start_kill();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuditConfig, SyscallAnomalyConfig};
    use crate::runtime::NativeRuntime;
    use crate::security::policy::{parse_security_policy_block_event, CommandPolicyViolation};
    use crate::security::{AutonomyLevel, SecurityPolicy, SyscallAnomalyDetector};
    use crate::tools::{action_command_preflight_for, policy_blocked_result};
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn test_security() -> Arc<SecurityPolicy> {
        let mut policy = SecurityPolicy::default();
        policy.autonomy = AutonomyLevel::Full;
        policy.workspace_dir = std::env::temp_dir();
        #[cfg(windows)]
        policy.allowed_commands.push("Write-Output".into());
        #[cfg(windows)]
        policy.allowed_commands.push("Start-Sleep".into());
        #[cfg(not(windows))]
        policy.allowed_commands.push("sleep".into());
        Arc::new(policy)
    }

    fn test_runtime() -> Arc<dyn RuntimeAdapter> {
        Arc::new(NativeRuntime::new())
    }

    #[cfg(windows)]
    fn process_echo_command(text: &str) -> String {
        format!("Write-Output {text}")
    }

    #[cfg(not(windows))]
    fn process_echo_command(text: &str) -> String {
        format!("echo {text}")
    }

    #[cfg(windows)]
    fn process_sleep_command(seconds: u64) -> String {
        format!("Start-Sleep -Seconds {seconds}")
    }

    #[cfg(not(windows))]
    fn process_sleep_command(seconds: u64) -> String {
        format!("sleep {seconds}")
    }

    fn test_syscall_detector(tmp: &TempDir) -> Arc<SyscallAnomalyDetector> {
        let log_path = tmp.path().join("process-syscall-anomalies.log");
        let cfg = SyscallAnomalyConfig {
            baseline_syscalls: vec!["read".into(), "write".into()],
            log_path: log_path.to_string_lossy().to_string(),
            alert_cooldown_secs: 1,
            max_alerts_per_minute: 50,
            ..SyscallAnomalyConfig::default()
        };
        let audit = AuditConfig {
            enabled: false,
            ..AuditConfig::default()
        };
        Arc::new(SyscallAnomalyDetector::new(cfg, tmp.path(), audit))
    }

    fn make_tool() -> ProcessTool {
        ProcessTool::new(test_security(), test_runtime())
    }

    #[test]
    fn process_tool_name() {
        assert_eq!(make_tool().name(), "process");
    }

    #[test]
    fn process_tool_description_not_empty() {
        assert!(!make_tool().description().is_empty());
    }

    #[test]
    fn process_tool_schema_has_action() {
        let schema = make_tool().parameters_schema();
        assert!(schema["properties"]["action"].is_object());
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("action")));
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(MAX_OUTPUT_BYTES, 524_288);
        assert_eq!(DEFAULT_MAX_PROCESSES, 8);
    }

    #[test]
    fn process_tool_uses_resource_limit_for_max_processes() {
        let tool = ProcessTool::new_with_resource_limits(
            test_security(),
            test_runtime(),
            ResourceLimitsConfig {
                max_subprocesses: 3,
                ..ResourceLimitsConfig::default()
            },
        );
        assert_eq!(tool.max_processes, 3);
    }

    #[test]
    fn policy_blocked_result_renders_structured_event_fields() {
        let violation = CommandPolicyViolation::new(
            "autonomy.allowed_commands",
            "Command not allowed by security policy: curl https://evil.example",
            "curl https://evil.example",
        );
        let result = policy_blocked_result(&violation);
        assert!(!result.success);
        let event = parse_security_policy_block_event(result.error.as_deref().unwrap())
            .expect("expected structured security policy block event");
        assert_eq!(event.policy_id, "autonomy.allowed_commands");
        assert_eq!(event.command_fragment, "curl https://evil.example");
        assert!(event
            .reason
            .contains("Command not allowed by security policy"));
    }

    #[test]
    fn parse_security_policy_block_event_extracts_fields() {
        let message = "blocked by security policy: policy=autonomy.allowed_commands; command=curl https://evil.example; reason=Command not allowed by security policy: curl https://evil.example";
        let event = parse_security_policy_block_event(message)
            .expect("formatted block message should parse into structured event");
        assert_eq!(event.policy_id, "autonomy.allowed_commands");
        assert_eq!(event.command_fragment, "curl https://evil.example");
        assert!(event
            .reason
            .contains("Command not allowed by security policy"));
    }

    #[tokio::test]
    async fn spawn_starts_background_process() {
        let tool = make_tool();
        let result = tool
            .execute(json!({
                "action": "spawn",
                "command": process_echo_command("hello_process_test")
            }))
            .await
            .unwrap();
        assert!(result.success, "spawn should succeed: {:?}", result.error);
        let output: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        assert!(output["id"].is_number());
        assert!(output["pid"].is_number());
    }

    #[tokio::test]
    async fn list_shows_spawned_process() {
        let tool = make_tool();
        tool.execute(json!({
            "action": "spawn",
            "command": process_echo_command("list_test")
        }))
        .await
        .unwrap();

        let result = tool.execute(json!({"action": "list"})).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains("list_test"));
    }

    #[tokio::test]
    async fn output_returns_stdout() {
        let tool = make_tool();
        let spawn_result = tool
            .execute(json!({
                "action": "spawn",
                "command": process_echo_command("output_capture_test")
            }))
            .await
            .unwrap();

        let spawn_output: serde_json::Value = serde_json::from_str(&spawn_result.output).unwrap();
        let id = spawn_output["id"].as_u64().unwrap();

        // Wait for the process to finish and output to be captured.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let result = tool
            .execute(json!({
                "action": "output",
                "id": id
            }))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("output_capture_test"));
    }

    #[tokio::test]
    async fn kill_terminates_process() {
        let tool = make_tool();
        let spawn_result = tool
            .execute(json!({
                "action": "spawn",
                "command": process_sleep_command(60)
            }))
            .await
            .unwrap();
        assert!(spawn_result.success);

        let spawn_output: serde_json::Value = serde_json::from_str(&spawn_result.output).unwrap();
        let id = spawn_output["id"].as_u64().unwrap();

        let kill_result = tool
            .execute(json!({
                "action": "kill",
                "id": id
            }))
            .await
            .unwrap();
        assert!(kill_result.success);
    }

    #[tokio::test]
    async fn unknown_action_returns_error() {
        let tool = make_tool();
        let result = tool.execute(json!({"action": "restart"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("Unknown action"));
    }

    #[tokio::test]
    async fn spawn_blocks_disallowed_command() {
        let tool = make_tool();
        let result = tool
            .execute(json!({
                "action": "spawn",
                "command": "rm -rf /"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        let event = parse_security_policy_block_event(result.error.as_deref().unwrap())
            .expect("expected structured security policy block event");
        assert_eq!(event.policy_id, "autonomy.allowed_commands");
        assert_eq!(event.command_fragment, "rm -rf /");
        assert!(event
            .reason
            .contains("Command not allowed by security policy"));
    }

    #[tokio::test]
    async fn spawn_blocks_disallowed_command_matches_preflight_event_fields() {
        let security = test_security();
        let command = "rm -rf /";
        let preflight = action_command_preflight_for(
            security.as_ref(),
            ActionCommandPreflight::new("process.spawn", Some(command), false),
        )
        .expect("expected command preflight to block disallowed command");
        assert!(!preflight.success);
        let preflight_event = parse_security_policy_block_event(
            preflight
                .error
                .as_deref()
                .expect("preflight block should include structured error"),
        )
        .expect("preflight block should parse into structured policy event");

        let tool = ProcessTool::new(security, test_runtime());
        let spawn = tool
            .execute(json!({
                "action": "spawn",
                "command": command
            }))
            .await
            .unwrap();
        assert!(!spawn.success);
        let spawn_event = parse_security_policy_block_event(
            spawn
                .error
                .as_deref()
                .expect("spawn block should include structured error"),
        )
        .expect("spawn block should parse into structured policy event");

        assert_eq!(spawn_event.policy_id, preflight_event.policy_id);
        assert_eq!(
            spawn_event.command_fragment,
            preflight_event.command_fragment
        );
        assert_eq!(spawn_event.reason, preflight_event.reason);
    }

    #[tokio::test]
    async fn spawn_blocks_forbidden_path() {
        let tool = make_tool();
        let result = tool
            .execute(json!({
                "action": "spawn",
                "command": "cat /etc/passwd"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        let event = parse_security_policy_block_event(result.error.as_deref().unwrap())
            .expect("expected structured security policy block event");
        assert_eq!(event.policy_id, "autonomy.workspace_path_guard");
        assert_eq!(event.command_fragment, "cat /etc/passwd");
        assert!(event.reason.contains("Path blocked"));
    }

    #[tokio::test]
    async fn kill_blocks_readonly() {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            workspace_dir: std::env::temp_dir(),
            ..SecurityPolicy::default()
        });
        let tool = ProcessTool::new(security, test_runtime());
        let result = tool
            .execute(json!({
                "action": "kill",
                "id": 0
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("read-only"));
    }

    #[tokio::test]
    async fn output_missing_id_returns_error() {
        let tool = make_tool();
        let result = tool.execute(json!({"action": "output"})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn output_nonexistent_id_returns_error() {
        let tool = make_tool();
        let result = tool
            .execute(json!({
                "action": "output",
                "id": 9999
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("No process"));
    }

    #[tokio::test]
    async fn spawn_blocks_rate_limited() {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            max_actions_per_hour: 0,
            workspace_dir: std::env::temp_dir(),
            ..SecurityPolicy::default()
        });
        let tool = ProcessTool::new(security, test_runtime());
        let result = tool
            .execute(json!({
                "action": "spawn",
                "command": process_echo_command("test")
            }))
            .await
            .unwrap();
        assert!(!result.success);
        let event = parse_security_policy_block_event(result.error.as_deref().unwrap())
            .expect("expected structured security policy block event");
        assert_eq!(event.policy_id, "autonomy.max_actions_per_hour");
        assert_eq!(event.command_fragment, process_echo_command("test"));
        assert!(event.reason.contains("Rate limit exceeded"));
    }

    struct NoLongRunningRuntime;

    impl RuntimeAdapter for NoLongRunningRuntime {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn name(&self) -> &str {
            "test-restricted"
        }
        fn has_shell_access(&self) -> bool {
            true
        }
        fn has_filesystem_access(&self) -> bool {
            true
        }
        fn storage_path(&self) -> PathBuf {
            PathBuf::from("/tmp")
        }
        fn supports_long_running(&self) -> bool {
            false
        }
        fn build_shell_command(
            &self,
            command: &str,
            workspace_dir: &std::path::Path,
        ) -> anyhow::Result<tokio::process::Command> {
            let mut cmd = tokio::process::Command::new("sh");
            cmd.arg("-c").arg(command).current_dir(workspace_dir);
            Ok(cmd)
        }
    }

    #[tokio::test]
    async fn spawn_rejects_when_runtime_unsupported() {
        let tool = ProcessTool::new(test_security(), Arc::new(NoLongRunningRuntime));
        let result = tool
            .execute(json!({
                "action": "spawn",
                "command": "echo test"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("long-running"));
    }

    #[test]
    fn append_bounded_truncates_old_data() {
        let buf = Mutex::new(OutputBuffer::default());
        let data = "x".repeat(MAX_OUTPUT_BYTES + 100);
        append_bounded(&buf, &data);
        let guard = buf.lock().unwrap();
        assert!(guard.data.len() <= MAX_OUTPUT_BYTES);
        assert!(guard.dropped_prefix_bytes >= 100);
    }

    #[test]
    fn slice_unseen_output_tracks_new_tail_after_rollover() {
        let mut analyzed = u64::try_from(MAX_OUTPUT_BYTES).expect("size should fit in u64");
        let current = format!("{}tail", "x".repeat(MAX_OUTPUT_BYTES.saturating_sub(4)));
        let dropped = 4_u64;

        let delta = slice_unseen_output(&current, dropped, &mut analyzed);

        assert_eq!(delta, "tail");
        assert_eq!(
            analyzed,
            dropped.saturating_add(u64::try_from(current.len()).expect("len should fit in u64"))
        );
    }

    #[tokio::test]
    async fn process_output_runs_syscall_detector_incrementally() {
        let tmp = tempfile::tempdir().expect("temp dir should be created");
        let log_path = tmp.path().join("process-syscall-anomalies.log");
        let tool = ProcessTool::new_with_syscall_detector(
            test_security(),
            test_runtime(),
            Some(test_syscall_detector(&tmp)),
        );

        let spawn_result = tool
            .execute(json!({
                "action": "spawn",
                "command": process_echo_command("seccomp denied syscall=openat")
            }))
            .await
            .expect("spawn should return result");
        assert!(spawn_result.success);
        let spawn_output: serde_json::Value =
            serde_json::from_str(&spawn_result.output).expect("spawn output should be json");
        let id = spawn_output["id"]
            .as_u64()
            .expect("process id should exist");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let first_output = tool
            .execute(json!({"action": "output", "id": id}))
            .await
            .expect("first output should return result");
        assert!(first_output.success);

        let first_log = tokio::fs::read_to_string(&log_path)
            .await
            .expect("first anomaly log should exist");
        let first_lines = first_log.lines().count();
        assert!(first_lines >= 1);
        assert!(first_log.contains("\"kind\":\"unknown_syscall\""));

        let second_output = tool
            .execute(json!({"action": "output", "id": id}))
            .await
            .expect("second output should return result");
        assert!(second_output.success);

        let second_log = tokio::fs::read_to_string(&log_path)
            .await
            .expect("second anomaly log should still exist");
        let second_lines = second_log.lines().count();
        assert_eq!(
            second_lines, first_lines,
            "incremental offsets should prevent duplicate detector emissions for unchanged output"
        );
    }
}
