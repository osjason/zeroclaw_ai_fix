/// Unified execution progress signal for channel-visible status updates.
use crate::security::policy::{
    parse_security_policy_block_event, policy_block_config_key, summarize_command_policy_block,
    CommandPolicyViolation,
};
use crate::util::truncate_with_ellipsis;
use serde_json::Value;

#[derive(Debug)]
pub(crate) enum ExecutionSignal {
    Triggered {
        detail_label: &'static str,
        detail: String,
    },
    Running {
        status: &'static str,
    },
    Completed {
        result_preview: String,
    },
    Blocked {
        policy_id: Option<String>,
        command_preview: Option<String>,
        reason_preview: String,
    },
}

#[derive(Debug)]
pub(crate) struct ExecutionEvent<'a> {
    pub source: &'a str,
    pub id: &'a str,
    pub name: &'a str,
    pub kind: &'a str,
    pub schedule: Option<&'a str>,
    pub signal: ExecutionSignal,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ExecutionRenderContext<'a> {
    pub source: &'a str,
    pub id: &'a str,
    pub name: &'a str,
    pub kind: &'a str,
    pub schedule: Option<&'a str>,
}

impl<'a> ExecutionRenderContext<'a> {
    fn with_signal(self, signal: ExecutionSignal) -> String {
        render_execution_event(ExecutionEvent {
            source: self.source,
            id: self.id,
            name: self.name,
            kind: self.kind,
            schedule: self.schedule,
            signal,
        })
    }

    pub(crate) fn render_start_pair(
        self,
        detail_label: &'static str,
        detail: String,
        running_status: &'static str,
    ) -> [String; 2] {
        [
            self.with_signal(ExecutionSignal::Triggered {
                detail_label,
                detail,
            }),
            self.with_signal(ExecutionSignal::Running {
                status: running_status,
            }),
        ]
    }

    pub(crate) fn render_completed(self, result_preview: String) -> String {
        self.with_signal(ExecutionSignal::Completed { result_preview })
    }

    pub(crate) fn render_blocked(
        self,
        policy_id: Option<String>,
        command_preview: Option<String>,
        reason_preview: String,
    ) -> String {
        self.with_signal(ExecutionSignal::Blocked {
            policy_id,
            command_preview,
            reason_preview,
        })
    }
}

const LIFECYCLE_STATUSES: &[&str] = &[
    "blocked_by_security_policy",
    "triggered",
    "running",
    "completed",
];
const STRUCTURED_LIFECYCLE_TOKENS: &[&str] = &[
    "triggered: id=",
    "running: id=",
    "blocked: id=",
    "completed: id=",
];
const SECURITY_BLOCK_PREFIX: &str = "blocked by security policy:";

/// Whether a progress payload should be treated as high priority and remain visible
/// even when normal progress updates are throttled/filtered.
pub(crate) fn is_high_priority_progress_update(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let status = extract_status_value(lower.as_str());
    let is_policy_block_summary =
        lower.contains("security blocked (policy=") && lower.contains("command=");
    let is_structured_lifecycle = is_structured_lifecycle_progress(lower.as_str());
    let is_tool_result_progress = text.lines().any(is_tool_result_progress_line);
    let is_tool_running_progress = text.lines().any(is_tool_running_progress_line);

    is_policy_block_summary
        || status.is_some_and(is_lifecycle_status)
        || is_structured_lifecycle
        || is_tool_result_progress
        || is_tool_running_progress
}

pub(crate) fn is_structured_lifecycle_or_policy_line(line: &str) -> bool {
    let lower = line.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }

    let lifecycle_status = extract_status_value(lower.as_str()).is_some_and(is_lifecycle_status);
    let structured_stage = is_structured_lifecycle_progress(lower.as_str());
    let policy_detail = lower.contains("policy=") && lower.contains("command=");
    let blocked_reason = lower.starts_with("reason=");

    lifecycle_status || structured_stage || policy_detail || blocked_reason
}

fn is_lifecycle_status(status: &str) -> bool {
    LIFECYCLE_STATUSES.contains(&status) || is_running_status_hint(status)
}

fn is_running_status_hint(status: &str) -> bool {
    status.contains("now executing")
}

fn is_structured_lifecycle_progress(text: &str) -> bool {
    STRUCTURED_LIFECYCLE_TOKENS
        .iter()
        .any(|token| text.contains(token))
}

fn extract_status_value(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix("status=")
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    })
}

fn is_tool_result_progress_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    let rest = if let Some(rest) = trimmed.strip_prefix('✅') {
        rest
    } else if let Some(rest) = trimmed.strip_prefix('❌') {
        rest
    } else {
        return false;
    };

    let body = rest.trim_start();
    body.contains('(') && (body.contains("s)") || body.contains("s):"))
}

fn is_tool_running_progress_line(line: &str) -> bool {
    line.trim_start()
        .strip_prefix('⏳')
        .is_some_and(|body| !body.trim().is_empty())
}

pub(crate) fn render_execution_event(event: ExecutionEvent<'_>) -> String {
    let source = event.source;
    let id = event.id;
    let name = event.name;
    let kind = event.kind;

    match event.signal {
        ExecutionSignal::Triggered {
            detail_label,
            detail,
        } => {
            let schedule = event.schedule.unwrap_or("unknown");
            format!(
                "⏱️ {source} triggered: id={id} name={name} type={kind}\nschedule={schedule}\n{detail_label}={detail}\nstatus=triggered"
            )
        }
        ExecutionSignal::Running { status } => {
            format!("▶️ {source} running: id={id} name={name} type={kind}\nstatus={status}")
        }
        ExecutionSignal::Completed { result_preview } => {
            let schedule_line = event
                .schedule
                .map(|schedule| format!("schedule={schedule}\n"))
                .unwrap_or_default();
            format!(
                "✅ {source} completed: id={id} name={name} type={kind}\n{schedule_line}result={result_preview}\nstatus=completed"
            )
        }
        ExecutionSignal::Blocked {
            policy_id,
            command_preview,
            reason_preview,
        } => {
            let schedule_line = event
                .schedule
                .map(|schedule| format!("schedule={schedule}\n"))
                .unwrap_or_default();

            if let (Some(policy_id), Some(command_preview)) = (policy_id, command_preview) {
                format!(
                    "🚫 {source} blocked: id={id} name={name} type={kind}\n{schedule_line}policy={policy_id}; command={command_preview}\nstatus=blocked_by_security_policy\nreason={reason_preview}"
                )
            } else {
                format!(
                    "🚫 {source} blocked: id={id} name={name} type={kind}\n{schedule_line}status=blocked_by_security_policy\nreason={reason_preview}"
                )
            }
        }
    }
}

pub(crate) fn render_execution_start_pair(
    source: &str,
    id: &str,
    name: &str,
    kind: &str,
    schedule: &str,
    detail_label: &'static str,
    detail: String,
    running_status: &'static str,
) -> [String; 2] {
    ExecutionRenderContext {
        source,
        id,
        name,
        kind,
        schedule: Some(schedule),
    }
    .render_start_pair(detail_label, detail, running_status)
}

pub(crate) fn render_execution_completed(
    source: &str,
    id: &str,
    name: &str,
    kind: &str,
    schedule: Option<&str>,
    result_preview: String,
) -> String {
    ExecutionRenderContext {
        source,
        id,
        name,
        kind,
        schedule,
    }
    .render_completed(result_preview)
}

pub(crate) fn render_execution_blocked(
    source: &str,
    id: &str,
    name: &str,
    kind: &str,
    schedule: Option<&str>,
    policy_id: Option<String>,
    command_preview: Option<String>,
    reason_preview: String,
) -> String {
    ExecutionRenderContext {
        source,
        id,
        name,
        kind,
        schedule,
    }
    .render_blocked(policy_id, command_preview, reason_preview)
}

#[derive(Debug)]
pub(crate) struct PolicyBlockedExecutionRender<'a> {
    pub source: &'a str,
    pub id: &'a str,
    pub name: &'a str,
    pub kind: &'a str,
    pub schedule: Option<&'a str>,
    pub raw_reason: &'a str,
    pub fallback_policy_id: Option<&'a str>,
    pub fallback_command: Option<&'a str>,
    pub default_reason: &'a str,
    pub default_reason_for_unstructured: bool,
    pub command_max_chars: usize,
    pub reason_max_chars: usize,
}

pub(crate) fn render_policy_blocked_execution_event(
    input: PolicyBlockedExecutionRender<'_>,
) -> Option<String> {
    let context = ExecutionRenderContext {
        source: input.source,
        id: input.id,
        name: input.name,
        kind: input.kind,
        schedule: input.schedule,
    };
    let trimmed = input.raw_reason.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(event) = parse_security_policy_block_event(trimmed) {
        let reason = if event.reason.trim().is_empty() {
            input.default_reason.to_string()
        } else {
            truncate_with_ellipsis(event.reason, input.reason_max_chars)
        };
        return Some(context.render_blocked(
            Some(event.policy_id.to_string()),
            Some(truncate_with_ellipsis(
                event.command_fragment,
                input.command_max_chars,
            )),
            reason,
        ));
    }

    let raw_fallback_reason = truncate_with_ellipsis(trimmed, input.reason_max_chars);
    let reason = if input.default_reason_for_unstructured && !input.default_reason.trim().is_empty()
    {
        input.default_reason.to_string()
    } else if raw_fallback_reason.is_empty() {
        input.default_reason.to_string()
    } else {
        raw_fallback_reason
    };
    Some(context.render_blocked(
        input.fallback_policy_id.map(str::to_string),
        input
            .fallback_command
            .map(|command| truncate_with_ellipsis(command, input.command_max_chars)),
        reason,
    ))
}

pub(crate) fn render_tool_policy_block_progress_detail(
    tool_name: &str,
    reason: &str,
) -> Option<String> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return None;
    }
    render_policy_blocked_execution_event(PolicyBlockedExecutionRender {
        source: "Agent",
        id: tool_name,
        name: tool_name,
        kind: "tool",
        schedule: None,
        raw_reason: trimmed,
        fallback_policy_id: None,
        fallback_command: None,
        default_reason: "Command blocked by security policy.",
        default_reason_for_unstructured: false,
        command_max_chars: 72,
        reason_max_chars: 120,
    })
}

fn extract_summary_field<'a>(summary: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("{key}=");
    let start = summary.find(&marker)?;
    let value_start = start + marker.len();
    let value = summary[value_start..]
        .split(';')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some(value)
}

pub(crate) fn render_tool_policy_block_progress_summary(
    tool_name: &str,
    reason: &str,
) -> Option<String> {
    let mut detail = render_tool_policy_block_progress_detail(tool_name, reason)?;
    if let Some(summary) = summarize_command_policy_block(reason, 72) {
        if !detail.contains("policy=") {
            if let Some(policy) = extract_summary_field(&summary, "policy") {
                detail.push(' ');
                detail.push_str("policy=");
                detail.push_str(policy);
            }
        }
        if !detail.contains("command=") {
            if let Some(command) = extract_summary_field(&summary, "command") {
                detail.push_str("; command=");
                detail.push_str(command);
            }
        }
        if !detail.contains("config_key=") {
            if let Some(config_key) = extract_summary_field(&summary, "config_key") {
                detail.push_str("; config_key=");
                detail.push_str(config_key);
            }
        }
    }

    if !detail.contains("policy=") {
        detail.push_str(" policy=unknown");
    }
    if !detail.contains("command=") {
        detail.push_str("; command=");
        detail.push_str(tool_name);
    }
    if !detail.contains("config_key=") {
        detail.push_str("; config_key=unknown");
    }

    Some(detail)
}

pub(crate) fn summarize_tool_policy_block_progress(
    tool_name: &str,
    reason: Option<&str>,
) -> Option<String> {
    reason.and_then(|raw| render_tool_policy_block_progress_summary(tool_name, raw))
}

pub(crate) fn format_tool_policy_block_event_message(
    policy_id: &'static str,
    reason: impl Into<String>,
    tool_name: &str,
    tool_hint: Option<&str>,
) -> String {
    let command_fragment = tool_hint
        .map(str::trim)
        .filter(|hint| !hint.is_empty())
        .map(|hint| format!("{tool_name} {hint}"))
        .unwrap_or_else(|| tool_name.to_string());
    format_policy_block_event_message(policy_id, reason, Some(&command_fragment))
}

pub(crate) fn truncate_tool_args_for_progress(
    tool_name: &str,
    tool_args: &Value,
    max_len: usize,
) -> String {
    let hint = match tool_name {
        "shell" => tool_args.get("command").and_then(|v| v.as_str()),
        "file_read" | "file_write" => tool_args.get("path").and_then(|v| v.as_str()),
        "composio_execute" => tool_args.get("action_name").and_then(|v| v.as_str()),
        "memory_recall" => tool_args.get("query").and_then(|v| v.as_str()),
        "memory_store" => tool_args.get("key").and_then(|v| v.as_str()),
        "web_search" => tool_args.get("query").and_then(|v| v.as_str()),
        "http_request" => tool_args.get("url").and_then(|v| v.as_str()),
        "browser_navigate" | "browser_screenshot" | "browser_click" | "browser_type" => {
            tool_args.get("url").and_then(|v| v.as_str())
        }
        _ => tool_args
            .get("action")
            .and_then(|v| v.as_str())
            .or_else(|| tool_args.get("query").and_then(|v| v.as_str())),
    };
    match hint {
        Some(raw) => truncate_with_ellipsis(raw, max_len),
        None => String::new(),
    }
}

pub(crate) fn format_tool_policy_block_event_from_args(
    policy_id: &'static str,
    reason: impl Into<String>,
    tool_name: &str,
    tool_args: &Value,
    hint_max_chars: usize,
) -> String {
    let hint = truncate_tool_args_for_progress(tool_name, tool_args, hint_max_chars);
    let hint = (!hint.is_empty()).then_some(hint.as_str());
    format_tool_policy_block_event_message(policy_id, reason, tool_name, hint)
}

pub(crate) fn render_cron_policy_blocked_result(
    id: &str,
    name: &str,
    kind: &str,
    schedule: Option<&str>,
    raw_reason: &str,
    fallback_command: &str,
    command_max_chars: usize,
    reason_max_chars: usize,
) -> Option<String> {
    render_policy_blocked_execution_event(PolicyBlockedExecutionRender {
        source: "Cron",
        id,
        name,
        kind,
        schedule,
        raw_reason,
        fallback_policy_id: Some("autonomy.unknown"),
        fallback_command: Some(fallback_command),
        default_reason: "blocked by security policy",
        default_reason_for_unstructured: true,
        command_max_chars,
        reason_max_chars,
    })
}

pub(crate) fn render_cron_start_announcements(
    id: &str,
    name: &str,
    kind: &str,
    schedule: &str,
    detail_label: &'static str,
    detail: String,
    running_status: &'static str,
) -> [String; 2] {
    render_execution_start_pair(
        "Cron",
        id,
        name,
        kind,
        schedule,
        detail_label,
        detail,
        running_status,
    )
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CronLifecycleAnnouncementRenderContext<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub kind: &'a str,
    pub schedule: &'a str,
    pub detail_label: &'static str,
    pub running_status: &'static str,
    pub blocked_subject: &'a str,
}

impl<'a> CronLifecycleAnnouncementRenderContext<'a> {
    pub(crate) fn render_start_announcements(self, detail: String) -> [String; 2] {
        render_cron_start_announcements(
            self.id,
            self.name,
            self.kind,
            self.schedule,
            self.detail_label,
            detail,
            self.running_status,
        )
    }

    pub(crate) fn render_result_announcement(
        self,
        success: bool,
        output: &str,
        output_preview: String,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Option<String> {
        render_cron_result_announcement(
            self.id,
            self.name,
            self.kind,
            self.schedule,
            success,
            output,
            output_preview,
            self.blocked_subject,
            command_max_chars,
            reason_max_chars,
        )
    }
}

pub(crate) fn render_cron_result_announcement(
    id: &str,
    name: &str,
    kind: &str,
    schedule: &str,
    success: bool,
    output: &str,
    output_preview: String,
    blocked_subject: &str,
    command_max_chars: usize,
    reason_max_chars: usize,
) -> Option<String> {
    if success {
        return Some(render_execution_completed(
            "Cron",
            id,
            name,
            kind,
            Some(schedule),
            output_preview,
        ));
    }

    let block_message = extract_embedded_security_block_message(output)?;
    render_cron_policy_blocked_result(
        id,
        name,
        kind,
        Some(schedule),
        block_message,
        blocked_subject,
        command_max_chars,
        reason_max_chars,
    )
}

pub(crate) fn render_policy_block_constraint_summary(
    reason: &str,
    max_command_chars: usize,
) -> Option<String> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return None;
    }

    summarize_command_policy_block(trimmed, max_command_chars)
        .map(|summary| format!("security blocked ({summary})"))
}

pub(crate) fn render_policy_block_constraint_summary_with_config_key(
    reason: &str,
    max_command_chars: usize,
) -> Option<String> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(event) = parse_security_policy_block_event(trimmed) {
        let command = truncate_with_ellipsis(event.command_fragment, max_command_chars);
        let config_key = policy_block_config_key(event.policy_id).unwrap_or(event.policy_id);
        return Some(format!(
            "security blocked (policy={}; command={command}; config_key={config_key})",
            event.policy_id
        ));
    }

    render_policy_block_constraint_summary(trimmed, max_command_chars)
}

pub(crate) fn extract_embedded_security_block_message(output: &str) -> Option<&str> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let offset = lower.find(SECURITY_BLOCK_PREFIX)?;
    Some(trimmed[offset..].trim())
}

pub(crate) fn format_policy_block_event_message(
    policy_id: &'static str,
    reason: impl Into<String>,
    command_fragment: Option<&str>,
) -> String {
    CommandPolicyViolation::from_block_event(policy_id, reason, command_fragment)
        .format_block_message()
}

#[cfg(test)]
mod tests {
    use super::{
        extract_embedded_security_block_message, is_high_priority_progress_update,
        render_policy_block_constraint_summary,
    };

    #[test]
    fn high_priority_progress_detects_policy_block_summary() {
        let summary =
            "❌ shell (0.2s): security blocked (policy=autonomy.allowed_commands; command=cat /etc/passwd)";
        assert!(is_high_priority_progress_update(summary));
    }

    #[test]
    fn high_priority_progress_detects_structured_cron_lifecycle_lines() {
        let triggered = "⏱️ Cron triggered: id=job1 name=nightly type=shell\nschedule=every(1000ms)\ncommand=echo ok\nstatus=triggered";
        let running =
            "▶️ Cron running: id=job1 name=nightly type=shell\nstatus=shell command is now executing";
        let blocked_without_status = "🚫 Cron blocked: id=job1 name=nightly type=shell\nschedule=every(1000ms)\npolicy=autonomy.allowed_commands; command=curl https://evil.example";
        assert!(is_high_priority_progress_update(triggered));
        assert!(is_high_priority_progress_update(running));
        assert!(is_high_priority_progress_update(blocked_without_status));
    }

    #[test]
    fn high_priority_progress_detects_structured_lifecycle_lines_without_source_prefix() {
        let triggered = "triggered: id=job1 name=nightly type=shell\nstatus=triggered";
        let running =
            "running: id=job1 name=nightly type=shell\nstatus=shell command is now executing";
        let blocked = "blocked: id=job1 name=nightly type=shell\npolicy=autonomy.allowed_commands; command=curl https://evil.example";
        assert!(is_high_priority_progress_update(triggered));
        assert!(is_high_priority_progress_update(running));
        assert!(is_high_priority_progress_update(blocked));
    }

    #[test]
    fn high_priority_progress_detects_status_only_lifecycle_markers() {
        assert!(is_high_priority_progress_update(
            "status=triggered\nreason=cron scheduling completed"
        ));
        assert!(is_high_priority_progress_update(
            "status=running\nreason=cron execution in progress"
        ));
        assert!(is_high_priority_progress_update(
            "status=blocked_by_security_policy\nreason=command denied"
        ));
        assert!(!is_high_priority_progress_update(
            "status=ok\nreason=regular summary"
        ));
        assert!(is_high_priority_progress_update(
            "status=shell command is now executing\nreason=cron execution in progress"
        ));
    }

    #[test]
    fn high_priority_progress_detects_structured_completed_line() {
        let completed = "✅ Cron completed: id=job1 name=nightly type=shell\nstatus=completed";
        assert!(is_high_priority_progress_update(completed));
    }

    #[test]
    fn high_priority_progress_detects_tool_result_lines() {
        assert!(is_high_priority_progress_update("✅ shell (1s)"));
        assert!(is_high_priority_progress_update(
            "❌ shell (0s): command timed out"
        ));
    }

    #[test]
    fn high_priority_progress_detects_running_tool_lines() {
        assert!(is_high_priority_progress_update("⏳ shell: ls -la"));
        assert!(is_high_priority_progress_update(
            "⏳ file_read: src/main.rs"
        ));
        assert!(!is_high_priority_progress_update("⏳"));
    }

    #[test]
    fn render_policy_block_constraint_summary_extracts_policy_and_command() {
        let raw = "blocked by security policy: policy=autonomy.allowed_commands; command=curl https://evil.example; reason=Command not allowed by security policy: curl https://evil.example";
        let summary = render_policy_block_constraint_summary(raw, 64)
            .expect("policy block summary should be rendered");
        assert!(summary.contains("policy=autonomy.allowed_commands"));
        assert!(summary.contains("command=curl https://evil.example"));
    }

    #[test]
    fn extract_embedded_security_block_message_finds_inline_reason() {
        let output = "agent job failed: blocked by security policy: policy=autonomy.allowed_commands; command=curl https://evil.example";
        let extracted = extract_embedded_security_block_message(output)
            .expect("should extract embedded security block reason");
        assert_eq!(
            extracted,
            "blocked by security policy: policy=autonomy.allowed_commands; command=curl https://evil.example"
        );
    }
}
