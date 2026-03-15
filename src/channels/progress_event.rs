/// Unified execution progress signal for channel-visible status updates.
use crate::security::policy::{
    parse_security_policy_block_event, summarize_command_policy_block, CommandPolicyViolation,
    PolicyBlockMetadata,
};
use crate::util::truncate_with_ellipsis;
use serde_json::Value;
use std::fmt::Write;

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

/// Whether a progress payload should force a continuation message instead of
/// editing the root draft in place.
pub(crate) fn should_force_draft_continuation(text: &str) -> bool {
    is_high_priority_progress_update(text)
}

pub(crate) fn upsert_progress_section(
    accumulated: &mut String,
    block: &str,
    start_marker: &str,
    end_marker: &str,
) {
    let section = format!("{start_marker}{block}{end_marker}");
    if let Some(start) = accumulated.find(start_marker) {
        if let Some(end_offset) = accumulated[start..].find(end_marker) {
            let end = start + end_offset + end_marker.len();
            accumulated.replace_range(start..end, &section);
            return;
        }
    }
    accumulated.push_str(&section);
}

pub(crate) fn strip_progress_section_markers(
    text: &str,
    start_marker: &str,
    end_marker: &str,
) -> String {
    text.replace(start_marker, "").replace(end_marker, "")
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

pub(crate) fn render_tool_progress_running_line(tool_name: &str, hint: &str) -> String {
    let mut line = String::new();
    let _ = write!(line, "⏳ {tool_name}");
    if !hint.is_empty() {
        let _ = write!(line, ": {hint}");
    }
    line
}

pub(crate) fn render_tool_progress_completed_line(
    tool_name: &str,
    secs: u64,
    success: bool,
    detail: Option<&str>,
) -> String {
    let mut line = String::new();
    let mark = if success { "✅" } else { "❌" };
    let _ = write!(line, "{mark} {tool_name} ({secs}s)");
    if !success {
        if let Some(detail) = detail {
            if !detail.is_empty() {
                let _ = write!(line, ": {detail}");
            }
        }
    }
    line
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

#[derive(Clone, Copy, Debug)]
struct PolicyBlockedExecutionPreset<'a> {
    fallback_policy_id: Option<&'a str>,
    fallback_command: Option<&'a str>,
    default_reason: &'a str,
    default_reason_for_unstructured: bool,
    command_max_chars: usize,
    reason_max_chars: usize,
}

fn render_policy_blocked_execution_with_preset(
    context: ExecutionRenderContext<'_>,
    raw_reason: &str,
    preset: PolicyBlockedExecutionPreset<'_>,
) -> Option<String> {
    render_policy_blocked_execution_event(PolicyBlockedExecutionRender {
        source: context.source,
        id: context.id,
        name: context.name,
        kind: context.kind,
        schedule: context.schedule,
        raw_reason,
        fallback_policy_id: preset.fallback_policy_id,
        fallback_command: preset.fallback_command,
        default_reason: preset.default_reason,
        default_reason_for_unstructured: preset.default_reason_for_unstructured,
        command_max_chars: preset.command_max_chars,
        reason_max_chars: preset.reason_max_chars,
    })
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

    if let Some(metadata) =
        PolicyBlockMetadata::from_message(trimmed, input.command_max_chars, input.reason_max_chars)
    {
        let reason = if metadata.reason_preview.trim().is_empty() {
            input.default_reason.to_string()
        } else {
            metadata.reason_preview
        };
        return Some(context.render_blocked(
            Some(metadata.policy_id),
            Some(metadata.command_preview),
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
    Some(
        context.render_blocked(
            input.fallback_policy_id.map(str::to_string),
            input
                .fallback_command
                .map(|command| truncate_with_ellipsis(command, input.command_max_chars)),
            reason,
        ),
    )
}

pub(crate) fn render_tool_policy_block_progress_detail(
    tool_name: &str,
    reason: &str,
) -> Option<String> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return None;
    }
    render_policy_blocked_execution_with_preset(
        ExecutionRenderContext {
            source: "Agent",
            id: tool_name,
            name: tool_name,
            kind: "tool",
            schedule: None,
        },
        trimmed,
        PolicyBlockedExecutionPreset {
            fallback_policy_id: None,
            fallback_command: None,
            default_reason: "Command blocked by security policy.",
            default_reason_for_unstructured: false,
            command_max_chars: 72,
            reason_max_chars: 120,
        },
    )
}

fn append_detail_field_if_missing(detail: &mut String, key: &str, value: &str) {
    let expected = format!("{key}={value}");
    if detail.contains(&expected) {
        return;
    }

    let separator = if detail.contains(&format!("{key}=")) {
        "; "
    } else if detail.contains(' ') {
        " "
    } else {
        "; "
    };
    detail.push_str(separator);
    detail.push_str(expected.as_str());
}

fn parse_policy_block_metadata(reason: &str, command_max_chars: usize) -> Option<PolicyBlockMetadata> {
    PolicyBlockMetadata::from_message(reason, command_max_chars, 120)
}

fn append_policy_block_metadata_detail(detail: &mut String, metadata: &PolicyBlockMetadata) {
    append_detail_field_if_missing(detail, "policy", &metadata.policy_id);
    append_detail_field_if_missing(detail, "command", &metadata.command_preview);
    append_detail_field_if_missing(detail, "config_key", &metadata.config_key);
    if let Some(rule_index) = metadata.rule_index.as_deref() {
        append_detail_field_if_missing(detail, "rule_index", rule_index);
    }
    if let Some(segment_command) = metadata.segment_command.as_deref() {
        append_detail_field_if_missing(detail, "segment_command", segment_command);
    }
    if let Some(command_context) = metadata.command_context.as_deref() {
        append_detail_field_if_missing(detail, "command_context", command_context);
    }
}

fn append_policy_block_command_context_guidance(
    guidance: &mut String,
    metadata: &PolicyBlockMetadata,
    max_context_chars: usize,
) {
    let Some(command_context) = metadata.command_context.as_deref() else {
        return;
    };
    let compact_context = truncate_with_ellipsis(command_context, max_context_chars);
    if compact_context.is_empty() || guidance.contains("command_context=") {
        return;
    }

    if let Some((summary, guidance_suffix)) = guidance.split_once(" Guidance:") {
        *guidance = format!("{summary}; command_context={compact_context} Guidance:{guidance_suffix}");
    } else {
        guidance.push_str("; command_context=");
        guidance.push_str(&compact_context);
    }
}

fn render_tool_policy_block_progress_summary_with_metadata(
    tool_name: &str,
    reason: &str,
    metadata: Option<&PolicyBlockMetadata>,
) -> Option<String> {
    let mut detail = render_tool_policy_block_progress_detail(tool_name, reason)?;
    if let Some(metadata) = metadata {
        append_policy_block_metadata_detail(&mut detail, metadata);
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

pub(crate) fn render_tool_policy_block_progress_summary(
    tool_name: &str,
    reason: &str,
) -> Option<String> {
    let metadata = parse_policy_block_metadata(reason, 72);
    render_tool_policy_block_progress_summary_with_metadata(tool_name, reason, metadata.as_ref())
}

pub(crate) fn summarize_tool_policy_block_progress(
    tool_name: &str,
    reason: Option<&str>,
) -> Option<String> {
    reason.and_then(|raw| render_tool_policy_block_progress_summary(tool_name, raw))
}

pub(crate) fn summarize_tool_policy_block_progress_from_reasons<'a, I>(
    tool_name: &str,
    reasons: I,
) -> Option<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = Vec::new();
    for reason in reasons {
        let trimmed = reason.trim();
        if trimmed.is_empty() || seen.contains(&trimmed) {
            continue;
        }
        seen.push(trimmed);
        if let Some(detail) = summarize_tool_policy_block_progress(tool_name, Some(trimmed)) {
            return Some(detail);
        }
    }
    None
}

fn summarize_structured_tool_policy_block_progress_from_reasons<'a, I>(
    tool_name: &str,
    reasons: I,
) -> Option<String>
where
    I: IntoIterator<Item = &'a str>,
{
    summarize_tool_policy_block_progress_from_reasons(
        tool_name,
        reasons
            .into_iter()
            .filter(|reason| parse_security_policy_block_event(reason.trim()).is_some()),
    )
}

pub(crate) fn policy_block_reason_candidates_from_outcome_fields<'a>(
    error_reason: Option<&'a str>,
    output: &'a str,
) -> Vec<&'a str> {
    let mut reasons = Vec::new();

    if let Some(reason) = error_reason {
        let trimmed = reason.trim();
        if !trimmed.is_empty() {
            reasons.push(trimmed);
        }
    }

    let trimmed_output = output.trim();
    if !trimmed_output.is_empty()
        && render_policy_block_constraint_summary_with_config_key(trimmed_output, 48).is_some()
        && !reasons.contains(&trimmed_output)
    {
        reasons.push(trimmed_output);
    }

    if let Some(embedded) = extract_embedded_security_block_message(output) {
        let trimmed = embedded.trim();
        if !trimmed.is_empty() && !reasons.contains(&trimmed) {
            reasons.push(trimmed);
        }
    }

    reasons
}

pub(crate) fn summarize_tool_policy_block_progress_from_outcome_fields(
    tool_name: &str,
    error_reason: Option<&str>,
    output: &str,
) -> Option<String> {
    summarize_tool_policy_block_progress_from_reasons(
        tool_name,
        policy_block_reason_candidates_from_outcome_fields(error_reason, output),
    )
}

pub(crate) fn summarize_tool_policy_block_progress_from_outcome(
    tool_name: &str,
    error_reason: Option<&str>,
    output: &str,
) -> Option<String> {
    if let Some(detail) = summarize_structured_tool_policy_block_progress_from_reasons(
        tool_name,
        [
            error_reason,
            extract_embedded_security_block_message(output),
        ]
        .into_iter()
        .flatten(),
    ) {
        return Some(detail);
    }

    summarize_tool_policy_block_progress_from_outcome_fields(tool_name, error_reason, output)
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

pub(crate) fn render_tool_policy_block_progress_summary_from_parts(
    policy_id: &'static str,
    reason: impl Into<String>,
    tool_name: &str,
    tool_hint: Option<&str>,
) -> Option<String> {
    let blocked = format_tool_policy_block_event_message(policy_id, reason, tool_name, tool_hint);
    render_tool_policy_block_progress_summary(tool_name, &blocked)
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

fn sanitize_policy_block_context_value(raw: &str) -> String {
    raw.trim()
        .replace(['\r', '\n'], " ")
        .replace(';', ",")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn ensure_policy_block_reason_has_command_context(
    reason: impl Into<String>,
    tool_name: &str,
    tool_args: &Value,
    hint_max_chars: usize,
) -> String {
    let reason = reason.into();
    let trimmed = reason.trim();
    if trimmed.contains("command_context=") {
        return trimmed.to_string();
    }

    let hint = truncate_tool_args_for_progress(tool_name, tool_args, hint_max_chars);
    let hint = sanitize_policy_block_context_value(&hint);
    let mut command_context = format!("tool={tool_name}");
    if !hint.is_empty() {
        command_context.push_str(", hint=");
        command_context.push_str(&hint);
    }

    if trimmed.is_empty() {
        return format!("command_context={command_context}");
    }
    format!("{trimmed}; command_context={command_context}")
}

pub(crate) fn format_tool_policy_block_event_from_args_with_context(
    policy_id: &'static str,
    reason: impl Into<String>,
    tool_name: &str,
    tool_args: &Value,
    hint_max_chars: usize,
) -> String {
    let reason = ensure_policy_block_reason_has_command_context(
        reason,
        tool_name,
        tool_args,
        hint_max_chars,
    );
    format_tool_policy_block_event_from_args(
        policy_id,
        reason,
        tool_name,
        tool_args,
        hint_max_chars,
    )
}

#[derive(Debug, Clone)]
pub(crate) struct ToolPolicyBlockTrace {
    pub blocked: String,
    pub progress_summary: Option<String>,
    pub policy_id: String,
    pub command: String,
    pub config_key: String,
    pub command_context: Option<String>,
}

pub(crate) fn format_tool_policy_block_event_from_args_with_context_and_trace(
    policy_id: &'static str,
    reason: impl Into<String>,
    tool_name: &str,
    tool_args: &Value,
    hint_max_chars: usize,
) -> ToolPolicyBlockTrace {
    let blocked = format_tool_policy_block_event_from_args_with_context(
        policy_id,
        reason,
        tool_name,
        tool_args,
        hint_max_chars,
    );
    let metadata = parse_policy_block_metadata(&blocked, hint_max_chars);
    let progress_summary = render_tool_policy_block_progress_summary_with_metadata(
        tool_name,
        &blocked,
        metadata.as_ref(),
    );
    if let Some(metadata) = metadata {
        return ToolPolicyBlockTrace {
            blocked,
            progress_summary,
            policy_id: metadata.policy_id,
            command: metadata.command_preview,
            config_key: metadata.config_key,
            command_context: metadata.command_context,
        };
    }

    ToolPolicyBlockTrace {
        blocked,
        progress_summary,
        policy_id: "unknown".to_string(),
        command: "unknown".to_string(),
        config_key: "unknown".to_string(),
        command_context: None,
    }
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
    render_policy_blocked_execution_with_preset(
        ExecutionRenderContext {
            source: "Cron",
            id,
            name,
            kind,
            schedule,
        },
        raw_reason,
        PolicyBlockedExecutionPreset {
            fallback_policy_id: Some("autonomy.unknown"),
            fallback_command: Some(fallback_command),
            default_reason: "blocked by security policy",
            default_reason_for_unstructured: true,
            command_max_chars,
            reason_max_chars,
        },
    )
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

pub(crate) fn build_cron_lifecycle_render_context<'a>(
    id: &'a str,
    name: &'a str,
    kind: &'a str,
    schedule: &'a str,
    detail_label: &'static str,
    running_status: &'static str,
    blocked_subject: &'a str,
) -> CronLifecycleAnnouncementRenderContext<'a> {
    CronLifecycleAnnouncementRenderContext {
        id,
        name,
        kind,
        schedule,
        detail_label,
        running_status,
        blocked_subject,
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CronLifecyclePreset<'a> {
    Agent { prompt: &'a str },
    Shell { command: &'a str },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CronLifecyclePresetDetails<'a> {
    pub kind: &'static str,
    pub detail_label: &'static str,
    pub detail_text: &'a str,
    pub running_status: &'static str,
    pub blocked_subject: &'a str,
}

pub(crate) fn cron_lifecycle_preset_details(
    preset: CronLifecyclePreset<'_>,
) -> CronLifecyclePresetDetails<'_> {
    match preset {
        CronLifecyclePreset::Agent { prompt } => {
            let blocked_subject = if prompt.trim().is_empty() {
                "<agent-task>"
            } else {
                prompt
            };
            CronLifecyclePresetDetails {
                kind: "agent",
                detail_label: "agent_task",
                detail_text: prompt,
                running_status: "agent is now executing",
                blocked_subject,
            }
        }
        CronLifecyclePreset::Shell { command } => CronLifecyclePresetDetails {
            kind: "shell",
            detail_label: "command",
            detail_text: command,
            running_status: "shell command is now executing",
            blocked_subject: command,
        },
    }
}

pub(crate) fn build_cron_lifecycle_render_context_with_preset<'a>(
    id: &'a str,
    name: &'a str,
    schedule: &'a str,
    preset: CronLifecyclePreset<'a>,
) -> (
    CronLifecycleAnnouncementRenderContext<'a>,
    CronLifecyclePresetDetails<'a>,
) {
    let details = cron_lifecycle_preset_details(preset);
    let context = build_cron_lifecycle_render_context(
        id,
        name,
        details.kind,
        schedule,
        details.detail_label,
        details.running_status,
        details.blocked_subject,
    );
    (context, details)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CronLifecycleDescriptor<'a> {
    Agent { prompt: Option<&'a str> },
    Shell { command: &'a str },
}

pub(crate) fn build_cron_lifecycle_announcement_builder<'a>(
    id: &'a str,
    name: &'a str,
    schedule: &'a str,
    descriptor: CronLifecycleDescriptor<'a>,
) -> CronLifecycleAnnouncementBuilder<'a> {
    let preset = match descriptor {
        CronLifecycleDescriptor::Agent { prompt } => CronLifecyclePreset::Agent {
            prompt: prompt.unwrap_or(""),
        },
        CronLifecycleDescriptor::Shell { command } => CronLifecyclePreset::Shell { command },
    };
    CronLifecycleAnnouncementBuilder::new(id, name, schedule, preset)
}

pub(crate) fn render_cron_start_announcements_with_preset(
    id: &str,
    name: &str,
    schedule: &str,
    preset: CronLifecyclePreset<'_>,
    detail_max_chars: usize,
) -> [String; 2] {
    let (context, details) =
        build_cron_lifecycle_render_context_with_preset(id, name, schedule, preset);
    let detail = compact_progress_preview(details.detail_text, detail_max_chars);
    context.render_start_announcements(detail)
}

pub(crate) fn render_cron_result_announcement_with_preset(
    id: &str,
    name: &str,
    schedule: &str,
    preset: CronLifecyclePreset<'_>,
    success: bool,
    output: &str,
    output_preview_max_chars: usize,
    command_max_chars: usize,
    reason_max_chars: usize,
) -> Option<String> {
    let (context, _) = build_cron_lifecycle_render_context_with_preset(id, name, schedule, preset);
    context.render_result_announcement(
        success,
        output,
        compact_progress_preview(output, output_preview_max_chars),
        command_max_chars,
        reason_max_chars,
    )
}

pub(crate) fn render_cron_start_announcements_with_descriptor(
    id: &str,
    name: &str,
    schedule: &str,
    descriptor: CronLifecycleDescriptor<'_>,
    detail_max_chars: usize,
) -> [String; 2] {
    build_cron_lifecycle_announcement_builder(id, name, schedule, descriptor)
        .render_start_announcements(detail_max_chars)
}

pub(crate) fn render_cron_result_announcement_with_descriptor(
    id: &str,
    name: &str,
    schedule: &str,
    descriptor: CronLifecycleDescriptor<'_>,
    success: bool,
    output: &str,
    output_preview_max_chars: usize,
    command_max_chars: usize,
    reason_max_chars: usize,
) -> Option<String> {
    build_cron_lifecycle_announcement_builder(id, name, schedule, descriptor)
        .render_result_announcement(
            success,
            output,
            output_preview_max_chars,
            command_max_chars,
            reason_max_chars,
        )
}

pub(crate) fn render_cron_blocked_announcement_with_descriptor(
    id: &str,
    name: &str,
    schedule: &str,
    descriptor: CronLifecycleDescriptor<'_>,
    policy_id: &'static str,
    reason: impl Into<String>,
    command_fragment: Option<&str>,
    command_max_chars: usize,
    reason_max_chars: usize,
) -> Option<String> {
    build_cron_lifecycle_announcement_builder(id, name, schedule, descriptor)
        .render_blocked_announcement(
            policy_id,
            reason,
            command_fragment,
            command_max_chars,
            reason_max_chars,
        )
}

pub(crate) fn render_cron_blocked_announcement_with_preset(
    id: &str,
    name: &str,
    schedule: &str,
    preset: CronLifecyclePreset<'_>,
    policy_id: &'static str,
    reason: impl Into<String>,
    command_fragment: Option<&str>,
    command_max_chars: usize,
    reason_max_chars: usize,
) -> Option<String> {
    let (context, _) = build_cron_lifecycle_render_context_with_preset(id, name, schedule, preset);
    context.render_blocked_announcement(
        policy_id,
        reason,
        command_fragment,
        command_max_chars,
        reason_max_chars,
    )
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CronLifecycleAnnouncementBuilder<'a> {
    id: &'a str,
    name: &'a str,
    schedule: &'a str,
    preset: CronLifecyclePreset<'a>,
}

impl<'a> CronLifecycleAnnouncementBuilder<'a> {
    pub(crate) fn new(
        id: &'a str,
        name: &'a str,
        schedule: &'a str,
        preset: CronLifecyclePreset<'a>,
    ) -> Self {
        Self {
            id,
            name,
            schedule,
            preset,
        }
    }

    pub(crate) fn render_start_announcements(self, detail_max_chars: usize) -> [String; 2] {
        render_cron_start_announcements_with_preset(
            self.id,
            self.name,
            self.schedule,
            self.preset,
            detail_max_chars,
        )
    }

    pub(crate) fn render_result_announcement(
        self,
        success: bool,
        output: &str,
        output_preview_max_chars: usize,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Option<String> {
        render_cron_result_announcement_with_preset(
            self.id,
            self.name,
            self.schedule,
            self.preset,
            success,
            output,
            output_preview_max_chars,
            command_max_chars,
            reason_max_chars,
        )
    }

    pub(crate) fn render_result_announcement_or_output(
        self,
        success: bool,
        output: &str,
        output_preview_max_chars: usize,
        command_max_chars: usize,
        reason_max_chars: usize,
        preserve_output: impl FnOnce(&str) -> bool,
    ) -> String {
        if preserve_output(output) {
            return output.to_string();
        }

        self.render_result_announcement(
            success,
            output,
            output_preview_max_chars,
            command_max_chars,
            reason_max_chars,
        )
        .unwrap_or_else(|| output.to_string())
    }

    pub(crate) fn render_blocked_announcement(
        self,
        policy_id: &'static str,
        reason: impl Into<String>,
        command_fragment: Option<&str>,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Option<String> {
        render_cron_blocked_announcement_with_preset(
            self.id,
            self.name,
            self.schedule,
            self.preset,
            policy_id,
            reason,
            command_fragment,
            command_max_chars,
            reason_max_chars,
        )
    }
}

pub(crate) fn compact_progress_preview(raw: &str, max_chars: usize) -> String {
    let compact = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.is_empty() {
        return "<empty>".to_string();
    }
    let mut chars = compact.chars();
    let preview: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{preview}...")
    } else {
        preview
    }
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
        self.render_output_announcement(
            success,
            output,
            output_preview,
            command_max_chars,
            reason_max_chars,
        )
    }

    pub(crate) fn render_blocked_announcement(
        self,
        policy_id: &'static str,
        reason: impl Into<String>,
        command_fragment: Option<&str>,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Option<String> {
        let structured_reason =
            format_policy_block_event_message(policy_id, reason, command_fragment);
        self.render_output_announcement(
            false,
            &structured_reason,
            compact_progress_preview(&structured_reason, reason_max_chars),
            command_max_chars,
            reason_max_chars,
        )
    }

    fn render_output_announcement(
        self,
        success: bool,
        output: &str,
        output_preview: String,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Option<String> {
        if success {
            return Some(render_execution_completed(
                "Cron",
                self.id,
                self.name,
                self.kind,
                Some(self.schedule),
                output_preview,
            ));
        }

        let block_message = extract_embedded_security_block_message(output)?;
        render_cron_policy_blocked_result(
            self.id,
            self.name,
            self.kind,
            Some(self.schedule),
            block_message,
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
    CronLifecycleAnnouncementRenderContext {
        id,
        name,
        kind,
        schedule,
        detail_label: "command",
        running_status: "shell command is now executing",
        blocked_subject,
    }
    .render_output_announcement(
        success,
        output,
        output_preview,
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

    if let Some(metadata) = parse_policy_block_metadata(trimmed, max_command_chars) {
        return Some(format!(
            "security blocked (policy={}; command={}; config_key={})",
            metadata.policy_id, metadata.command_preview, metadata.config_key
        ));
    }

    render_policy_block_constraint_summary(trimmed, max_command_chars)
}

pub(crate) fn render_policy_block_constraint_guidance(
    reason: &str,
    max_command_chars: usize,
) -> Option<String> {
    render_policy_block_constraint_summary_with_config_key(reason, max_command_chars).map(
        |summary| {
            format!(
                "{summary} Guidance: choose an allowed command/tool, or adjust the corresponding `[autonomy]` policy gate."
            )
        },
    )
}

pub(crate) fn render_policy_block_constraint_guidance_with_context(
    reason: &str,
    max_command_chars: usize,
    max_context_chars: usize,
) -> Option<String> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut guidance = render_policy_block_constraint_guidance(trimmed, max_command_chars)?;

    if let Some(metadata) = parse_policy_block_metadata(trimmed, max_command_chars) {
        append_policy_block_command_context_guidance(&mut guidance, &metadata, max_context_chars);
    }

    Some(guidance)
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
        extract_embedded_security_block_message,
        format_tool_policy_block_event_from_args_with_context_and_trace,
        is_high_priority_progress_update, render_policy_block_constraint_summary,
        strip_progress_section_markers, summarize_tool_policy_block_progress,
        upsert_progress_section,
    };
    use serde_json::json;

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

    #[test]
    fn summarize_tool_policy_block_progress_keeps_command_context_rule_metadata() {
        let raw = "blocked by security policy: policy=autonomy.command_context_rules; command=curl https://evil.example; reason=Command blocked by command_context_rules: no allow rule matched constraints for 'curl'; segment_command=curl https://evil.example; allow_rule_count=1; first_allow_rule=action=allow, commands=curl, allowed_domains=api.internal; rule_index=0; command_context=action=allow, commands=curl, allowed_domains=api.internal";
        let summary = summarize_tool_policy_block_progress("shell", Some(raw))
            .expect("security block summary should be rendered");
        assert!(summary.contains("policy=autonomy.command_context_rules"));
        assert!(summary.contains("command=curl https://evil.example"));
        assert!(summary.contains("rule_index=0"));
        assert!(summary.contains("segment_command=curl https://evil.example"));
        assert!(summary
            .contains("command_context=action=allow, commands=curl, allowed_domains=api.internal"));
    }

    #[test]
    fn tool_policy_block_trace_carries_precomputed_progress_summary() {
        let trace = format_tool_policy_block_event_from_args_with_context_and_trace(
            "autonomy.command_context_rules",
            "Command blocked by command_context_rules: no allow rule matched constraints for 'curl'; segment_command=curl https://evil.example; rule_index=0",
            "shell",
            &json!({"command": "curl https://evil.example"}),
            72,
        );
        let summary = trace
            .progress_summary
            .as_deref()
            .expect("progress summary should be precomputed");
        assert!(summary.contains("policy=autonomy.command_context_rules"));
        assert!(summary.contains("command=curl https://evil.example"));
        assert!(summary.contains("rule_index=0"));
    }

    #[test]
    fn upsert_progress_section_replaces_existing_block() {
        let mut text = String::new();
        upsert_progress_section(&mut text, "⏳ shell: ls\n", "<start>", "<end>");
        upsert_progress_section(&mut text, "✅ shell (1s)\n", "<start>", "<end>");
        let stripped = strip_progress_section_markers(&text, "<start>", "<end>");
        assert!(!stripped.contains("⏳ shell: ls"));
        assert!(stripped.contains("✅ shell (1s)"));
    }
}
