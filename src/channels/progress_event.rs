/// Unified execution progress signal for channel-visible status updates.
use crate::config::{AutonomyConfig, ProgressMode};
use crate::security::policy::{
    preview_command_entries, render_command_policy_block_guidance,
    render_command_policy_block_summary, CommandPolicyViolation, CommandPreviewStyle,
    PolicyBlockRenderReport,
};
use crate::security::AutonomyLevel;
use crate::util::truncate_with_ellipsis;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::Write;
use std::time::Duration;

pub(crate) const DEFAULT_POLICY_BLOCK_HINT_MAX_CHARS: usize = 72;
pub(crate) const DEFAULT_POLICY_BLOCK_CONTEXT_MAX_CHARS: usize = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProgressModePolicy {
    mode: ProgressMode,
}

impl ProgressModePolicy {
    pub(crate) const fn new(mode: ProgressMode) -> Self {
        Self { mode }
    }

    pub(crate) fn mode(self) -> ProgressMode {
        self.mode
    }

    pub(crate) fn emits_verbose_updates(self) -> bool {
        self.mode == ProgressMode::Verbose
    }

    pub(crate) fn tracks_tool_steps(self) -> bool {
        self.mode != ProgressMode::Off
    }

    pub(crate) fn exposes_internal_text(self, text: &str) -> bool {
        is_high_priority_progress_update(text) || self.emits_verbose_updates()
    }

    pub(crate) fn exposes_progress_block(self, block: &str) -> bool {
        is_high_priority_progress_update(block) || self.tracks_tool_steps()
    }

    pub(crate) fn emits_runtime_constraint_detail(self, detail: Option<&str>) -> bool {
        self.mode == ProgressMode::Off && detail.is_some()
    }
}

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
    Failed {
        reason_preview: String,
    },
    Blocked {
        report: PolicyBlockRenderReport,
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
    fn new(
        source: &'a str,
        id: &'a str,
        name: &'a str,
        kind: &'a str,
        schedule: Option<&'a str>,
    ) -> Self {
        Self {
            source,
            id,
            name,
            kind,
            schedule,
        }
    }

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

    pub(crate) fn render_failed(self, reason_preview: String) -> String {
        self.with_signal(ExecutionSignal::Failed { reason_preview })
    }

    pub(crate) fn render_blocked(self, report: PolicyBlockRenderReport) -> String {
        self.with_signal(ExecutionSignal::Blocked { report })
    }

    fn render_runtime_constraint_failure_from_outcome_fields(
        self,
        tool_name: &str,
        error_reason: Option<&str>,
        output: &str,
        output_preview_max_chars: usize,
    ) -> String {
        let summary = RuntimeConstraintOutcomeSummary::for_failed_outcome_fields(
            tool_name,
            error_reason,
            output,
        );
        self.render_runtime_constraint_failure(summary.as_ref(), output, output_preview_max_chars)
    }

    fn render_runtime_constraint_failure(
        self,
        summary: Option<&RuntimeConstraintOutcomeSummary>,
        output: &str,
        output_preview_max_chars: usize,
    ) -> String {
        if let Some(blocked) = summary.and_then(RuntimeConstraintOutcomeSummary::blocked_trace) {
            return self.render_blocked(blocked.report.clone());
        }

        let failure_detail = summary
            .and_then(RuntimeConstraintOutcomeSummary::progress_detail_owned)
            .unwrap_or_else(|| compact_progress_preview(output, output_preview_max_chars));
        self.render_failed(failure_detail)
    }
}

const LIFECYCLE_STATUSES: &[&str] = &[
    "blocked_by_security_policy",
    "triggered",
    "running",
    "completed",
    "failed",
];
const STRUCTURED_LIFECYCLE_TOKENS: &[&str] = &[
    "triggered: id=",
    "running: id=",
    "blocked: id=",
    "completed: id=",
];
const SECURITY_BLOCK_PREFIX: &str = "blocked by security policy:";
const POLICY_BLOCK_REASON_MAX_CHARS: usize = 120;

#[derive(Clone, Copy, Debug)]
struct PolicyBlockRenderPreset<'a> {
    fallback_policy_id: Option<&'a str>,
    fallback_command: Option<&'a str>,
    fallback_config_key: Option<&'a str>,
    default_reason: &'a str,
    default_reason_for_unstructured: bool,
    command_max_chars: usize,
    reason_max_chars: usize,
}

#[derive(Clone, Copy, Debug)]
enum PolicyBlockSubjectKind {
    Tool,
    Execution,
}

impl PolicyBlockRenderPreset<'_> {
    fn report(self, reason: &str) -> Option<PolicyBlockRenderReport> {
        PolicyBlockRenderReport::from_message_or_fallback(
            reason,
            self.fallback_policy_id,
            self.fallback_command,
            self.fallback_config_key,
            self.default_reason,
            self.default_reason_for_unstructured,
            self.command_max_chars,
            self.reason_max_chars,
        )
    }
}

impl PolicyBlockSubjectKind {
    fn preset<'a>(
        self,
        subject: &'a str,
        fallback_policy_id: Option<&'a str>,
        fallback_config_key: Option<&'a str>,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> PolicyBlockRenderPreset<'a> {
        let (default_reason, default_reason_for_unstructured) = match self {
            Self::Tool => ("Command blocked by security policy.", false),
            Self::Execution => ("blocked by security policy", true),
        };

        PolicyBlockRenderPreset {
            fallback_policy_id,
            fallback_command: Some(subject),
            fallback_config_key,
            default_reason,
            default_reason_for_unstructured,
            command_max_chars,
            reason_max_chars,
        }
    }
}

fn policy_block_report(reason: &str, max_command_chars: usize) -> Option<PolicyBlockRenderReport> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return None;
    }
    PolicyBlockRenderReport::from_message(trimmed, max_command_chars, POLICY_BLOCK_REASON_MAX_CHARS)
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DraftProgressDisposition {
    SkipDuplicate,
    SkipThrottled,
    EditInPlace,
    ForceContinuation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DraftContinuationReason {
    HighPriorityProgress,
    EditCapReached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DraftProgressUpdateDecision {
    Skip,
    EditInPlace { next_edits_used: u32 },
    CreateContinuation { reason: DraftContinuationReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DraftProgressState<'a> {
    pub last_rendered_text: Option<&'a str>,
    pub elapsed_since_last: Option<Duration>,
    pub edits_used: u32,
}

pub(crate) fn classify_draft_progress_update(
    text: &str,
    last_rendered_text: Option<&str>,
    elapsed_since_last: Option<Duration>,
    draft_update_interval_ms: u64,
) -> DraftProgressDisposition {
    if should_force_draft_continuation(text) {
        return DraftProgressDisposition::ForceContinuation;
    }

    if last_rendered_text.is_some_and(|previous| previous == text) {
        return DraftProgressDisposition::SkipDuplicate;
    }

    if elapsed_since_last.is_some_and(|elapsed| {
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX) < draft_update_interval_ms
    }) {
        return DraftProgressDisposition::SkipThrottled;
    }

    DraftProgressDisposition::EditInPlace
}

pub(crate) fn decide_draft_progress_update(
    text: &str,
    state: Option<DraftProgressState<'_>>,
    draft_update_interval_ms: u64,
    max_draft_edits: u32,
) -> DraftProgressUpdateDecision {
    match classify_draft_progress_update(
        text,
        state.and_then(|state| state.last_rendered_text),
        state.and_then(|state| state.elapsed_since_last),
        draft_update_interval_ms,
    ) {
        DraftProgressDisposition::ForceContinuation => {
            DraftProgressUpdateDecision::CreateContinuation {
                reason: DraftContinuationReason::HighPriorityProgress,
            }
        }
        DraftProgressDisposition::SkipDuplicate | DraftProgressDisposition::SkipThrottled => {
            DraftProgressUpdateDecision::Skip
        }
        DraftProgressDisposition::EditInPlace => {
            if state.is_some_and(|state| state.edits_used >= max_draft_edits) {
                DraftProgressUpdateDecision::CreateContinuation {
                    reason: DraftContinuationReason::EditCapReached,
                }
            } else {
                DraftProgressUpdateDecision::EditInPlace {
                    next_edits_used: state
                        .map(|state| state.edits_used.saturating_add(1))
                        .unwrap_or(1),
                }
            }
        }
    }
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

fn normalized_progress_block(block: &str) -> String {
    let pinned = collect_structured_lifecycle_or_policy_lines(block);
    if pinned.is_empty() {
        block.trim().to_string()
    } else {
        pinned.join("\n")
    }
}

pub(crate) fn truncate_progress_preserving_structured_lines(
    content: &str,
    max_chars: usize,
) -> String {
    if content.chars().count() <= max_chars {
        return content.to_string();
    }

    if !is_high_priority_progress_update(content) {
        return truncate_with_ellipsis(content, max_chars);
    }

    let pinned_lifecycle = collect_structured_lifecycle_or_policy_lines(content);
    if pinned_lifecycle.is_empty() {
        return truncate_with_ellipsis(content, max_chars);
    }

    let pinned_prefix = pinned_lifecycle.join("\n");
    let budget_for_body = max_chars.saturating_sub(pinned_prefix.chars().count());
    let body = truncate_with_ellipsis(content, budget_for_body.saturating_sub(2));
    let merged = format!("{pinned_prefix}\n\n{body}");
    truncate_with_ellipsis(&merged, max_chars)
}

pub(crate) fn upsert_structured_progress_block(
    accumulated: &mut String,
    block: &str,
    start_marker: &str,
    end_marker: &str,
) {
    let normalized = normalized_progress_block(block);
    if normalized.is_empty() {
        return;
    }
    upsert_progress_section(accumulated, &normalized, start_marker, end_marker);
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

pub(crate) fn collect_structured_lifecycle_or_policy_lines(content: &str) -> Vec<String> {
    let mut lines = Vec::new();

    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if is_structured_lifecycle_or_policy_line(line)
            && lines.last().is_none_or(|last| last != line)
        {
            lines.push(line.to_string());
        }
    }

    lines
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

pub(crate) fn render_shell_policy_instructions(autonomy: &AutonomyConfig) -> String {
    let mut instructions = String::new();
    instructions.push_str("\n## Shell Policy\n\n");
    instructions
        .push_str("When using the `shell` tool, follow these runtime constraints exactly.\n\n");

    let autonomy_label = match autonomy.level {
        AutonomyLevel::ReadOnly => "read_only",
        AutonomyLevel::Supervised => "supervised",
        AutonomyLevel::Full => "full",
    };
    let _ = writeln!(instructions, "- Autonomy level: `{autonomy_label}`");

    if autonomy.level == AutonomyLevel::ReadOnly {
        instructions.push_str(
            "- Shell execution is disabled in `read_only` mode. Do not emit shell tool calls.\n",
        );
        return instructions;
    }

    let allowed_preview = preview_command_entries(
        &autonomy.allowed_commands,
        64,
        CommandPreviewStyle::MarkdownCode,
    )
    .render(
        "none configured. Any shell command will be rejected.",
        "wildcard `*` is configured (any command name/path may be allowlisted).",
        None,
    );
    let unrestricted_preview = preview_command_entries(
        &autonomy.unrestricted_commands,
        32,
        CommandPreviewStyle::MarkdownCode,
    )
    .render("", "wildcard `*` is configured.", None);

    let _ = writeln!(instructions, "- Allowed commands: {allowed_preview}");

    if !unrestricted_preview.is_empty() {
        let _ = writeln!(
            instructions,
            "- Unrestricted commands: {unrestricted_preview} (these bypass normal shell policy gates)."
        );
    }

    if autonomy.level == AutonomyLevel::Supervised && autonomy.require_approval_for_medium_risk {
        instructions.push_str(
            "- Medium-risk shell commands require explicit approval in `supervised` mode.\n",
        );
    }
    if autonomy.block_high_risk_commands {
        instructions.push_str(
            "- High-risk shell commands are blocked even when command names are allowed.\n",
        );
    }
    instructions.push_str(
        "- If a requested command is outside policy, choose allowed alternatives and explain the limitation.\n",
    );

    instructions
}

pub(crate) fn render_runtime_constraint_retry_prompt(reasons: &[String]) -> Option<String> {
    if reasons.is_empty() {
        return None;
    }

    Some(format!(
        "Runtime policy blocked one or more tool calls this turn:\n- {}\n\
         These are runtime safety or approval constraints, not transient tool failures. \
         Do not retry the same blocked tool, path, command, or domain unchanged. \
         Explain the exact blocker to the user, mention the relevant config key or approval gate when known, \
         and either choose an allowed alternative or clearly state what must change before continuing.",
        reasons.join("\n- ")
    ))
}

const RUNTIME_CONSTRAINT_SUMMARY_MAX_CHARS: usize = 480;

fn collect_unique_runtime_constraint_summaries<I, T, F>(
    items: I,
    max_items: usize,
    mut summarize: F,
) -> Vec<String>
where
    I: IntoIterator<Item = T>,
    F: FnMut(T) -> Option<String>,
{
    let mut summaries = Vec::new();
    let mut seen = HashSet::new();

    for item in items {
        let Some(summary) = summarize(item) else {
            continue;
        };

        let summary = truncate_with_ellipsis(&summary, RUNTIME_CONSTRAINT_SUMMARY_MAX_CHARS);
        if summary.is_empty() || !seen.insert(summary.clone()) {
            continue;
        }

        summaries.push(summary);
        if summaries.len() >= max_items {
            break;
        }
    }

    summaries
}

pub(crate) fn summarize_runtime_constraint_reasons<I, S>(
    reasons: I,
    max_items: usize,
    max_command_chars: usize,
    max_context_chars: usize,
) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    collect_unique_runtime_constraint_summaries(reasons, max_items, |reason| {
        summarize_runtime_constraint_guidance(reason.as_ref(), max_command_chars, max_context_chars)
    })
}

pub(crate) fn summarize_runtime_constraint_outcome_fields<'a, I>(
    results: I,
    max_items: usize,
    _max_command_chars: usize,
    _max_context_chars: usize,
) -> Vec<String>
where
    I: IntoIterator<Item = (&'a str, Option<&'a str>, &'a str)>,
{
    collect_unique_runtime_constraint_summaries(
        results,
        max_items,
        |(tool_name, error_reason, output)| {
            RuntimeConstraintOutcomeSummary::progress_detail_from_outcome_fields(
                tool_name,
                error_reason,
                output,
            )
        },
    )
}

pub(crate) fn summarize_runtime_constraint_reasons_default<I, S>(
    reasons: I,
    max_items: usize,
) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    summarize_runtime_constraint_reasons(
        reasons,
        max_items,
        DEFAULT_POLICY_BLOCK_HINT_MAX_CHARS,
        DEFAULT_POLICY_BLOCK_CONTEXT_MAX_CHARS,
    )
}

pub(crate) fn summarize_runtime_constraint_outcomes<'a, I>(
    results: I,
    max_items: usize,
) -> Vec<String>
where
    I: IntoIterator<Item = (&'a str, Option<&'a str>, &'a str)>,
{
    summarize_runtime_constraint_outcome_fields(
        results,
        max_items,
        DEFAULT_POLICY_BLOCK_HINT_MAX_CHARS,
        DEFAULT_POLICY_BLOCK_CONTEXT_MAX_CHARS,
    )
}

pub(crate) fn summarize_runtime_constraint_summaries<'a, I>(
    summaries: I,
    max_items: usize,
) -> Vec<String>
where
    I: IntoIterator<Item = &'a RuntimeConstraintOutcomeSummary>,
{
    collect_unique_runtime_constraint_summaries(summaries, max_items, |summary| {
        summary.progress_detail_owned()
    })
}

pub(crate) fn build_runtime_constraint_retry_prompt(reasons: &[String]) -> Option<String> {
    render_runtime_constraint_retry_prompt(reasons)
}

pub(crate) fn render_execution_event(event: ExecutionEvent<'_>) -> String {
    let source = event.source;
    let id = event.id;
    let name = event.name;
    let kind = event.kind;
    let header = |stage: &str| format!("{source} {stage}: id={id} name={name} type={kind}");
    let schedule_line = event
        .schedule
        .map(|schedule| format!("schedule={schedule}\n"))
        .unwrap_or_default();

    match event.signal {
        ExecutionSignal::Triggered {
            detail_label,
            detail,
        } => {
            let schedule = event.schedule.unwrap_or("unknown");
            format!(
                "⏱️ {}\nschedule={schedule}\n{detail_label}={detail}\nstatus=triggered",
                header("triggered")
            )
        }
        ExecutionSignal::Running { status } => {
            format!("▶️ {}\nstatus={status}", header("running"))
        }
        ExecutionSignal::Completed { result_preview } => {
            format!(
                "✅ {}\n{schedule_line}result={result_preview}\nstatus=completed",
                header("completed")
            )
        }
        ExecutionSignal::Failed { reason_preview } => {
            format!(
                "❌ {}\n{schedule_line}reason={reason_preview}\nstatus=failed",
                header("failed")
            )
        }
        ExecutionSignal::Blocked { report } => {
            if let Some(detail) = report.progress_detail() {
                format!(
                    "🚫 {}\n{schedule_line}{detail}\nstatus=blocked_by_security_policy\nreason={reason}",
                    header("blocked"),
                    reason = report.reason_preview
                )
            } else {
                format!(
                    "🚫 {}\n{schedule_line}status=blocked_by_security_policy\nreason={reason}",
                    header("blocked"),
                    reason = report.reason_preview
                )
            }
        }
    }
}

fn render_policy_block_report(
    subject_kind: PolicyBlockSubjectKind,
    subject: &str,
    reason: &str,
    fallback_policy_id: Option<&str>,
    fallback_config_key: Option<&str>,
    command_max_chars: usize,
    reason_max_chars: usize,
) -> Option<PolicyBlockRenderReport> {
    subject_kind
        .preset(
            subject,
            fallback_policy_id,
            fallback_config_key,
            command_max_chars,
            reason_max_chars,
        )
        .report(reason)
}

pub(crate) fn summarize_tool_policy_block_progress(
    tool_name: &str,
    reason: Option<&str>,
) -> Option<String> {
    ToolPolicyBlockTrace::from_reason(
        tool_name,
        reason?,
        Some("unknown"),
        Some("unknown"),
        DEFAULT_POLICY_BLOCK_HINT_MAX_CHARS,
        DEFAULT_POLICY_BLOCK_CONTEXT_MAX_CHARS,
    )
    .map(|trace| trace.progress_detail())
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
        && render_command_policy_block_summary(trimmed_output, 48).is_some()
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
    RuntimeConstraintOutcomeSummary::from_outcome_fields(tool_name, error_reason, output)
        .progress_detail_owned()
}

pub(crate) fn trace_structured_tool_policy_block_from_outcome_fields(
    tool_name: &str,
    error_reason: Option<&str>,
    output: &str,
    hint_max_chars: usize,
    reason_max_chars: usize,
) -> Option<ToolPolicyBlockTrace> {
    RuntimeConstraintOutcomeSummary::from_reasons(
        tool_name,
        policy_block_reason_candidates_from_outcome_fields(error_reason, output),
        hint_max_chars,
        reason_max_chars,
    )
    .into_blocked_trace()
}

#[derive(Debug, Clone)]
enum RuntimeConstraintDetail {
    Blocked(ToolPolicyBlockTrace),
    Guidance(String),
}

impl RuntimeConstraintDetail {
    fn into_blocked_trace(self) -> Option<ToolPolicyBlockTrace> {
        match self {
            Self::Blocked(blocked) => Some(blocked),
            Self::Guidance(_) => None,
        }
    }

    fn progress_detail_owned(&self) -> String {
        match self {
            Self::Blocked(blocked) => blocked.progress_detail(),
            Self::Guidance(detail) => detail.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeConstraintOutcomeSummary {
    detail: Option<RuntimeConstraintDetail>,
}

impl RuntimeConstraintOutcomeSummary {
    fn from_reasons<'a, I>(
        tool_name: &str,
        reasons: I,
        hint_max_chars: usize,
        reason_max_chars: usize,
    ) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut fallback_detail = None;

        for reason in reasons {
            let trimmed = reason.trim();
            if trimmed.is_empty() {
                continue;
            }

            if render_command_policy_block_summary(trimmed, 48).is_some() {
                return Self::from_optional_blocked(ToolPolicyBlockTrace::from_reason(
                    tool_name,
                    trimmed,
                    Some("unknown"),
                    Some("unknown"),
                    hint_max_chars,
                    reason_max_chars,
                ));
            }

            if fallback_detail.is_none() {
                fallback_detail = summarize_runtime_constraint_guidance(
                    trimmed,
                    hint_max_chars,
                    reason_max_chars,
                )
                .filter(|summary| !summary.is_empty());
            }
        }

        Self {
            detail: fallback_detail.map(RuntimeConstraintDetail::Guidance),
        }
    }

    fn from_optional_blocked(blocked: Option<ToolPolicyBlockTrace>) -> Self {
        Self {
            detail: blocked.map(RuntimeConstraintDetail::Blocked),
        }
    }

    pub(crate) fn from_blocked(blocked: ToolPolicyBlockTrace) -> Self {
        Self {
            detail: Some(RuntimeConstraintDetail::Blocked(blocked)),
        }
    }

    pub(crate) fn from_outcome_fields(
        tool_name: &str,
        error_reason: Option<&str>,
        output: &str,
    ) -> Self {
        Self::from_reasons(
            tool_name,
            policy_block_reason_candidates_from_outcome_fields(error_reason, output),
            DEFAULT_POLICY_BLOCK_HINT_MAX_CHARS,
            DEFAULT_POLICY_BLOCK_CONTEXT_MAX_CHARS,
        )
    }

    pub(crate) fn for_failed_outcome_fields(
        tool_name: &str,
        error_reason: Option<&str>,
        output: &str,
    ) -> Option<Self> {
        let summary = Self::from_outcome_fields(tool_name, error_reason, output);
        summary.has_detail().then_some(summary)
    }

    pub(crate) fn progress_detail_from_outcome_fields(
        tool_name: &str,
        error_reason: Option<&str>,
        output: &str,
    ) -> Option<String> {
        Self::for_failed_outcome_fields(tool_name, error_reason, output)
            .and_then(|summary| summary.progress_detail_owned())
    }

    pub(crate) fn finalize_failed_outcome_fields(
        tool_name: &str,
        output: &mut String,
        error_reason: &mut Option<String>,
    ) -> Option<Self> {
        let summary = Self::for_failed_outcome_fields(tool_name, error_reason.as_deref(), output);
        if let Some(summary) = summary.as_ref() {
            summary.apply_to_failed_outcome_fields(output, error_reason);
        }
        summary
    }

    pub(crate) fn blocked_trace(&self) -> Option<&ToolPolicyBlockTrace> {
        match self.detail.as_ref() {
            Some(RuntimeConstraintDetail::Blocked(blocked)) => Some(blocked),
            _ => None,
        }
    }

    fn into_blocked_trace(self) -> Option<ToolPolicyBlockTrace> {
        self.detail
            .and_then(RuntimeConstraintDetail::into_blocked_trace)
    }

    pub(crate) fn progress_detail_owned(&self) -> Option<String> {
        self.detail
            .as_ref()
            .map(RuntimeConstraintDetail::progress_detail_owned)
    }

    pub(crate) fn preferred_error_reason<'a>(
        &'a self,
        error_reason: Option<&'a str>,
    ) -> Option<Cow<'a, str>> {
        self.blocked_trace()
            .and_then(ToolPolicyBlockTrace::canonical_error_reason)
            .map(Cow::Owned)
            .or_else(|| error_reason.map(Cow::Borrowed))
    }

    pub(crate) fn append_runtime_trace_metadata(&self, metadata: &mut Value) {
        if let Some(blocked) = self.blocked_trace() {
            blocked.append_runtime_trace_metadata(metadata);
        }
    }

    pub(crate) fn canonical_blocked_output(&self) -> Option<String> {
        self.blocked_trace()
            .map(ToolPolicyBlockTrace::canonical_output)
    }

    pub(crate) fn apply_to_failed_outcome_fields(
        &self,
        output: &mut String,
        error_reason: &mut Option<String>,
    ) -> Option<String> {
        if let Some(blocked) = self
            .blocked_trace()
            .map(ToolPolicyBlockTrace::blocked_outcome_fields)
        {
            *output = blocked.output.clone();
            *error_reason = blocked.error_reason;
        }
        self.progress_detail_owned()
    }

    fn has_detail(&self) -> bool {
        self.detail.is_some()
    }
}

pub(crate) fn render_runtime_constraint_failure_from_outcome_fields(
    tool_name: &str,
    render_context: ExecutionRenderContext<'_>,
    error_reason: Option<&str>,
    output: &str,
    output_preview_max_chars: usize,
) -> String {
    render_context.render_runtime_constraint_failure_from_outcome_fields(
        tool_name,
        error_reason,
        output,
        output_preview_max_chars,
    )
}

pub(crate) fn format_tool_policy_block_event_message(
    policy_id: &'static str,
    reason: impl Into<String>,
    tool_name: &str,
    tool_hint: Option<&str>,
) -> String {
    let command_fragment = tool_policy_block_command_fragment(tool_name, tool_hint);
    format_policy_block_event_message(policy_id, reason, Some(&command_fragment))
}

pub(crate) fn render_tool_policy_block_progress_summary_from_parts(
    policy_id: &'static str,
    reason: impl Into<String>,
    tool_name: &str,
    tool_hint: Option<&str>,
) -> Option<String> {
    Some(
        ToolPolicyBlockTrace::from_violation(
            tool_name,
            &tool_policy_block_violation(policy_id, reason, tool_name, tool_hint),
            DEFAULT_POLICY_BLOCK_HINT_MAX_CHARS,
            DEFAULT_POLICY_BLOCK_CONTEXT_MAX_CHARS,
        )
        .progress_detail(),
    )
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
    format_tool_policy_block_event_message(
        policy_id,
        reason,
        tool_name,
        tool_progress_hint(tool_name, tool_args, hint_max_chars).as_deref(),
    )
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
    tool_name: String,
    pub report: PolicyBlockRenderReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockedOutcomeFields {
    pub output: String,
    pub error_reason: Option<String>,
    pub duration: Duration,
}

impl ToolPolicyBlockTrace {
    fn from_reason(
        tool_name: &str,
        blocked: impl Into<String>,
        fallback_policy_id: Option<&str>,
        fallback_config_key: Option<&str>,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Option<Self> {
        let blocked = blocked.into();
        let report = render_policy_block_report(
            PolicyBlockSubjectKind::Tool,
            tool_name,
            &blocked,
            fallback_policy_id,
            fallback_config_key,
            command_max_chars,
            reason_max_chars,
        )?;
        Some(Self::new(blocked, report, tool_name))
    }

    fn from_violation(
        tool_name: &str,
        violation: &CommandPolicyViolation,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Self {
        Self::new(
            violation.format_block_message(),
            violation.render_execution_report_with_limits(command_max_chars, reason_max_chars),
            tool_name,
        )
    }

    fn new(blocked: String, report: PolicyBlockRenderReport, tool_name: &str) -> Self {
        Self {
            blocked,
            tool_name: tool_name.to_string(),
            report,
        }
    }

    fn render_progress_detail(tool_name: &str, report: &PolicyBlockRenderReport) -> String {
        ExecutionRenderContext::new("Agent", tool_name, tool_name, "tool", None)
            .render_blocked(report.clone())
    }

    pub(crate) fn progress_detail(&self) -> String {
        Self::render_progress_detail(self.tool_name.as_str(), &self.report)
    }

    pub(crate) fn progress_detail_owned(&self) -> Option<String> {
        Some(self.progress_detail())
    }

    pub(crate) fn canonical_output(&self) -> String {
        self.blocked.clone()
    }

    pub(crate) fn canonical_error_reason(&self) -> Option<String> {
        Some(self.blocked.clone())
    }

    pub(crate) fn blocked_outcome_fields(&self) -> BlockedOutcomeFields {
        BlockedOutcomeFields {
            output: self.canonical_output(),
            error_reason: self.canonical_error_reason(),
            duration: self.duration(),
        }
    }

    pub(crate) fn policy_id(&self) -> Option<&str> {
        self.report.policy_id()
    }

    pub(crate) fn command(&self) -> Option<&str> {
        self.report.command_preview()
    }

    pub(crate) fn config_key(&self) -> Option<&str> {
        self.report.config_key()
    }

    pub(crate) fn command_context(&self) -> Option<&str> {
        self.report.command_context()
    }

    pub(crate) fn append_runtime_trace_metadata(&self, metadata: &mut Value) {
        self.report.append_runtime_trace_metadata(metadata);
    }

    pub(crate) fn duration(&self) -> Duration {
        Duration::ZERO
    }

    pub(crate) fn runtime_trace_metadata(
        &self,
        iteration: usize,
        tool_name: &str,
        arguments: String,
        blocked_by_channel_policy: bool,
    ) -> Value {
        let mut metadata = serde_json::json!({
            "iteration": iteration + 1,
            "tool": tool_name,
            "arguments": arguments,
            "blocked_by_channel_policy": blocked_by_channel_policy,
        });
        self.append_runtime_trace_metadata(&mut metadata);
        metadata
    }
}

fn tool_policy_block_command_fragment(tool_name: &str, tool_hint: Option<&str>) -> String {
    tool_hint
        .map(str::trim)
        .filter(|hint| !hint.is_empty())
        .map(|hint| format!("{tool_name} {hint}"))
        .unwrap_or_else(|| tool_name.to_string())
}

fn tool_policy_block_violation(
    policy_id: &'static str,
    reason: impl Into<String>,
    tool_name: &str,
    tool_hint: Option<&str>,
) -> CommandPolicyViolation {
    let command_fragment = tool_policy_block_command_fragment(tool_name, tool_hint);
    CommandPolicyViolation::from_block_event(policy_id, reason, Some(&command_fragment))
}

fn tool_progress_hint(tool_name: &str, tool_args: &Value, hint_max_chars: usize) -> Option<String> {
    let hint = truncate_tool_args_for_progress(tool_name, tool_args, hint_max_chars);
    (!hint.is_empty()).then_some(hint)
}

pub(crate) fn format_tool_policy_block_event_from_args_with_context_and_trace(
    policy_id: &'static str,
    reason: impl Into<String>,
    tool_name: &str,
    tool_args: &Value,
    hint_max_chars: usize,
) -> ToolPolicyBlockTrace {
    let reason = ensure_policy_block_reason_has_command_context(
        reason,
        tool_name,
        tool_args,
        hint_max_chars,
    );
    let tool_hint = tool_progress_hint(tool_name, tool_args, hint_max_chars);
    let violation = tool_policy_block_violation(policy_id, reason, tool_name, tool_hint.as_deref());
    ToolPolicyBlockTrace::from_violation(tool_name, &violation, hint_max_chars, 120)
}

pub(crate) fn trace_structured_tool_policy_block(
    tool_name: &str,
    blocked: &str,
    hint_max_chars: usize,
    reason_max_chars: usize,
) -> Option<ToolPolicyBlockTrace> {
    ToolPolicyBlockTrace::from_reason(
        tool_name,
        blocked.trim(),
        Some("unknown"),
        Some("unknown"),
        hint_max_chars,
        reason_max_chars,
    )
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CronLifecycleDescriptorDetails<'a> {
    pub kind: &'static str,
    pub detail_label: &'static str,
    pub detail_text: &'a str,
    pub running_status: &'static str,
    pub blocked_subject: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CronLifecycleDescriptor<'a> {
    Agent { prompt: Option<&'a str> },
    Shell { command: &'a str },
}

impl<'a> CronLifecycleDescriptor<'a> {
    fn details(self) -> CronLifecycleDescriptorDetails<'a> {
        match self {
            Self::Agent { prompt } => {
                let prompt = prompt.unwrap_or("");
                let blocked_subject = if prompt.trim().is_empty() {
                    "<agent-task>"
                } else {
                    prompt
                };
                CronLifecycleDescriptorDetails {
                    kind: "agent",
                    detail_label: "agent_task",
                    detail_text: prompt,
                    running_status: "agent is now executing",
                    blocked_subject,
                }
            }
            Self::Shell { command } => CronLifecycleDescriptorDetails {
                kind: "shell",
                detail_label: "command",
                detail_text: command,
                running_status: "shell command is now executing",
                blocked_subject: command,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CronLifecycleRenderInput<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub schedule: Cow<'a, str>,
    pub descriptor: CronLifecycleDescriptor<'a>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CronLifecycleRenderLimits {
    pub detail_max_chars: usize,
    pub output_preview_max_chars: usize,
    pub command_max_chars: usize,
    pub reason_max_chars: usize,
}

impl<'a> CronLifecycleRenderInput<'a> {
    pub(crate) fn new(
        id: &'a str,
        name: &'a str,
        schedule: impl Into<Cow<'a, str>>,
        descriptor: CronLifecycleDescriptor<'a>,
    ) -> Self {
        Self {
            id,
            name,
            schedule: schedule.into(),
            descriptor,
        }
    }
}

pub(crate) fn render_cron_start_announcements_with_descriptor(
    id: &str,
    name: &str,
    schedule: &str,
    descriptor: CronLifecycleDescriptor<'_>,
    limits: CronLifecycleRenderLimits,
) -> [String; 2] {
    CronLifecycleRenderInput::new(id, name, schedule, descriptor).start_announcements(limits)
}

pub(crate) fn render_cron_result_announcement_with_descriptor(
    id: &str,
    name: &str,
    schedule: &str,
    descriptor: CronLifecycleDescriptor<'_>,
    success: bool,
    output: &str,
    limits: CronLifecycleRenderLimits,
) -> Option<String> {
    CronLifecycleRenderInput::new(id, name, schedule, descriptor)
        .result_announcement(success, output, limits)
}

pub(crate) fn render_cron_blocked_announcement_with_descriptor(
    id: &str,
    name: &str,
    schedule: &str,
    descriptor: CronLifecycleDescriptor<'_>,
    policy_id: &'static str,
    reason: impl Into<String>,
    command_fragment: Option<&str>,
    limits: CronLifecycleRenderLimits,
) -> Option<String> {
    let blocked = CommandPolicyViolation::from_block_event(policy_id, reason, command_fragment);
    render_cron_violation_announcement_with_descriptor(
        id, name, schedule, descriptor, &blocked, limits,
    )
}

pub(crate) fn render_cron_violation_announcement_with_descriptor(
    id: &str,
    name: &str,
    schedule: &str,
    descriptor: CronLifecycleDescriptor<'_>,
    blocked: &CommandPolicyViolation,
    limits: CronLifecycleRenderLimits,
) -> Option<String> {
    CronLifecycleRenderInput::new(id, name, schedule, descriptor)
        .blocked_announcement_from_violation(blocked, limits)
}

impl<'a> CronLifecycleRenderInput<'a> {
    fn descriptor_details(&self) -> CronLifecycleDescriptorDetails<'a> {
        self.descriptor.details()
    }

    fn render_context(&self, kind: &'static str) -> ExecutionRenderContext<'_> {
        ExecutionRenderContext::new(
            "Cron",
            self.id,
            self.name,
            kind,
            Some(self.schedule.as_ref()),
        )
    }

    pub(crate) fn start_announcements(self, limits: CronLifecycleRenderLimits) -> [String; 2] {
        let details = self.descriptor_details();
        let detail = compact_progress_preview(details.detail_text, limits.detail_max_chars);
        self.render_context(details.kind).render_start_pair(
            details.detail_label,
            detail,
            details.running_status,
        )
    }

    pub(crate) fn result_announcement(
        self,
        success: bool,
        output: &str,
        limits: CronLifecycleRenderLimits,
    ) -> Option<String> {
        let details = self.descriptor_details();
        let render_context = self.render_context(details.kind);

        if success {
            return Some(render_context.render_completed(compact_progress_preview(
                output,
                limits.output_preview_max_chars,
            )));
        }

        Some(
            render_context.render_runtime_constraint_failure_from_outcome_fields(
                details.blocked_subject,
                None,
                output,
                limits.output_preview_max_chars,
            ),
        )
    }

    pub(crate) fn result_announcement_or_original(
        self,
        success: bool,
        output: &str,
        limits: CronLifecycleRenderLimits,
    ) -> String {
        self.result_announcement(success, output, limits)
            .unwrap_or_else(|| output.to_string())
    }

    pub(crate) fn blocked_announcement(
        self,
        policy_id: &'static str,
        reason: impl Into<String>,
        command_fragment: Option<&str>,
        limits: CronLifecycleRenderLimits,
    ) -> Option<String> {
        let details = self.descriptor_details();
        let blocked = CommandPolicyViolation::from_block_event(
            policy_id,
            reason,
            command_fragment.or(Some(details.blocked_subject)),
        );
        self.blocked_announcement_from_violation(&blocked, limits)
    }

    pub(crate) fn blocked_announcement_from_violation(
        self,
        blocked: &CommandPolicyViolation,
        limits: CronLifecycleRenderLimits,
    ) -> Option<String> {
        let details = self.descriptor_details();
        let report = blocked
            .render_execution_report_with_limits(limits.command_max_chars, limits.reason_max_chars);
        Some(self.render_context(details.kind).render_blocked(report))
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

pub(crate) fn render_policy_block_constraint_summary(
    reason: &str,
    max_command_chars: usize,
) -> Option<String> {
    render_command_policy_block_summary(reason, max_command_chars)
}

pub(crate) fn render_policy_block_constraint_guidance(
    reason: &str,
    max_command_chars: usize,
) -> Option<String> {
    render_policy_block_constraint_guidance_with_context(
        reason,
        max_command_chars,
        DEFAULT_POLICY_BLOCK_CONTEXT_MAX_CHARS,
    )
}

pub(crate) fn render_policy_block_constraint_guidance_with_context(
    reason: &str,
    max_command_chars: usize,
    max_context_chars: usize,
) -> Option<String> {
    render_command_policy_block_guidance(
        reason,
        max_command_chars,
        POLICY_BLOCK_REASON_MAX_CHARS,
        max_context_chars,
    )
}

fn strip_runtime_constraint_error_prefix(reason: &str) -> &str {
    let trimmed = reason.trim();
    trimmed
        .strip_prefix("Error:")
        .map(str::trim)
        .unwrap_or(trimmed)
}

fn contains_progress_marker(haystack: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| haystack.contains(marker))
}

fn looks_like_workspace_path_block_reason(lower_reason: &str) -> bool {
    contains_progress_marker(
        lower_reason,
        &[
            "path not allowed by security policy",
            "path blocked by security policy",
            "outside the allowed workspace",
            "escapes workspace",
        ],
    )
}

fn references_workspace_path_policy_knobs(lower_reason: &str) -> bool {
    contains_progress_marker(lower_reason, &["allowed_roots", "workspace_only"])
}

fn summarize_workspace_path_runtime_constraint(trimmed: &str, lower: &str) -> Option<String> {
    if !looks_like_workspace_path_block_reason(lower) {
        return None;
    }

    if references_workspace_path_policy_knobs(lower) {
        return Some(trimmed.to_string());
    }

    Some(format!(
        "{trimmed} Guidance: review `[autonomy].workspace_only` and `[autonomy].allowed_roots`."
    ))
}

fn summarize_operator_runtime_constraint(trimmed: &str, lower: &str) -> Option<String> {
    if lower.contains("requires explicit approval") || lower.contains("denied by user") {
        return Some(format!(
            "{trimmed} Guidance: supervised execution requires approval for this tool or action."
        ));
    }

    if lower.contains("not available in this channel") {
        return Some(format!(
            "{trimmed} Guidance: review the channel/runtime tool exclusion list or use another allowed tool."
        ));
    }

    None
}

pub(crate) fn summarize_runtime_constraint_guidance(
    reason: &str,
    max_command_chars: usize,
    max_context_chars: usize,
) -> Option<String> {
    let trimmed = strip_runtime_constraint_error_prefix(reason);
    if trimmed.is_empty() {
        return None;
    }

    if let Some(guidance) = render_policy_block_constraint_guidance_with_context(
        trimmed,
        max_command_chars,
        max_context_chars,
    ) {
        return Some(guidance);
    }

    let lower = trimmed.to_ascii_lowercase();

    if let Some(summary) = summarize_workspace_path_runtime_constraint(trimmed, &lower) {
        return Some(summary);
    }

    if let Some(summary) = summarize_operator_runtime_constraint(trimmed, &lower) {
        return Some(summary);
    }

    if references_workspace_path_policy_knobs(&lower)
        || lower.contains("allow_sensitive_file_reads")
        || lower.contains("allow_sensitive_file_writes")
        || lower.contains("security.url_access.")
        || lower.contains("first-time domain approval required")
    {
        return Some(trimmed.to_string());
    }

    None
}

pub(crate) fn normalize_runtime_constraint_guidance(
    reason: &str,
    max_command_chars: usize,
    max_context_chars: usize,
) -> String {
    let trimmed = strip_runtime_constraint_error_prefix(reason);
    if trimmed.is_empty() {
        return String::new();
    }

    summarize_runtime_constraint_guidance(trimmed, max_command_chars, max_context_chars)
        .unwrap_or_else(|| trimmed.to_string())
}

pub(crate) fn looks_like_runtime_constraint_reason(reason: &str) -> bool {
    summarize_runtime_constraint_guidance(
        reason,
        DEFAULT_POLICY_BLOCK_HINT_MAX_CHARS,
        DEFAULT_POLICY_BLOCK_CONTEXT_MAX_CHARS,
    )
    .is_some()
}

pub(crate) fn normalize_runtime_constraint_reason(reason: &str) -> String {
    normalize_runtime_constraint_guidance(
        reason,
        DEFAULT_POLICY_BLOCK_HINT_MAX_CHARS,
        DEFAULT_POLICY_BLOCK_CONTEXT_MAX_CHARS,
    )
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
        classify_draft_progress_update, collect_structured_lifecycle_or_policy_lines,
        decide_draft_progress_update, extract_embedded_security_block_message,
        format_tool_policy_block_event_from_args_with_context_and_trace,
        is_high_priority_progress_update, render_cron_result_announcement_with_descriptor,
        render_policy_block_constraint_guidance_with_context,
        render_policy_block_constraint_summary,
        render_runtime_constraint_failure_from_outcome_fields, strip_progress_section_markers,
        summarize_runtime_constraint_guidance, summarize_tool_policy_block_progress,
        truncate_progress_preserving_structured_lines, upsert_progress_section,
        upsert_structured_progress_block, CronLifecycleDescriptor, CronLifecycleRenderLimits,
        DraftContinuationReason, DraftProgressDisposition, DraftProgressState,
        DraftProgressUpdateDecision, ExecutionRenderContext, RuntimeConstraintOutcomeSummary,
        ToolPolicyBlockTrace,
    };
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn classify_draft_progress_update_forces_continuation_for_high_priority_progress() {
        assert_eq!(
            classify_draft_progress_update("⏳ shell: cargo check", Some("previous"), None, 60_000),
            DraftProgressDisposition::ForceContinuation
        );
    }

    #[test]
    fn classify_draft_progress_update_skips_duplicate_progress() {
        assert_eq!(
            classify_draft_progress_update("steady", Some("steady"), None, 60_000),
            DraftProgressDisposition::SkipDuplicate
        );
    }

    #[test]
    fn classify_draft_progress_update_skips_throttled_non_priority_progress() {
        assert_eq!(
            classify_draft_progress_update(
                "steady",
                Some("previous"),
                Some(Duration::from_millis(500)),
                1_000
            ),
            DraftProgressDisposition::SkipThrottled
        );
    }

    #[test]
    fn classify_draft_progress_update_allows_regular_edit_when_not_throttled() {
        assert_eq!(
            classify_draft_progress_update(
                "steady",
                Some("previous"),
                Some(Duration::from_secs(2)),
                1_000
            ),
            DraftProgressDisposition::EditInPlace
        );
    }

    #[test]
    fn decide_draft_progress_update_skips_duplicate_progress() {
        assert_eq!(
            decide_draft_progress_update(
                "steady",
                Some(DraftProgressState {
                    last_rendered_text: Some("steady"),
                    elapsed_since_last: Some(Duration::from_secs(5)),
                    edits_used: 1,
                }),
                1_000,
                3,
            ),
            DraftProgressUpdateDecision::Skip
        );
    }

    #[test]
    fn decide_draft_progress_update_forces_continuation_for_priority_progress() {
        assert_eq!(
            decide_draft_progress_update(
                "⏳ shell: cargo check",
                Some(DraftProgressState {
                    last_rendered_text: Some("previous"),
                    elapsed_since_last: Some(Duration::from_millis(10)),
                    edits_used: 99,
                }),
                60_000,
                1,
            ),
            DraftProgressUpdateDecision::CreateContinuation {
                reason: DraftContinuationReason::HighPriorityProgress,
            }
        );
    }

    #[test]
    fn decide_draft_progress_update_rolls_to_continuation_after_edit_cap() {
        assert_eq!(
            decide_draft_progress_update(
                "steady",
                Some(DraftProgressState {
                    last_rendered_text: Some("previous"),
                    elapsed_since_last: Some(Duration::from_secs(5)),
                    edits_used: 2,
                }),
                1_000,
                2,
            ),
            DraftProgressUpdateDecision::CreateContinuation {
                reason: DraftContinuationReason::EditCapReached,
            }
        );
    }

    #[test]
    fn decide_draft_progress_update_increments_edit_count_for_regular_edit() {
        assert_eq!(
            decide_draft_progress_update(
                "steady",
                Some(DraftProgressState {
                    last_rendered_text: Some("previous"),
                    elapsed_since_last: Some(Duration::from_secs(5)),
                    edits_used: 2,
                }),
                1_000,
                3,
            ),
            DraftProgressUpdateDecision::EditInPlace { next_edits_used: 3 }
        );
    }

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
        assert!(summary.contains("config_key=autonomy.allowed_commands"));
    }

    #[test]
    fn render_policy_block_constraint_guidance_keeps_command_context_metadata() {
        let raw = "blocked by security policy: policy=autonomy.command_context_rules; command=curl https://evil.example; reason=Command blocked by command_context_rules: no allow rule matched constraints for 'curl'; rule_index=0; command_context=action=allow, commands=curl, allowed_domains=api.internal";
        let guidance = render_policy_block_constraint_guidance_with_context(raw, 72, 120)
            .expect("policy block guidance should be rendered");
        assert!(guidance.contains("policy=autonomy.command_context_rules"));
        assert!(guidance.contains("command=curl https://evil.example"));
        assert!(guidance.contains("config_key=autonomy.command_context_rules"));
        assert!(guidance.contains("Guidance: choose an allowed command/tool"));
        assert!(guidance
            .contains("command_context=action=allow, commands=curl, allowed_domains=api.internal"));
    }

    #[test]
    fn summarize_runtime_constraint_guidance_handles_workspace_path_blockers() {
        let raw = "Error: Path blocked by security policy: /etc/passwd";
        let guidance = summarize_runtime_constraint_guidance(raw, 72, 120)
            .expect("workspace path blockers should produce guidance");
        assert!(guidance.contains("Path blocked by security policy: /etc/passwd"));
        assert!(guidance.contains("[autonomy].workspace_only"));
        assert!(guidance.contains("[autonomy].allowed_roots"));
    }

    #[test]
    fn summarize_runtime_constraint_guidance_preserves_known_policy_knobs() {
        let raw =
            "Error: first-time domain approval required by security.url_access.approved_domains";
        let guidance = summarize_runtime_constraint_guidance(raw, 72, 120)
            .expect("known policy knobs should be preserved");
        assert_eq!(
            guidance,
            "first-time domain approval required by security.url_access.approved_domains"
        );
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
    fn collect_structured_lifecycle_or_policy_lines_deduplicates_visible_block_lines() {
        let content = "  status=triggered\n\nstatus=triggered\npolicy=autonomy.allowed_commands; command=cat /etc/passwd\nreason=Command not allowed by security policy\nother line";
        let lines = collect_structured_lifecycle_or_policy_lines(content);
        assert_eq!(
            lines,
            vec![
                "status=triggered".to_string(),
                "policy=autonomy.allowed_commands; command=cat /etc/passwd".to_string(),
                "reason=Command not allowed by security policy".to_string(),
            ]
        );
    }

    #[test]
    fn upsert_structured_progress_block_keeps_only_visible_policy_lines() {
        let mut accumulated = String::from("draft");
        let block = "🚫 Shell blocked\npolicy=autonomy.allowed_commands; command=cat /etc/passwd\nstatus=blocked_by_security_policy\nreason=Command not allowed by security policy\ninternal trace";

        upsert_structured_progress_block(&mut accumulated, block, "<start>", "<end>");

        assert_eq!(
            accumulated,
            "draft<start>policy=autonomy.allowed_commands; command=cat /etc/passwd\nstatus=blocked_by_security_policy\nreason=Command not allowed by security policy<end>"
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
        let summary = trace.progress_detail();
        assert_eq!(trace.policy_id(), Some("autonomy.command_context_rules"));
        assert_eq!(trace.command(), Some("shell curl https://evil.example"));
        assert_eq!(trace.config_key(), Some("autonomy.command_context_rules"));
        assert!(summary.contains("policy=autonomy.command_context_rules"));
        assert!(summary.contains("command=shell curl https://evil.example"));
        assert!(summary.contains("config_key=autonomy.command_context_rules"));
        assert!(summary.contains("rule_index=0"));
        assert!(summary.contains("command_context=tool=shell, hint=curl https://evil.example"));
    }

    #[test]
    fn runtime_constraint_outcome_summary_falls_back_to_embedded_policy_block_output() {
        let summary = RuntimeConstraintOutcomeSummary::from_outcome_fields(
            "shell",
            Some("execution failed without structured reason"),
            "agent job failed: blocked by security policy: policy=autonomy.allowed_commands; command=curl https://evil.example; reason=Command not allowed by security policy: curl https://evil.example",
        );
        let blocked = summary
            .blocked_trace()
            .expect("embedded policy block should produce a structured trace");
        assert_eq!(blocked.policy_id(), Some("autonomy.allowed_commands"));
        assert_eq!(blocked.config_key(), Some("autonomy.allowed_commands"));
        assert!(summary
            .progress_detail_owned()
            .unwrap_or_default()
            .contains("command=curl https://evil.example"));
    }

    #[test]
    fn runtime_constraint_outcome_summary_applies_canonical_blocked_output_to_failed_fields() {
        let summary = RuntimeConstraintOutcomeSummary::from_outcome_fields(
            "shell",
            Some("execution failed without structured reason"),
            "agent job failed: blocked by security policy: policy=autonomy.allowed_commands; command=curl https://evil.example; reason=Command not allowed by security policy: curl https://evil.example",
        );
        let mut output = "placeholder".to_string();
        let mut error_reason = Some("placeholder".to_string());

        let detail = summary.apply_to_failed_outcome_fields(&mut output, &mut error_reason);

        assert_eq!(
            output,
            "blocked by security policy: policy=autonomy.allowed_commands; command=curl https://evil.example; reason=Command not allowed by security policy: curl https://evil.example"
        );
        assert_eq!(error_reason.as_deref(), Some(output.as_str()));
        assert!(detail
            .unwrap_or_default()
            .contains("command=curl https://evil.example"));
    }

    #[test]
    fn render_runtime_constraint_failure_from_outcome_fields_falls_back_to_failed_preview() {
        let rendered = render_runtime_constraint_failure_from_outcome_fields(
            "shell",
            ExecutionRenderContext::new("Cron", "job-1", "nightly", "Shell", Some("every(1m)")),
            Some("plain failure"),
            "plain failure output without policy block",
            220,
        );

        assert!(rendered.contains("Cron failed: id=job-1"));
        assert!(rendered.contains("status=failed"));
        assert!(rendered.contains("plain failure"));
    }

    #[test]
    fn tool_policy_block_trace_carries_canonical_fields() {
        let blocked = ToolPolicyBlockTrace::new(
            "blocked by security policy: policy=autonomy.command_context_rules; command=shell curl https://evil.example; reason=Command blocked by command_context_rules: no allow rule matched constraints for 'curl'; segment_command=curl https://evil.example; rule_index=0".to_string(),
            crate::security::policy::CommandPolicyViolation::from_block_event(
                "autonomy.command_context_rules",
                "Command blocked by command_context_rules: no allow rule matched constraints for 'curl'; segment_command=curl https://evil.example; rule_index=0",
                Some("shell curl https://evil.example"),
            )
            .render_report_with_limits(72, 120),
            "shell",
        );

        assert_eq!(blocked.policy_id(), Some("autonomy.command_context_rules"));
        assert_eq!(
            blocked.canonical_error_reason(),
            Some(blocked.canonical_output())
        );
        assert_eq!(blocked.duration(), Duration::ZERO);
    }

    #[test]
    fn runtime_constraint_summary_from_blocked_trace_reuses_canonical_output() {
        let blocked = ToolPolicyBlockTrace::new(
            "blocked by security policy: policy=autonomy.command_context_rules; command=shell curl https://evil.example; reason=Command blocked by command_context_rules: no allow rule matched constraints for 'curl'; segment_command=curl https://evil.example; rule_index=0".to_string(),
            crate::security::policy::CommandPolicyViolation::from_block_event(
                "autonomy.command_context_rules",
                "Command blocked by command_context_rules: no allow rule matched constraints for 'curl'; segment_command=curl https://evil.example; rule_index=0",
                Some("shell curl https://evil.example"),
            )
            .render_report_with_limits(72, 120),
            "shell",
        );
        let summary = RuntimeConstraintOutcomeSummary::from_blocked(blocked.clone());

        assert_eq!(
            summary.canonical_blocked_output(),
            Some(blocked.canonical_output())
        );
        assert_eq!(
            summary.progress_detail_owned().as_deref(),
            blocked.progress_detail_owned().as_deref()
        );
    }

    #[test]
    fn cron_result_announcement_reuses_runtime_constraint_summary_for_wrapped_block() {
        let announcement = render_cron_result_announcement_with_descriptor(
            "job-1",
            "nightly",
            "every(60000ms)",
            CronLifecycleDescriptor::Shell {
                command: "curl https://evil.example",
            },
            false,
            "agent job failed: blocked by security policy: policy=autonomy.allowed_commands; command=curl https://evil.example; reason=Command not allowed by security policy: curl https://evil.example",
            CronLifecycleRenderLimits {
                detail_max_chars: 180,
                output_preview_max_chars: 220,
                command_max_chars: 220,
                reason_max_chars: 220,
            },
        )
        .expect("blocked announcement should be rendered");

        assert!(announcement.contains("Cron blocked: id=job-1"));
        assert!(announcement.contains("status=blocked_by_security_policy"));
        assert!(announcement.contains("policy=autonomy.allowed_commands"));
        assert!(announcement.contains("command=curl https://evil.example"));
        assert!(announcement
            .contains("reason=Command not allowed by security policy: curl https://evil.example"));
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

    #[test]
    fn truncate_progress_preserving_structured_lines_keeps_policy_metadata_visible() {
        let content = "status=blocked_by_security_policy\npolicy=autonomy.allowed_commands; command=cat /etc/passwd\nreason=Command not allowed by security policy\nadditional narrative that would normally be truncated away because it keeps going and going";
        let truncated = truncate_progress_preserving_structured_lines(content, 140);

        assert!(truncated.contains("status=blocked_by_security_policy"));
        assert!(truncated.contains("policy=autonomy.allowed_commands; command=cat /etc/passwd"));
        assert!(truncated.contains("reason=Command not allowed by security policy"));
    }
}
