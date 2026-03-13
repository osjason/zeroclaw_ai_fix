use super::traits::ToolResult;
use super::{action_command_preflight_for, ActionCommandPreflight};
use super::policy_blocked_result;
use crate::config::Config;
use crate::security::policy::{
    action_budget_violation, action_precheck_violation, CommandPolicyViolation,
};
use crate::security::SecurityPolicy;
use serde_json::Value;

pub(crate) struct CronJobRequest<'a> {
    pub(crate) job_id: &'a str,
    pub(crate) approved: bool,
}

const CRON_ENABLED_POLICY_ID: &str = "cron.enabled";
const CRON_DISABLED_REASON: &str = "cron is disabled by config (cron.enabled=false)";

pub(crate) fn ensure_cron_enabled(config: &Config, action: &str) -> Result<(), ToolResult> {
    if !config.cron.enabled {
        let violation = CommandPolicyViolation::from_block_event(
            CRON_ENABLED_POLICY_ID,
            CRON_DISABLED_REASON,
            Some(action),
        );
        return Err(policy_blocked_result(&violation));
    }
    Ok(())
}

pub(crate) fn parse_job_request(args: &Value) -> Result<CronJobRequest<'_>, ToolResult> {
    let job_id = match args.get("job_id").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => value,
        _ => return Err(missing_param("job_id")),
    };

    let approved = args
        .get("approved")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(CronJobRequest { job_id, approved })
}

pub(crate) fn precheck_action_allowed(
    security: &SecurityPolicy,
    action: &str,
) -> Option<ToolResult> {
    action_precheck_violation(security, action).map(|blocked| policy_blocked_result(&blocked))
}

pub(crate) fn preflight_command_allowed(
    security: &SecurityPolicy,
    action: &str,
    command: Option<&str>,
    approved: bool,
) -> Option<ToolResult> {
    action_command_preflight_for(
        security,
        ActionCommandPreflight::new(action, command, approved),
    )
}

pub(crate) fn consume_action_budget(security: &SecurityPolicy, action: &str) -> Option<ToolResult> {
    action_budget_violation(security, action).map(|blocked| policy_blocked_result(&blocked))
}

fn missing_param(name: &str) -> ToolResult {
    ToolResult {
        success: false,
        output: String::new(),
        error: Some(format!("Missing '{name}' parameter")),
    }
}
