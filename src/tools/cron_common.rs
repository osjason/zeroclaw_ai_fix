use super::policy_blocked_result;
use super::traits::ToolResult;
use crate::config::Config;
use crate::security::policy::{action_budget_violation, action_precheck_violation};
use crate::security::SecurityPolicy;
use serde_json::Value;

pub(crate) struct CronJobRequest<'a> {
    pub(crate) job_id: &'a str,
    pub(crate) approved: bool,
}

pub(crate) fn ensure_cron_enabled(config: &Config) -> Result<(), ToolResult> {
    if !config.cron.enabled {
        return Err(ToolResult {
            success: false,
            output: String::new(),
            error: Some("cron is disabled by config (cron.enabled=false)".to_string()),
        });
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

pub(crate) fn consume_action_budget(security: &SecurityPolicy, action: &str) -> Option<ToolResult> {
    action_budget_violation(security, action).map(|blocked| policy_blocked_result(&blocked))
}

pub(crate) fn enforce_action_command_gate(
    security: &SecurityPolicy,
    action: &str,
    command: Option<&str>,
    approved: bool,
) -> Result<(), ToolResult> {
    super::action_command_preflight_result(security, action, command, approved).map_or(Ok(()), Err)
}

fn missing_param(name: &str) -> ToolResult {
    ToolResult {
        success: false,
        output: String::new(),
        error: Some(format!("Missing '{name}' parameter")),
    }
}
