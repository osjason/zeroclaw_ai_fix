use super::traits::ToolResult;
use crate::config::Config;
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
    if !security.can_act() {
        return Some(ToolResult {
            success: false,
            output: String::new(),
            error: Some(format!(
                "Security policy: read-only mode, cannot perform '{action}'"
            )),
        });
    }

    if security.is_rate_limited() {
        return Some(ToolResult {
            success: false,
            output: String::new(),
            error: Some("Rate limit exceeded: too many actions in the last hour".to_string()),
        });
    }

    None
}

pub(crate) fn consume_action_budget(security: &SecurityPolicy) -> Option<ToolResult> {
    if security.record_action() {
        None
    } else {
        Some(ToolResult {
            success: false,
            output: String::new(),
            error: Some("Rate limit exceeded: action budget exhausted".to_string()),
        })
    }
}

fn missing_param(name: &str) -> ToolResult {
    ToolResult {
        success: false,
        output: String::new(),
        error: Some(format!("Missing '{name}' parameter")),
    }
}
