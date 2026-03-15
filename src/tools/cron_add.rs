use super::cron_common::{ensure_cron_enabled, preflight_command_allowed};
use super::traits::{Tool, ToolResult};
use crate::config::Config;
use crate::cron::{self, DeliveryConfig, JobType, Schedule, SessionTarget};
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

pub struct CronAddTool {
    config: Arc<Config>,
    security: Arc<SecurityPolicy>,
}

const MIN_AGENT_EVERY_MS: u64 = 5 * 60 * 1000;
const AGENT_RECURRING_CONFIRMATION_ERROR: &str =
    "Agent jobs with recurring schedules require recurring_confirmed=true. \
For one-time reminders, use schedule.kind='at' with an RFC3339 timestamp.";

enum CronAddJob {
    Shell {
        command: String,
    },
    Agent {
        prompt: String,
        session_target: SessionTarget,
        model: Option<String>,
        delivery: Option<DeliveryConfig>,
    },
}

impl CronAddJob {
    fn command_for_preflight(&self) -> Option<&str> {
        match self {
            Self::Shell { command } => Some(command.as_str()),
            Self::Agent { .. } => None,
        }
    }
}

impl CronAddTool {
    pub fn new(config: Arc<Config>, security: Arc<SecurityPolicy>) -> Self {
        Self { config, security }
    }
}

#[async_trait]
impl Tool for CronAddTool {
    fn name(&self) -> &str {
        "cron_add"
    }

    fn description(&self) -> &str {
        "Create a scheduled cron job (shell or agent) with cron/at/every schedules. \
         Use job_type='agent' with a prompt to run the AI agent on schedule. \
         Use schedule.kind='at' for one-time reminders/delayed sends (recommended). \
         Agent jobs with schedule.kind='cron' or schedule.kind='every' are recurring and require explicit recurring confirmation. \
         To deliver output to a channel (Discord, Telegram, Slack, Mattermost, QQ, Napcat, Lark, Feishu, Email), set \
         delivery={\"mode\":\"announce\",\"channel\":\"discord\",\"to\":\"<channel_id_or_chat_id>\"}. \
         This is the preferred tool for sending scheduled/delayed messages to users via channels."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "schedule": {
                    "type": "object",
                    "description": "Schedule object: {kind:'cron',expr,tz?} recurring | {kind:'at',at} one-time | {kind:'every',every_ms} recurring interval"
                },
                "job_type": { "type": "string", "enum": ["shell", "agent"] },
                "command": { "type": "string" },
                "prompt": { "type": "string" },
                "session_target": { "type": "string", "enum": ["isolated", "main"] },
                "model": { "type": "string" },
                "recurring_confirmed": {
                    "type": "boolean",
                    "description": "Required for agent recurring schedules (schedule.kind='cron' or 'every'). Set true only when recurring behavior is intentional.",
                    "default": false
                },
                "delivery": {
                    "type": "object",
                    "description": "Delivery config to send job output to a channel. Example: {\"mode\":\"announce\",\"channel\":\"discord\",\"to\":\"<channel_id>\"}",
                    "properties": {
                        "mode": { "type": "string", "enum": ["none", "announce"], "description": "Set to 'announce' to deliver output to a channel" },
                        "channel": { "type": "string", "enum": ["telegram", "discord", "slack", "mattermost", "qq", "napcat", "lark", "feishu", "email"], "description": "Channel type to deliver to" },
                        "to": { "type": "string", "description": "Target: Discord channel ID, Telegram chat ID, Slack channel, etc." },
                        "best_effort": { "type": "boolean", "description": "If true, delivery failure does not fail the job" }
                    }
                },
                "delete_after_run": { "type": "boolean" },
                "approved": {
                    "type": "boolean",
                    "description": "Set true to explicitly approve medium/high-risk shell commands in supervised mode",
                    "default": false
                }
            },
            "required": ["schedule"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        if let Err(blocked) = ensure_cron_enabled(&self.config, "cron_add") {
            return Ok(blocked);
        }

        let schedule = match args.get("schedule") {
            Some(v) => match serde_json::from_value::<Schedule>(v.clone()) {
                Ok(schedule) => schedule,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Invalid schedule: {e}")),
                    });
                }
            },
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing 'schedule' parameter".to_string()),
                });
            }
        };

        let name = args
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        let job_type = match args.get("job_type").and_then(serde_json::Value::as_str) {
            Some("agent") => JobType::Agent,
            Some("shell") => JobType::Shell,
            Some(other) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Invalid job_type: {other}")),
                });
            }
            None => {
                if args.get("prompt").is_some() {
                    JobType::Agent
                } else {
                    JobType::Shell
                }
            }
        };

        let default_delete_after_run = matches!(schedule, Schedule::At { .. });
        let delete_after_run = args
            .get("delete_after_run")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(default_delete_after_run);
        let approved = args
            .get("approved")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let job = match job_type {
            JobType::Shell => {
                let command = match args.get("command").and_then(serde_json::Value::as_str) {
                    Some(command) if !command.trim().is_empty() => command,
                    _ => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some("Missing 'command' for shell job".to_string()),
                        });
                    }
                };
                CronAddJob::Shell {
                    command: command.to_string(),
                }
            }
            JobType::Agent => {
                let prompt = match args.get("prompt").and_then(serde_json::Value::as_str) {
                    Some(prompt) if !prompt.trim().is_empty() => prompt,
                    _ => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some("Missing 'prompt' for agent job".to_string()),
                        });
                    }
                };

                let session_target = match args.get("session_target") {
                    Some(v) => match serde_json::from_value::<SessionTarget>(v.clone()) {
                        Ok(target) => target,
                        Err(e) => {
                            return Ok(ToolResult {
                                success: false,
                                output: String::new(),
                                error: Some(format!("Invalid session_target: {e}")),
                            });
                        }
                    },
                    None => SessionTarget::Isolated,
                };

                let model = args
                    .get("model")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string);
                let recurring_confirmed = args
                    .get("recurring_confirmed")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);

                match &schedule {
                    Schedule::Every { every_ms } => {
                        if !recurring_confirmed {
                            return Ok(ToolResult {
                                success: false,
                                output: String::new(),
                                error: Some(AGENT_RECURRING_CONFIRMATION_ERROR.to_string()),
                            });
                        }
                        if *every_ms < MIN_AGENT_EVERY_MS {
                            return Ok(ToolResult {
                                success: false,
                                output: String::new(),
                                error: Some(format!(
                                    "Agent schedule.kind='every' must be >= {MIN_AGENT_EVERY_MS} ms (5 minutes)"
                                )),
                            });
                        }
                    }
                    Schedule::Cron { .. } => {
                        if !recurring_confirmed {
                            return Ok(ToolResult {
                                success: false,
                                output: String::new(),
                                error: Some(AGENT_RECURRING_CONFIRMATION_ERROR.to_string()),
                            });
                        }
                    }
                    Schedule::At { .. } => {}
                }

                let delivery = match args.get("delivery") {
                    Some(v) => match serde_json::from_value::<DeliveryConfig>(v.clone()) {
                        Ok(cfg) => Some(cfg),
                        Err(e) => {
                            return Ok(ToolResult {
                                success: false,
                                output: String::new(),
                                error: Some(format!("Invalid delivery config: {e}")),
                            });
                        }
                    },
                    None => None,
                };

                CronAddJob::Agent {
                    prompt: prompt.to_string(),
                    session_target,
                    model,
                    delivery,
                }
            }
        };

        if let Some(blocked) = preflight_command_allowed(
            self.security.as_ref(),
            "cron_add",
            job.command_for_preflight(),
            approved,
        ) {
            return Ok(blocked);
        }

        let result = match job {
            CronAddJob::Shell { command } => {
                cron::add_shell_job(&self.config, name, schedule, &command)
            }
            CronAddJob::Agent {
                prompt,
                session_target,
                model,
                delivery,
            } => cron::add_agent_job(
                &self.config,
                name,
                schedule,
                &prompt,
                session_target,
                model,
                delivery,
                delete_after_run,
            ),
        };

        match result {
            Ok(job) => Ok(ToolResult {
                success: true,
                output: serde_json::to_string_pretty(&json!({
                    "id": job.id,
                    "name": job.name,
                    "job_type": job.job_type,
                    "schedule": job.schedule,
                    "next_run": job.next_run,
                    "enabled": job.enabled
                }))?,
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e.to_string()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::security::policy::parse_security_policy_block_event;
    use crate::security::AutonomyLevel;
    use crate::tools::{action_command_preflight_for, ActionCommandPreflight};
    use tempfile::TempDir;

    async fn test_config(tmp: &TempDir) -> Arc<Config> {
        let config = Config {
            workspace_dir: tmp.path().join("workspace"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        tokio::fs::create_dir_all(&config.workspace_dir)
            .await
            .unwrap();
        Arc::new(config)
    }

    fn test_security(cfg: &Config) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy::from_config(
            &cfg.autonomy,
            &cfg.workspace_dir,
        ))
    }

    #[tokio::test]
    async fn adds_shell_job() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let tool = CronAddTool::new(cfg.clone(), test_security(&cfg));
        let result = tool
            .execute(json!({
                "schedule": { "kind": "cron", "expr": "*/5 * * * *" },
                "job_type": "shell",
                "command": "echo ok"
            }))
            .await
            .unwrap();

        assert!(result.success, "{:?}", result.error);
        assert!(result.output.contains("next_run"));
    }

    #[tokio::test]
    async fn blocks_disallowed_shell_command() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config {
            workspace_dir: tmp.path().join("workspace"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        config.autonomy.allowed_commands = vec!["echo".into()];
        config.autonomy.level = AutonomyLevel::Supervised;
        tokio::fs::create_dir_all(&config.workspace_dir)
            .await
            .unwrap();
        let cfg = Arc::new(config);
        let tool = CronAddTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "schedule": { "kind": "cron", "expr": "*/5 * * * *" },
                "job_type": "shell",
                "command": "curl https://example.com"
            }))
            .await
            .unwrap();

        assert!(!result.success);
        let blocked = result.error.unwrap_or_default();
        let event = parse_security_policy_block_event(&blocked)
            .expect("cron_add should expose structured security block event");
        assert_eq!(event.policy_id, "autonomy.allowed_commands");
        assert_eq!(event.command_fragment, "curl https://example.com");
        assert!(event.reason.contains("Command blocked by allowed_commands"));
    }

    #[tokio::test]
    async fn blocks_disallowed_shell_command_matches_preflight_event_fields() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config {
            workspace_dir: tmp.path().join("workspace"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        config.autonomy.allowed_commands = vec!["echo".into()];
        config.autonomy.level = AutonomyLevel::Supervised;
        tokio::fs::create_dir_all(&config.workspace_dir)
            .await
            .unwrap();
        let cfg = Arc::new(config);
        let security = test_security(&cfg);
        let command = "curl https://example.com";
        let preflight = action_command_preflight_for(
            security.as_ref(),
            ActionCommandPreflight::new("cron_add", Some(command), false),
        )
        .expect("expected cron_add preflight to block disallowed command");
        assert!(!preflight.success);
        let preflight_event = parse_security_policy_block_event(
            preflight
                .error
                .as_deref()
                .expect("preflight block should include structured error"),
        )
        .expect("preflight block should parse into structured policy event");

        let tool = CronAddTool::new(cfg, security);
        let result = tool
            .execute(json!({
                "schedule": { "kind": "cron", "expr": "*/5 * * * *" },
                "job_type": "shell",
                "command": command
            }))
            .await
            .unwrap();
        assert!(!result.success);
        let event = parse_security_policy_block_event(
            result
                .error
                .as_deref()
                .expect("cron_add block should include structured error"),
        )
        .expect("cron_add block should parse into structured policy event");

        assert_eq!(event.policy_id, preflight_event.policy_id);
        assert_eq!(event.command_fragment, preflight_event.command_fragment);
        assert_eq!(event.reason, preflight_event.reason);
    }

    #[tokio::test]
    async fn blocks_mutation_in_read_only_mode() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config {
            workspace_dir: tmp.path().join("workspace"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        config.autonomy.level = AutonomyLevel::ReadOnly;
        std::fs::create_dir_all(&config.workspace_dir).unwrap();
        let cfg = Arc::new(config);
        let tool = CronAddTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "schedule": { "kind": "cron", "expr": "*/5 * * * *" },
                "job_type": "shell",
                "command": "echo ok"
            }))
            .await
            .unwrap();

        assert!(!result.success);
        let blocked = result.error.unwrap_or_default();
        let event = parse_security_policy_block_event(&blocked)
            .expect("cron_add read-only block should expose structured security block event");
        assert_eq!(event.policy_id, "autonomy.read_only");
        assert_eq!(event.command_fragment, "echo ok");
        assert!(event.reason.contains("read-only"));
    }

    #[tokio::test]
    async fn blocks_add_when_rate_limited() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config {
            workspace_dir: tmp.path().join("workspace"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        config.autonomy.level = AutonomyLevel::Full;
        config.autonomy.max_actions_per_hour = 0;
        std::fs::create_dir_all(&config.workspace_dir).unwrap();
        let cfg = Arc::new(config);
        let tool = CronAddTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "schedule": { "kind": "cron", "expr": "*/5 * * * *" },
                "job_type": "shell",
                "command": "echo ok"
            }))
            .await
            .unwrap();

        assert!(!result.success);
        let blocked = result.error.unwrap_or_default();
        let event = parse_security_policy_block_event(&blocked)
            .expect("cron_add rate-limit block should expose structured security block event");
        assert_eq!(event.policy_id, "autonomy.max_actions_per_hour");
        assert_eq!(event.command_fragment, "echo ok");
        assert!(event.reason.contains("Rate limit exceeded"));
        assert!(cron::list_jobs(&cfg).unwrap().is_empty());
    }

    #[tokio::test]
    async fn medium_risk_shell_command_requires_approval() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config {
            workspace_dir: tmp.path().join("workspace"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        config.autonomy.allowed_commands = vec!["touch".into()];
        config.autonomy.level = AutonomyLevel::Supervised;
        std::fs::create_dir_all(&config.workspace_dir).unwrap();
        let cfg = Arc::new(config);
        let security = test_security(&cfg);
        let tool = CronAddTool::new(cfg.clone(), security.clone());
        let command = "touch cron-approval-test";
        let preflight = action_command_preflight_for(
            security.as_ref(),
            ActionCommandPreflight::new("cron_add", Some(command), false),
        )
        .expect("expected cron_add preflight to require approval");
        assert!(!preflight.success);
        let preflight_event = parse_security_policy_block_event(
            preflight
                .error
                .as_deref()
                .expect("preflight block should include structured error"),
        )
        .expect("preflight block should parse into structured policy event");

        let denied = tool
            .execute(json!({
                "schedule": { "kind": "cron", "expr": "*/5 * * * *" },
                "job_type": "shell",
                "command": command
            }))
            .await
            .unwrap();
        assert!(!denied.success);
        let denied_event = parse_security_policy_block_event(
            denied
                .error
                .as_deref()
                .expect("cron_add approval block should include structured error"),
        )
        .expect("cron_add approval block should parse into structured policy event");
        assert_eq!(denied_event.policy_id, preflight_event.policy_id);
        assert_eq!(
            denied_event.command_fragment,
            preflight_event.command_fragment
        );
        assert_eq!(denied_event.reason, preflight_event.reason);

        let approved = tool
            .execute(json!({
                "schedule": { "kind": "cron", "expr": "*/5 * * * *" },
                "job_type": "shell",
                "command": command,
                "approved": true
            }))
            .await
            .unwrap();
        assert!(approved.success, "{:?}", approved.error);
    }

    #[tokio::test]
    async fn rejects_invalid_schedule() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let tool = CronAddTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "schedule": { "kind": "every", "every_ms": 0 },
                "job_type": "shell",
                "command": "echo nope"
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .unwrap_or_default()
            .contains("every_ms must be > 0"));
    }

    #[tokio::test]
    async fn agent_job_requires_prompt() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let tool = CronAddTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "schedule": { "kind": "cron", "expr": "*/5 * * * *" },
                "job_type": "agent"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .unwrap_or_default()
            .contains("Missing 'prompt'"));
    }

    #[tokio::test]
    async fn agent_every_requires_recurring_confirmation() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let tool = CronAddTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "schedule": { "kind": "every", "every_ms": 300000 },
                "job_type": "agent",
                "prompt": "Send me a recurring status update"
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .unwrap_or_default()
            .contains("recurring_confirmed=true"));
    }

    #[tokio::test]
    async fn agent_cron_requires_recurring_confirmation() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let tool = CronAddTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "schedule": { "kind": "cron", "expr": "*/5 * * * *" },
                "job_type": "agent",
                "prompt": "Send recurring reminders"
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .unwrap_or_default()
            .contains("recurring_confirmed=true"));
    }

    #[tokio::test]
    async fn agent_every_rejects_high_frequency_intervals() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let tool = CronAddTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "schedule": { "kind": "every", "every_ms": 60000 },
                "job_type": "agent",
                "prompt": "Send me updates frequently",
                "recurring_confirmed": true
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .unwrap_or_default()
            .contains("must be >= 300000 ms"));
    }

    #[tokio::test]
    async fn agent_every_with_explicit_confirmation_succeeds() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let tool = CronAddTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "schedule": { "kind": "every", "every_ms": 300000 },
                "job_type": "agent",
                "prompt": "Share a heartbeat summary",
                "recurring_confirmed": true
            }))
            .await
            .unwrap();

        assert!(result.success, "{:?}", result.error);
        assert!(result.output.contains("next_run"));
    }
}
