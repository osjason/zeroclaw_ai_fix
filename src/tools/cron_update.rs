use super::cron_common::{ensure_cron_enabled, parse_job_request, preflight_command_allowed};
use super::traits::{Tool, ToolResult};
use crate::config::Config;
use crate::cron::{self, CronJobPatch, DeliveryConfig, JobType, Schedule};
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

pub struct CronUpdateTool {
    config: Arc<Config>,
    security: Arc<SecurityPolicy>,
}

struct CronUpdateRequest {
    job_id: String,
    approved: bool,
    patch: CronJobPatch,
    default_delivery: Option<DeliveryConfig>,
}

impl CronUpdateRequest {
    fn command_for_preflight(&self) -> Option<&str> {
        self.patch.command.as_deref()
    }
}

impl CronUpdateTool {
    pub fn new(config: Arc<Config>, security: Arc<SecurityPolicy>) -> Self {
        Self { config, security }
    }

    fn error_result(message: impl Into<String>) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message.into()),
        }
    }

    fn parse_default_delivery(
        args: &serde_json::Value,
    ) -> Result<Option<DeliveryConfig>, ToolResult> {
        match args.get("default_delivery") {
            Some(value) => serde_json::from_value::<DeliveryConfig>(value.clone())
                .map(Some)
                .map_err(|e| Self::error_result(format!("Invalid default_delivery payload: {e}"))),
            None => Ok(None),
        }
    }

    fn parse_patch(args: &serde_json::Value) -> Result<CronJobPatch, ToolResult> {
        let patch_val = match args.get("patch") {
            Some(value) => value.clone(),
            None => return Err(Self::error_result("Missing 'patch' parameter")),
        };
        serde_json::from_value::<CronJobPatch>(patch_val)
            .map_err(|e| Self::error_result(format!("Invalid patch payload: {e}")))
    }

    fn parse_request(args: &serde_json::Value) -> Result<CronUpdateRequest, ToolResult> {
        let request = parse_job_request(args)?;
        Ok(CronUpdateRequest {
            job_id: request.job_id.to_string(),
            approved: request.approved,
            patch: Self::parse_patch(args)?,
            default_delivery: Self::parse_default_delivery(args)?,
        })
    }

    fn should_apply_default_delivery(
        existing_job: &crate::cron::CronJob,
        patch: &CronJobPatch,
        default_delivery: Option<&DeliveryConfig>,
    ) -> bool {
        if patch.delivery.is_some()
            || default_delivery.is_none()
            || !matches!(existing_job.job_type, JobType::Agent)
            || !matches!(existing_job.schedule, Schedule::At { .. })
            || existing_job
                .name
                .as_deref()
                .is_some_and(|name| name.starts_with("__"))
        {
            return false;
        }

        let mode = existing_job.delivery.mode.trim();
        let channel = existing_job
            .delivery
            .channel
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let target = existing_job
            .delivery
            .to
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        (mode.is_empty() || mode.eq_ignore_ascii_case("none"))
            && channel.is_none()
            && target.is_none()
    }
}

#[async_trait]
impl Tool for CronUpdateTool {
    fn name(&self) -> &str {
        "cron_update"
    }

    fn description(&self) -> &str {
        "Patch an existing cron job (schedule, command, prompt, enabled, delivery, model, etc.)"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "job_id": { "type": "string" },
                "patch": { "type": "object" },
                "approved": {
                    "type": "boolean",
                    "description": "Set true to explicitly approve medium/high-risk shell commands in supervised mode",
                    "default": false
                }
            },
            "required": ["job_id", "patch"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        if let Err(blocked) = ensure_cron_enabled(&self.config, "cron_update") {
            return Ok(blocked);
        }
        let request = match Self::parse_request(&args) {
            Ok(request) => request,
            Err(blocked) => return Ok(blocked),
        };
        if let Some(blocked) = preflight_command_allowed(
            self.security.as_ref(),
            "cron_update",
            request.command_for_preflight(),
            request.approved,
        ) {
            return Ok(blocked);
        }
        let CronUpdateRequest {
            job_id,
            mut patch,
            default_delivery,
            ..
        } = request;

        let existing_job = match cron::get_job(&self.config, &job_id) {
            Ok(job) => job,
            Err(e) => {
                return Ok(Self::error_result(e.to_string()));
            }
        };
        if Self::should_apply_default_delivery(&existing_job, &patch, default_delivery.as_ref()) {
            patch.delivery = default_delivery;
        }

        match cron::update_job(&self.config, &job_id, patch) {
            Ok(job) => Ok(ToolResult {
                success: true,
                output: serde_json::to_string_pretty(&job)?,
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                ..Self::error_result(e.to_string())
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
    async fn updates_enabled_flag() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let job = cron::add_job(&cfg, "*/5 * * * *", "echo ok").unwrap();
        let tool = CronUpdateTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "job_id": job.id,
                "patch": { "enabled": false }
            }))
            .await
            .unwrap();

        assert!(result.success, "{:?}", result.error);
        assert!(result.output.contains("\"enabled\": false"));
    }

    #[tokio::test]
    async fn blocks_disallowed_command_updates() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config {
            workspace_dir: tmp.path().join("workspace"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        config.autonomy.allowed_commands = vec!["echo".into()];
        tokio::fs::create_dir_all(&config.workspace_dir)
            .await
            .unwrap();
        let cfg = Arc::new(config);
        let job = cron::add_job(&cfg, "*/5 * * * *", "echo ok").unwrap();
        let tool = CronUpdateTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "job_id": job.id,
                "patch": { "command": "curl https://example.com" }
            }))
            .await
            .unwrap();
        assert!(!result.success);
        let blocked = result.error.unwrap_or_default();
        let event = parse_security_policy_block_event(&blocked)
            .expect("cron_update should expose structured security block event");
        assert_eq!(event.policy_id, "autonomy.allowed_commands");
        assert_eq!(event.command_fragment, "curl https://example.com");
        assert!(event.reason.contains("Command blocked by allowed_commands"));
    }

    #[tokio::test]
    async fn blocks_disallowed_command_updates_match_preflight_event_fields() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config {
            workspace_dir: tmp.path().join("workspace"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        config.autonomy.allowed_commands = vec!["echo".into()];
        tokio::fs::create_dir_all(&config.workspace_dir)
            .await
            .unwrap();
        let cfg = Arc::new(config);
        let security = test_security(&cfg);
        let command = "curl https://example.com";
        let preflight = action_command_preflight_for(
            security.as_ref(),
            ActionCommandPreflight::new("cron_update", Some(command), false),
        )
        .expect("expected cron_update preflight to block disallowed command");
        assert!(!preflight.success);
        let preflight_event = parse_security_policy_block_event(
            preflight
                .error
                .as_deref()
                .expect("preflight block should include structured error"),
        )
        .expect("preflight block should parse into structured policy event");

        let job = cron::add_job(&cfg, "*/5 * * * *", "echo ok").unwrap();
        let tool = CronUpdateTool::new(cfg, security);
        let result = tool
            .execute(json!({
                "job_id": job.id,
                "patch": { "command": command }
            }))
            .await
            .unwrap();
        assert!(!result.success);
        let event = parse_security_policy_block_event(
            result
                .error
                .as_deref()
                .expect("cron_update block should include structured error"),
        )
        .expect("cron_update block should parse into structured policy event");

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
        let job = cron::add_job(&cfg, "*/5 * * * *", "echo ok").unwrap();
        let tool = CronUpdateTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "job_id": job.id,
                "patch": { "enabled": false }
            }))
            .await
            .unwrap();
        assert!(!result.success);
        let blocked = result.error.unwrap_or_default();
        let event = parse_security_policy_block_event(&blocked)
            .expect("cron_update read-only block should expose structured security block event");
        assert_eq!(event.policy_id, "autonomy.read_only");
        assert_eq!(event.command_fragment, "cron_update");
        assert!(event.reason.contains("read-only"));
    }

    #[tokio::test]
    async fn medium_risk_shell_update_requires_approval() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config {
            workspace_dir: tmp.path().join("workspace"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        config.autonomy.level = AutonomyLevel::Supervised;
        config.autonomy.allowed_commands = vec!["echo".into(), "touch".into()];
        std::fs::create_dir_all(&config.workspace_dir).unwrap();
        let cfg = Arc::new(config);
        let security = test_security(&cfg);
        let command = "touch cron-update-approval-test";
        let preflight = action_command_preflight_for(
            security.as_ref(),
            ActionCommandPreflight::new("cron_update", Some(command), false),
        )
        .expect("expected cron_update preflight to require explicit approval");
        assert!(!preflight.success);
        let preflight_event = parse_security_policy_block_event(
            preflight
                .error
                .as_deref()
                .expect("preflight approval block should include structured error"),
        )
        .expect("preflight approval block should parse into structured policy event");
        let job = cron::add_job(&cfg, "*/5 * * * *", "echo ok").unwrap();
        let tool = CronUpdateTool::new(cfg.clone(), security);

        let denied = tool
            .execute(json!({
                "job_id": job.id,
                "patch": { "command": command }
            }))
            .await
            .unwrap();
        assert!(!denied.success);
        let denied_event = parse_security_policy_block_event(
            denied
                .error
                .as_deref()
                .expect("cron_update approval block should include structured error"),
        )
        .expect("cron_update approval block should parse into structured policy event");
        assert_eq!(denied_event.policy_id, preflight_event.policy_id);
        assert_eq!(
            denied_event.command_fragment,
            preflight_event.command_fragment
        );
        assert_eq!(denied_event.reason, preflight_event.reason);

        let approved = tool
            .execute(json!({
                "job_id": job.id,
                "patch": { "command": command },
                "approved": true
            }))
            .await
            .unwrap();
        assert!(approved.success, "{:?}", approved.error);
    }

    #[tokio::test]
    async fn blocks_update_when_rate_limited() {
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
        let job = cron::add_job(&cfg, "*/5 * * * *", "echo ok").unwrap();
        let tool = CronUpdateTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "job_id": job.id,
                "patch": { "command": "echo should-not-run" }
            }))
            .await
            .unwrap();
        assert!(!result.success);
        let blocked = result.error.unwrap_or_default();
        let event = parse_security_policy_block_event(&blocked)
            .expect("cron_update rate-limit block should expose structured security block event");
        assert_eq!(event.policy_id, "autonomy.max_actions_per_hour");
        assert_eq!(event.command_fragment, "echo should-not-run");
        assert!(event.reason.contains("Rate limit exceeded"));
        assert_eq!(cron::get_job(&cfg, &job.id).unwrap().command, "echo ok");
    }

    #[tokio::test]
    async fn applies_default_delivery_to_agent_jobs_when_patch_omits_it() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let job = cron::add_agent_job(
            &cfg,
            Some("daily-summary".into()),
            cron::Schedule::At {
                at: chrono::Utc::now() + chrono::Duration::minutes(10),
            },
            "summarize the latest alerts",
            crate::cron::SessionTarget::Isolated,
            None,
            None,
            true,
        )
        .unwrap();
        let tool = CronUpdateTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "job_id": job.id,
                "patch": { "enabled": true },
                "default_delivery": {
                    "mode": "announce",
                    "channel": "feishu",
                    "to": "oc_chat_123"
                }
            }))
            .await
            .unwrap();

        assert!(result.success, "{:?}", result.error);
        let updated = cron::get_job(&cfg, &job.id).unwrap();
        assert_eq!(updated.delivery.mode, "announce");
        assert_eq!(updated.delivery.channel.as_deref(), Some("feishu"));
        assert_eq!(updated.delivery.to.as_deref(), Some("oc_chat_123"));
    }

    #[tokio::test]
    async fn does_not_override_existing_delivery_on_agent_job_update() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let job = cron::add_agent_job(
            &cfg,
            Some("daily-summary".into()),
            cron::Schedule::At {
                at: chrono::Utc::now() + chrono::Duration::minutes(10),
            },
            "summarize the latest alerts",
            crate::cron::SessionTarget::Isolated,
            None,
            Some(DeliveryConfig {
                mode: "announce".into(),
                channel: Some("discord".into()),
                to: Some("C123".into()),
                best_effort: true,
            }),
            true,
        )
        .unwrap();
        let tool = CronUpdateTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "job_id": job.id,
                "patch": { "enabled": true },
                "default_delivery": {
                    "mode": "announce",
                    "channel": "feishu",
                    "to": "oc_chat_123"
                }
            }))
            .await
            .unwrap();

        assert!(result.success, "{:?}", result.error);
        let updated = cron::get_job(&cfg, &job.id).unwrap();
        assert_eq!(updated.delivery.mode, "announce");
        assert_eq!(updated.delivery.channel.as_deref(), Some("discord"));
        assert_eq!(updated.delivery.to.as_deref(), Some("C123"));
    }

    #[tokio::test]
    async fn does_not_apply_default_delivery_to_recurring_or_internal_jobs() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let recurring_job = cron::add_agent_job(
            &cfg,
            Some("__consolidate_nightly".into()),
            cron::Schedule::Cron {
                expr: "0 3 * * *".into(),
                tz: None,
            },
            "internal maintenance task",
            crate::cron::SessionTarget::Isolated,
            None,
            None,
            false,
        )
        .unwrap();
        let tool = CronUpdateTool::new(cfg.clone(), test_security(&cfg));

        let result = tool
            .execute(json!({
                "job_id": recurring_job.id,
                "patch": { "enabled": true },
                "default_delivery": {
                    "mode": "announce",
                    "channel": "feishu",
                    "to": "oc_chat_123"
                }
            }))
            .await
            .unwrap();

        assert!(result.success, "{:?}", result.error);
        let updated = cron::get_job(&cfg, &recurring_job.id).unwrap();
        assert_eq!(updated.delivery.mode, "none");
        assert!(updated.delivery.channel.is_none());
        assert!(updated.delivery.to.is_none());
    }
}
