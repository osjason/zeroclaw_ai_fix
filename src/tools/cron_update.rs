use super::cron_common::{
    consume_action_budget, ensure_cron_enabled, parse_job_request, precheck_action_allowed,
};
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

impl CronUpdateTool {
    pub fn new(config: Arc<Config>, security: Arc<SecurityPolicy>) -> Self {
        Self { config, security }
    }

    fn parse_default_delivery(args: &serde_json::Value) -> Result<Option<DeliveryConfig>, String> {
        match args.get("default_delivery") {
            Some(value) => serde_json::from_value::<DeliveryConfig>(value.clone())
                .map(Some)
                .map_err(|e| format!("Invalid default_delivery payload: {e}")),
            None => Ok(None),
        }
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
        if let Err(blocked) = ensure_cron_enabled(&self.config) {
            return Ok(blocked);
        }
        let request = match parse_job_request(&args) {
            Ok(request) => request,
            Err(blocked) => return Ok(blocked),
        };
        let job_id = request.job_id;
        let approved = request.approved;

        let patch_val = match args.get("patch") {
            Some(v) => v.clone(),
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing 'patch' parameter".to_string()),
                });
            }
        };

        let patch = match serde_json::from_value::<CronJobPatch>(patch_val) {
            Ok(patch) => patch,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Invalid patch payload: {e}")),
                });
            }
        };
        let default_delivery = match Self::parse_default_delivery(&args) {
            Ok(default_delivery) => default_delivery,
            Err(error) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(error),
                });
            }
        };

        if let Some(command) = &patch.command {
            if let Err(reason) = self.security.validate_command_execution(command, approved) {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(reason),
                });
            }
        }

        let mut patch = patch;
        let existing_job = match cron::get_job(&self.config, job_id) {
            Ok(job) => job,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(e.to_string()),
                });
            }
        };
        if Self::should_apply_default_delivery(&existing_job, &patch, default_delivery.as_ref()) {
            patch.delivery = default_delivery;
        }

        if let Some(blocked) = precheck_action_allowed(&self.security, "cron_update") {
            return Ok(blocked);
        }
        if let Some(blocked) = consume_action_budget(&self.security) {
            return Ok(blocked);
        }

        match cron::update_job(&self.config, job_id, patch) {
            Ok(job) => Ok(ToolResult {
                success: true,
                output: serde_json::to_string_pretty(&job)?,
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
    use crate::security::AutonomyLevel;
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
        assert!(result.error.unwrap_or_default().contains("not allowed"));
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
        assert!(result.error.unwrap_or_default().contains("read-only"));
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
        let job = cron::add_job(&cfg, "*/5 * * * *", "echo ok").unwrap();
        let tool = CronUpdateTool::new(cfg.clone(), test_security(&cfg));

        let denied = tool
            .execute(json!({
                "job_id": job.id,
                "patch": { "command": "touch cron-update-approval-test" }
            }))
            .await
            .unwrap();
        assert!(!denied.success);
        assert!(denied
            .error
            .unwrap_or_default()
            .contains("explicit approval"));

        let approved = tool
            .execute(json!({
                "job_id": job.id,
                "patch": { "command": "touch cron-update-approval-test" },
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
                "patch": { "enabled": false }
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .unwrap_or_default()
            .contains("Rate limit exceeded"));
        assert!(cron::get_job(&cfg, &job.id).unwrap().enabled);
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
