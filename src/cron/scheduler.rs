#[cfg(feature = "channel-lark")]
use crate::channels::LarkChannel;
#[cfg(feature = "channel-matrix")]
use crate::channels::MatrixChannel;
use crate::channels::{
    progress_event::{render_execution_event, ExecutionEvent, ExecutionSignal},
    Channel, DingTalkChannel, DiscordChannel, EmailChannel, MattermostChannel, NapcatChannel,
    QQChannel, SendMessage, SlackChannel, TelegramChannel, WhatsAppChannel,
};
use crate::config::Config;
use crate::cron::{
    due_jobs, next_run_for_schedule, record_last_run, record_run, remove_job, reschedule_after_run,
    update_job, CronJob, CronJobPatch, DeliveryConfig, JobType, Schedule, SessionTarget,
};
use crate::security::policy::{
    action_command_preflight_with_approval_violation, is_command_policy_block_message,
    parse_security_policy_block_event, CommandPolicyViolation,
};
use crate::security::SecurityPolicy;
use anyhow::Result;
use chrono::{DateTime, Utc};
use futures_util::{stream, StreamExt};
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio::time::{self, Duration};

const MIN_POLL_SECONDS: u64 = 5;
const SHELL_JOB_TIMEOUT_SECS: u64 = 120;
const SCHEDULER_COMPONENT: &str = "scheduler";
const START_ANNOUNCEMENT_PREVIEW_CHARS: usize = 180;
const RESULT_ANNOUNCEMENT_PREVIEW_CHARS: usize = 220;
const LEGACY_BLOCKED_POLICY_ID: &str = "autonomy.unknown";

pub(crate) fn is_no_reply_sentinel(output: &str) -> bool {
    output.trim().eq_ignore_ascii_case("NO_REPLY")
}

pub async fn run(config: Config) -> Result<()> {
    let poll_secs = config.reliability.scheduler_poll_secs.max(MIN_POLL_SECONDS);
    let mut interval = time::interval(Duration::from_secs(poll_secs));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let security = Arc::new(SecurityPolicy::from_config(
        &config.autonomy,
        &config.workspace_dir,
    ));

    crate::health::mark_component_ok(SCHEDULER_COMPONENT);

    loop {
        interval.tick().await;
        // Keep scheduler liveness fresh even when there are no due jobs.
        crate::health::mark_component_ok(SCHEDULER_COMPONENT);

        let jobs = match due_jobs(&config, Utc::now()) {
            Ok(jobs) => jobs,
            Err(e) => {
                crate::health::mark_component_error(SCHEDULER_COMPONENT, e.to_string());
                tracing::warn!("Scheduler query failed: {e}");
                continue;
            }
        };

        process_due_jobs(&config, &security, jobs, SCHEDULER_COMPONENT).await;
    }
}

pub async fn execute_job_now(config: &Config, job: &CronJob) -> (bool, String) {
    let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);
    Box::pin(execute_job_with_start_announcement(config, &security, job)).await
}

async fn execute_job_with_retry(
    config: &Config,
    security: &SecurityPolicy,
    job: &CronJob,
) -> (bool, String) {
    let mut last_output = String::new();
    let retries = config.reliability.scheduler_retries;
    let mut backoff_ms = config.reliability.provider_backoff_ms.max(200);

    for attempt in 0..=retries {
        let (success, output) = match job.job_type {
            JobType::Shell => run_job_command(config, security, job).await,
            JobType::Agent => Box::pin(run_agent_job(config, security, job)).await,
        };
        last_output = output;

        if success {
            return (true, last_output);
        }

        if is_command_policy_block_message(&last_output) {
            // Deterministic policy violations are not retryable.
            return (false, last_output);
        }

        if attempt < retries {
            let jitter_ms = u64::from(Utc::now().timestamp_subsec_millis() % 250);
            time::sleep(Duration::from_millis(backoff_ms + jitter_ms)).await;
            backoff_ms = (backoff_ms.saturating_mul(2)).min(30_000);
        }
    }

    (false, last_output)
}

async fn execute_job_with_start_announcement(
    config: &Config,
    security: &SecurityPolicy,
    job: &CronJob,
) -> (bool, String) {
    if let Err(e) = deliver_start_if_configured(config, job).await {
        tracing::warn!("Cron start delivery failed: {e}");
    }
    Box::pin(execute_job_with_retry(config, security, job)).await
}

async fn process_due_jobs(
    config: &Config,
    security: &Arc<SecurityPolicy>,
    jobs: Vec<CronJob>,
    component: &str,
) {
    // Refresh scheduler health on every successful poll cycle, including idle cycles.
    crate::health::mark_component_ok(component);

    let max_concurrent = config.scheduler.max_concurrent.max(1);
    let mut in_flight = stream::iter(jobs.into_iter().map(|job| {
        let config = config.clone();
        let security = Arc::clone(security);
        let component = component.to_owned();
        async move {
            Box::pin(execute_and_persist_job(
                &config,
                security.as_ref(),
                &job,
                &component,
            ))
            .await
        }
    }))
    .buffer_unordered(max_concurrent);

    while let Some((job_id, success, output)) = in_flight.next().await {
        if !success {
            tracing::warn!("Scheduler job '{job_id}' failed: {output}");
        }
    }
}

async fn execute_and_persist_job(
    config: &Config,
    security: &SecurityPolicy,
    job: &CronJob,
    component: &str,
) -> (String, bool, String) {
    crate::health::mark_component_ok(component);
    warn_if_high_frequency_agent_job(job);
    let started_at = Utc::now();
    let (success, output) =
        Box::pin(execute_job_with_start_announcement(config, security, job)).await;
    let finished_at = Utc::now();
    let success = persist_job_result(config, job, success, &output, started_at, finished_at).await;

    (job.id.clone(), success, output)
}

async fn run_agent_job(
    config: &Config,
    security: &SecurityPolicy,
    job: &CronJob,
) -> (bool, String) {
    let agent_subject = format!(
        "cron-agent:{} {}",
        job.id,
        job.prompt.as_deref().unwrap_or_default()
    );

    if let Some(blocked) =
        action_command_preflight_with_approval_violation(security, &agent_subject, None, false)
    {
        return (false, blocked.format_block_message());
    }
    let name = job.name.clone().unwrap_or_else(|| "cron-job".to_string());
    let prompt = job.prompt.clone().unwrap_or_default();
    let prefixed_prompt = format!("[cron:{} {name}] {prompt}", job.id);
    let model_override = job.model.clone();

    let run_result = match job.session_target {
        SessionTarget::Main | SessionTarget::Isolated => {
            Box::pin(crate::agent::run(
                config.clone(),
                Some(prefixed_prompt),
                None,
                model_override,
                config.default_temperature,
                vec![],
                false,
                None,
            ))
            .await
        }
    };

    match run_result {
        Ok(response) => (
            true,
            if response.trim().is_empty() {
                "agent job executed".to_string()
            } else {
                response
            },
        ),
        Err(e) => (false, format!("agent job failed: {e}")),
    }
}

async fn persist_job_result(
    config: &Config,
    job: &CronJob,
    mut success: bool,
    output: &str,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
) -> bool {
    let duration_ms = (finished_at - started_at).num_milliseconds();
    let announce_output = build_job_result_announcement(job, success, output);

    if let Err(e) = deliver_if_configured(config, job, &announce_output).await {
        if job.delivery.best_effort {
            tracing::warn!("Cron delivery failed (best_effort): {e}");
        } else {
            success = false;
            tracing::warn!("Cron delivery failed: {e}");
        }
    }

    let _ = record_run(
        config,
        &job.id,
        started_at,
        finished_at,
        if success { "ok" } else { "error" },
        Some(output),
        duration_ms,
    );

    if is_one_shot_auto_delete(job) {
        if success {
            if let Err(e) = remove_job(config, &job.id) {
                tracing::warn!("Failed to remove one-shot cron job after success: {e}");
            }
        } else {
            let _ = record_last_run(config, &job.id, finished_at, false, output);
            if let Err(e) = update_job(
                config,
                &job.id,
                CronJobPatch {
                    enabled: Some(false),
                    ..CronJobPatch::default()
                },
            ) {
                tracing::warn!("Failed to disable failed one-shot cron job: {e}");
            }
        }
        return success;
    }

    if let Err(e) = reschedule_after_run(config, job, success, output) {
        tracing::warn!("Failed to persist scheduler run result: {e}");
    }

    success
}

fn is_one_shot_auto_delete(job: &CronJob) -> bool {
    job.delete_after_run && matches!(job.schedule, Schedule::At { .. })
}

fn warn_if_high_frequency_agent_job(job: &CronJob) {
    if !matches!(job.job_type, JobType::Agent) {
        return;
    }
    let too_frequent = match &job.schedule {
        Schedule::Every { every_ms } => *every_ms < 5 * 60 * 1000,
        Schedule::Cron { .. } => {
            let now = Utc::now();
            match (
                next_run_for_schedule(&job.schedule, now),
                next_run_for_schedule(&job.schedule, now + chrono::Duration::seconds(1)),
            ) {
                (Ok(a), Ok(b)) => (b - a).num_minutes() < 5,
                _ => false,
            }
        }
        Schedule::At { .. } => false,
    };

    if too_frequent {
        tracing::warn!(
            "Cron agent job '{}' is scheduled more frequently than every 5 minutes",
            job.id
        );
    }
}

async fn deliver_if_configured(config: &Config, job: &CronJob, output: &str) -> Result<()> {
    if is_no_reply_sentinel(output) {
        tracing::debug!(
            "Cron job '{}' returned NO_REPLY sentinel; skipping announce delivery",
            job.id
        );
        return Ok(());
    }

    deliver_announcements_if_configured(config, job, [output]).await
}

async fn deliver_start_if_configured(config: &Config, job: &CronJob) -> Result<()> {
    deliver_announcements_if_configured(config, job, build_start_announcements(job)).await
}

async fn deliver_announcements_if_configured<I, S>(
    config: &Config,
    job: &CronJob,
    announcements: I,
) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let Some((channel, target)) = resolve_announce_target(job)? else {
        return Ok(());
    };
    for announcement in announcements {
        deliver_announcement(config, channel, target, announcement.as_ref()).await?;
    }
    Ok(())
}

fn resolve_announce_target(job: &CronJob) -> Result<Option<(&str, &str)>> {
    let delivery: &DeliveryConfig = &job.delivery;
    if !delivery.mode.eq_ignore_ascii_case("announce") {
        return Ok(None);
    }
    let channel = delivery
        .channel
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("delivery.channel is required for announce mode"))?;
    let target = delivery
        .to
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("delivery.to is required for announce mode"))?;
    Ok(Some((channel, target)))
}

fn cron_job_kind(job_type: &JobType) -> &'static str {
    match job_type {
        JobType::Agent => "agent",
        JobType::Shell => "shell",
    }
}

fn render_cron_execution_signal(job: &CronJob, signal: ExecutionSignal) -> String {
    let name = job.name.as_deref().unwrap_or("cron-job");
    let kind = cron_job_kind(&job.job_type);
    let schedule = describe_schedule(&job.schedule);
    render_execution_event(ExecutionEvent {
        source: "Cron",
        id: &job.id,
        name,
        kind,
        schedule: Some(&schedule),
        signal,
    })
}

fn build_start_announcements(job: &CronJob) -> [String; 2] {
    let (detail_label, detail, running_status) = match job.job_type {
        JobType::Agent => (
            "agent_task",
            compact_preview(
                job.prompt.as_deref().unwrap_or(""),
                START_ANNOUNCEMENT_PREVIEW_CHARS,
            ),
            "agent is now executing",
        ),
        JobType::Shell => (
            "command",
            compact_preview(&job.command, START_ANNOUNCEMENT_PREVIEW_CHARS),
            "shell command is now executing",
        ),
    };

    [
        render_cron_execution_signal(
            job,
            ExecutionSignal::Triggered {
                detail_label,
                detail,
            },
        ),
        render_cron_execution_signal(
            job,
            ExecutionSignal::Running {
                status: running_status,
            },
        ),
    ]
}

fn build_job_result_announcement(job: &CronJob, success: bool, output: &str) -> String {
    if is_no_reply_sentinel(output) {
        return output.to_string();
    }

    if !success {
        if let Some(blocked_signal) = build_security_blocked_signal(job, output) {
            return render_cron_execution_signal(job, blocked_signal);
        }
    }

    output.to_string()
}

fn build_security_blocked_signal(job: &CronJob, output: &str) -> Option<ExecutionSignal> {
    let blocked_signal = if let Some(event) = parse_security_policy_block_event(output) {
        ExecutionSignal::Blocked {
            policy_id: Some(event.policy_id.to_string()),
            command_preview: Some(compact_preview(
                event.command_fragment,
                RESULT_ANNOUNCEMENT_PREVIEW_CHARS,
            )),
            reason_preview: compact_preview(event.reason, RESULT_ANNOUNCEMENT_PREVIEW_CHARS),
        }
    } else if is_command_policy_block_message(output) {
        ExecutionSignal::Blocked {
            policy_id: Some(LEGACY_BLOCKED_POLICY_ID.to_string()),
            command_preview: Some(compact_preview(
                blocked_command_subject(job),
                RESULT_ANNOUNCEMENT_PREVIEW_CHARS,
            )),
            reason_preview: compact_preview(output, RESULT_ANNOUNCEMENT_PREVIEW_CHARS),
        }
    } else {
        return None;
    };

    Some(blocked_signal)
}

fn blocked_command_subject(job: &CronJob) -> &str {
    match job.job_type {
        JobType::Shell => &job.command,
        JobType::Agent => job
            .prompt
            .as_deref()
            .filter(|prompt| !prompt.trim().is_empty())
            .unwrap_or("<agent-task>"),
    }
}

fn describe_schedule(schedule: &Schedule) -> String {
    match schedule {
        Schedule::Cron { expr, tz } => {
            if let Some(tz) = tz {
                format!("cron({expr}) tz={tz}")
            } else {
                format!("cron({expr})")
            }
        }
        Schedule::At { at } => format!("at({})", at.to_rfc3339()),
        Schedule::Every { every_ms } => format!("every({every_ms}ms)"),
    }
}

fn compact_preview(raw: &str, max_chars: usize) -> String {
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

#[cfg(test)]
type TestAnnouncement = (String, String, String);

#[cfg(test)]
fn test_announcements_store() -> &'static tokio::sync::Mutex<Vec<TestAnnouncement>> {
    static STORE: std::sync::OnceLock<tokio::sync::Mutex<Vec<TestAnnouncement>>> =
        std::sync::OnceLock::new();
    STORE.get_or_init(|| tokio::sync::Mutex::new(Vec::new()))
}

#[cfg(test)]
async fn push_test_announcement(channel: &str, target: &str, output: &str) {
    test_announcements_store().lock().await.push((
        channel.to_string(),
        target.to_string(),
        output.to_string(),
    ));
}

pub(crate) async fn deliver_announcement(
    config: &Config,
    channel: &str,
    target: &str,
    output: &str,
) -> Result<()> {
    #[cfg(test)]
    if channel.eq_ignore_ascii_case("__test__") {
        push_test_announcement(channel, target, output).await;
        return Ok(());
    }

    let normalized = channel.to_ascii_lowercase();
    match normalized.as_str() {
        "telegram" => {
            let tg = config
                .channels_config
                .telegram
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("telegram channel not configured"))?;
            let channel = TelegramChannel::new(
                tg.bot_token.clone(),
                tg.allowed_users.clone(),
                tg.mention_only,
                tg.ack_enabled,
            )
            .with_workspace_dir(config.workspace_dir.clone());
            channel.send(&SendMessage::new(output, target)).await?;
        }
        "discord" => {
            let dc = config
                .channels_config
                .discord
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("discord channel not configured"))?;
            let channel = DiscordChannel::new(
                dc.bot_token.clone(),
                dc.guild_id.clone(),
                dc.allowed_users.clone(),
                dc.listen_to_bots,
                dc.mention_only,
            )
            .with_workspace_dir(config.workspace_dir.clone());
            channel.send(&SendMessage::new(output, target)).await?;
        }
        "slack" => {
            let sl = config
                .channels_config
                .slack
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("slack channel not configured"))?;
            let channel = SlackChannel::new(
                sl.bot_token.clone(),
                sl.app_token.clone(),
                sl.channel_id.clone(),
                sl.channel_ids.clone(),
                sl.allowed_users.clone(),
            );
            channel.send(&SendMessage::new(output, target)).await?;
        }
        "mattermost" => {
            let mm = config
                .channels_config
                .mattermost
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("mattermost channel not configured"))?;
            let channel = MattermostChannel::new(
                mm.url.clone(),
                mm.bot_token.clone(),
                mm.channel_id.clone(),
                mm.allowed_users.clone(),
                mm.thread_replies.unwrap_or(true),
                mm.mention_only.unwrap_or(false),
            );
            channel.send(&SendMessage::new(output, target)).await?;
        }
        "dingtalk" => {
            let dt = config
                .channels_config
                .dingtalk
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("dingtalk channel not configured"))?;
            let channel = DingTalkChannel::new(
                dt.client_id.clone(),
                dt.client_secret.clone(),
                dt.allowed_users.clone(),
            );
            channel.send(&SendMessage::new(output, target)).await?;
        }
        "qq" => {
            let qq = config
                .channels_config
                .qq
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("qq channel not configured"))?;
            let channel = QQChannel::new_with_environment(
                qq.app_id.clone(),
                qq.app_secret.clone(),
                qq.allowed_users.clone(),
                qq.environment.clone(),
            );
            channel.send(&SendMessage::new(output, target)).await?;
        }
        "napcat" => {
            let napcat_cfg = config
                .channels_config
                .napcat
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("napcat channel not configured"))?;
            let channel = NapcatChannel::from_config(napcat_cfg.clone())?;
            channel.send(&SendMessage::new(output, target)).await?;
        }
        "whatsapp_web" | "whatsapp" => {
            let wa = config
                .channels_config
                .whatsapp
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("whatsapp channel not configured"))?;

            // WhatsApp Web requires the connected channel instance from the
            // channel runtime. Fall back to cloud mode if configured.
            if let Some(live_channel) = crate::channels::get_live_channel("whatsapp") {
                live_channel.send(&SendMessage::new(output, target)).await?;
            } else if wa.is_cloud_config() {
                let channel = WhatsAppChannel::new(
                    wa.access_token.clone().unwrap_or_default(),
                    wa.phone_number_id.clone().unwrap_or_default(),
                    wa.verify_token.clone().unwrap_or_default(),
                    wa.allowed_numbers.clone(),
                );
                channel.send(&SendMessage::new(output, target)).await?;
            } else {
                anyhow::bail!(
                    "whatsapp_web delivery requires an active channels runtime session; start daemon/channels with whatsapp web enabled"
                );
            }
        }
        "lark" => {
            #[cfg(feature = "channel-lark")]
            {
                let lark = config
                    .channels_config
                    .lark
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("lark channel not configured"))?;
                let channel = LarkChannel::from_lark_config(lark);
                channel.send(&SendMessage::new(output, target)).await?;
            }
            #[cfg(not(feature = "channel-lark"))]
            {
                anyhow::bail!("lark delivery channel requires `channel-lark` feature");
            }
        }
        "feishu" => {
            #[cfg(feature = "channel-lark")]
            {
                let feishu = config
                    .channels_config
                    .feishu
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("feishu channel not configured"))?;
                let channel = LarkChannel::from_feishu_config(feishu);
                channel.send(&SendMessage::new(output, target)).await?;
            }
            #[cfg(not(feature = "channel-lark"))]
            {
                anyhow::bail!("feishu delivery channel requires `channel-lark` feature");
            }
        }
        "email" => {
            let email = config
                .channels_config
                .email
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("email channel not configured"))?;
            let channel = EmailChannel::new(email.clone());
            channel.send(&SendMessage::new(output, target)).await?;
        }
        "matrix" => {
            #[cfg(feature = "channel-matrix")]
            {
                // NOTE: uses the basic constructor without session hints (user_id/device_id).
                // Plain (non-E2EE) Matrix rooms work fine. Encrypted-room delivery is not
                // supported in cron mode; use start_channels for full E2EE listener sessions.
                let mx = config
                    .channels_config
                    .matrix
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("matrix channel not configured"))?;
                let channel = MatrixChannel::new(
                    mx.homeserver.clone(),
                    mx.access_token.clone(),
                    mx.room_id.clone(),
                    mx.allowed_users.clone(),
                );
                channel.send(&SendMessage::new(output, target)).await?;
            }
            #[cfg(not(feature = "channel-matrix"))]
            {
                anyhow::bail!("matrix delivery channel requires `channel-matrix` feature");
            }
        }
        other => anyhow::bail!("unsupported delivery channel: {other}"),
    }

    Ok(())
}

async fn run_job_command(
    config: &Config,
    security: &SecurityPolicy,
    job: &CronJob,
) -> (bool, String) {
    run_job_command_with_timeout(
        config,
        security,
        job,
        Duration::from_secs(SHELL_JOB_TIMEOUT_SECS),
    )
    .await
}

async fn run_job_command_with_timeout(
    config: &Config,
    security: &SecurityPolicy,
    job: &CronJob,
    timeout: Duration,
) -> (bool, String) {
    if let Some(blocked) = action_command_preflight_with_approval_violation(
        security,
        &job.command,
        Some(&job.command),
        false,
    ) {
        return (false, blocked.format_block_message());
    }

    let child = match Command::new("sh")
        .arg("-lc")
        .arg(&job.command)
        .current_dir(&config.workspace_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return (false, format!("spawn error: {e}")),
    };

    match time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let combined = format!(
                "status={}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                stdout.trim(),
                stderr.trim()
            );
            (output.status.success(), combined)
        }
        Ok(Err(e)) => (false, format!("spawn error: {e}")),
        Err(_) => (
            false,
            format!("job timed out after {}s", timeout.as_secs_f64()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::cron::{self, DeliveryConfig};
    use crate::security::policy::parse_security_policy_block_event;
    use crate::security::SecurityPolicy;
    use chrono::{Duration as ChronoDuration, Utc};
    use std::sync::OnceLock;
    use tempfile::TempDir;

    async fn env_lock() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await
    }

    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvGuard {
        fn unset(key: &'static str) -> Self {
            let original = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.original.as_ref() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    async fn test_config(tmp: &TempDir) -> Config {
        let config = Config {
            workspace_dir: tmp.path().join("workspace"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        tokio::fs::create_dir_all(&config.workspace_dir)
            .await
            .unwrap();
        config
    }

    fn test_job(command: &str) -> CronJob {
        CronJob {
            id: "test-job".into(),
            expression: "* * * * *".into(),
            schedule: crate::cron::Schedule::Cron {
                expr: "* * * * *".into(),
                tz: None,
            },
            command: command.into(),
            prompt: None,
            name: None,
            job_type: JobType::Shell,
            session_target: SessionTarget::Isolated,
            model: None,
            enabled: true,
            delivery: DeliveryConfig::default(),
            delete_after_run: false,
            created_at: Utc::now(),
            next_run: Utc::now(),
            last_run: None,
            last_status: None,
            last_output: None,
        }
    }

    fn assert_security_policy_block(
        output: &str,
        expected_policy_id: &str,
        expected_command_fragment: &str,
        expected_reason_fragment: &str,
    ) {
        let event = parse_security_policy_block_event(output)
            .expect("expected structured security policy block event");
        assert_eq!(event.policy_id, expected_policy_id);
        assert_eq!(event.command_fragment, expected_command_fragment);
        assert!(
            event.reason.contains(expected_reason_fragment),
            "expected reason to contain `{expected_reason_fragment}`, got `{}`",
            event.reason
        );
    }

    fn unique_component(prefix: &str) -> String {
        format!("{prefix}-{}", uuid::Uuid::new_v4())
    }

    async fn clear_test_announcements() {
        test_announcements_store().lock().await.clear();
    }

    async fn snapshot_test_announcements() -> Vec<TestAnnouncement> {
        test_announcements_store().lock().await.clone()
    }

    #[tokio::test]
    async fn run_job_command_success() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let job = test_job("echo scheduler-ok");
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_job_command(&config, &security, &job).await;
        assert!(success);
        assert!(output.contains("scheduler-ok"));
        assert!(output.contains("status=exit status: 0"));
    }

    #[tokio::test]
    async fn run_job_command_failure() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let job = test_job("ls definitely_missing_file_for_scheduler_test");
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_job_command(&config, &security, &job).await;
        assert!(!success);
        assert!(output.contains("definitely_missing_file_for_scheduler_test"));
        assert!(output.contains("status=exit status:"));
    }

    #[tokio::test]
    async fn run_job_command_times_out() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.allowed_commands = vec!["sleep".into()];
        let job = test_job("sleep 1");
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) =
            run_job_command_with_timeout(&config, &security, &job, Duration::from_millis(50)).await;
        assert!(!success);
        assert!(output.contains("job timed out after"));
    }

    #[tokio::test]
    async fn run_job_command_blocks_disallowed_command() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.allowed_commands = vec!["echo".into()];
        let job = test_job("curl https://evil.example");
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_job_command(&config, &security, &job).await;
        assert!(!success);
        let event = parse_security_policy_block_event(&output)
            .expect("expected structured security policy block event");
        assert_eq!(event.policy_id, "autonomy.allowed_commands");
        assert_eq!(event.command_fragment, "curl https://evil.example");
        assert!(event
            .reason
            .to_ascii_lowercase()
            .contains("command not allowed"));
    }

    #[tokio::test]
    async fn run_job_command_blocks_forbidden_path_argument() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.allowed_commands = vec!["cat".into()];
        let job = test_job("cat /etc/passwd");
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_job_command(&config, &security, &job).await;
        assert!(!success);
        assert_security_policy_block(
            &output,
            "autonomy.workspace_path_guard",
            "cat /etc/passwd",
            "Path blocked by security policy",
        );
    }

    #[tokio::test]
    async fn run_job_command_blocks_forbidden_option_assignment_path_argument() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.allowed_commands = vec!["grep".into()];
        let job = test_job("grep --file=/etc/passwd root ./src");
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_job_command(&config, &security, &job).await;
        assert!(!success);
        assert_security_policy_block(
            &output,
            "autonomy.workspace_path_guard",
            "grep --file=/etc/passwd root ./src",
            "Path blocked by security policy",
        );
    }

    #[tokio::test]
    async fn run_job_command_blocks_forbidden_short_option_attached_path_argument() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.allowed_commands = vec!["grep".into()];
        let job = test_job("grep -f/etc/passwd root ./src");
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_job_command(&config, &security, &job).await;
        assert!(!success);
        assert_security_policy_block(
            &output,
            "autonomy.workspace_path_guard",
            "grep -f/etc/passwd root ./src",
            "Path blocked by security policy",
        );
    }

    #[tokio::test]
    async fn run_job_command_blocks_tilde_user_path_argument() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.allowed_commands = vec!["cat".into()];
        let job = test_job("cat ~root/.ssh/id_rsa");
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_job_command(&config, &security, &job).await;
        assert!(!success);
        assert_security_policy_block(
            &output,
            "autonomy.workspace_path_guard",
            "cat ~root/.ssh/id_rsa",
            "Path blocked by security policy",
        );
    }

    #[tokio::test]
    async fn run_job_command_blocks_input_redirection_path_bypass() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.allowed_commands = vec!["cat".into()];
        let job = test_job("cat </etc/passwd");
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_job_command(&config, &security, &job).await;
        assert!(!success);
        assert_security_policy_block(
            &output,
            "autonomy.shell_structure.redirection",
            "cat </etc/passwd",
            "Shell redirection operators",
        );
    }

    #[tokio::test]
    async fn run_job_command_blocks_readonly_mode() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.level = crate::security::AutonomyLevel::ReadOnly;
        let job = test_job("echo should-not-run");
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_job_command(&config, &security, &job).await;
        assert!(!success);
        let event = parse_security_policy_block_event(&output)
            .expect("expected structured security policy block event");
        assert_eq!(event.policy_id, "autonomy.read_only");
        assert_eq!(event.command_fragment, "echo should-not-run");
        assert!(event.reason.contains("read-only"));
    }

    #[tokio::test]
    async fn run_job_command_blocks_rate_limited() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.max_actions_per_hour = 0;
        let job = test_job("echo should-not-run");
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_job_command(&config, &security, &job).await;
        assert!(!success);
        let event = parse_security_policy_block_event(&output)
            .expect("expected structured security policy block event");
        assert_eq!(event.policy_id, "autonomy.max_actions_per_hour");
        assert_eq!(event.command_fragment, "echo should-not-run");
        assert!(event.reason.contains("Rate limit exceeded"));
    }

    #[tokio::test]
    async fn execute_job_with_retry_recovers_after_first_failure() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.reliability.scheduler_retries = 1;
        config.reliability.provider_backoff_ms = 1;
        config.autonomy.allowed_commands = vec!["sh".into()];
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        tokio::fs::write(
            config.workspace_dir.join("retry-once.sh"),
            "#!/bin/sh\nif [ -f retry-ok.flag ]; then\n  echo recovered\n  exit 0\nfi\ntouch retry-ok.flag\nexit 1\n",
        )
        .await
        .unwrap();
        let job = test_job("sh ./retry-once.sh");

        let (success, output) = execute_job_with_retry(&config, &security, &job).await;
        assert!(success);
        assert!(output.contains("recovered"));
    }

    #[tokio::test]
    async fn execute_job_with_retry_exhausts_attempts() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.reliability.scheduler_retries = 1;
        config.reliability.provider_backoff_ms = 1;
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let job = test_job("ls always_missing_for_retry_test");

        let (success, output) = execute_job_with_retry(&config, &security, &job).await;
        assert!(!success);
        assert!(output.contains("always_missing_for_retry_test"));
    }

    #[tokio::test]
    async fn run_agent_job_returns_error_without_provider_key() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let _env = env_lock().await;
        let _generic = EnvGuard::unset("ZEROCLAW_API_KEY");
        let _fallback = EnvGuard::unset("API_KEY");
        let _openrouter = EnvGuard::unset("OPENROUTER_API_KEY");
        let mut job = test_job("");
        job.job_type = JobType::Agent;
        job.prompt = Some("Say hello".into());
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_agent_job(&config, &security, &job).await;
        assert!(!success);
        assert!(output.contains("agent job failed:"));
    }

    #[tokio::test]
    async fn run_agent_job_blocks_readonly_mode() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.level = crate::security::AutonomyLevel::ReadOnly;
        let mut job = test_job("");
        job.job_type = JobType::Agent;
        job.prompt = Some("Say hello".into());
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_agent_job(&config, &security, &job).await;
        assert!(!success);
        assert_security_policy_block(
            &output,
            "autonomy.read_only",
            "cron-agent:test-job Say hello",
            "read-only",
        );
    }

    #[tokio::test]
    async fn run_agent_job_blocks_rate_limited() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.max_actions_per_hour = 0;
        let mut job = test_job("");
        job.job_type = JobType::Agent;
        job.prompt = Some("Say hello".into());
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);

        let (success, output) = run_agent_job(&config, &security, &job).await;
        assert!(!success);
        assert_security_policy_block(
            &output,
            "autonomy.max_actions_per_hour",
            "cron-agent:test-job Say hello",
            "Rate limit exceeded",
        );
    }

    #[tokio::test]
    async fn process_due_jobs_marks_component_ok_even_when_idle() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let security = Arc::new(SecurityPolicy::from_config(
            &config.autonomy,
            &config.workspace_dir,
        ));
        let component = unique_component("scheduler-idle");

        crate::health::mark_component_error(&component, "pre-existing error");
        process_due_jobs(&config, &security, Vec::new(), &component).await;

        let snapshot = crate::health::snapshot_json();
        let entry = &snapshot["components"][component.as_str()];
        assert_eq!(entry["status"], "ok");
        assert!(entry["last_ok"].as_str().is_some());
        assert!(entry["last_error"].is_null());
    }

    #[tokio::test]
    async fn process_due_jobs_failure_does_not_mark_component_unhealthy() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let job = test_job("ls definitely_missing_file_for_scheduler_component_health_test");
        let security = Arc::new(SecurityPolicy::from_config(
            &config.autonomy,
            &config.workspace_dir,
        ));
        let component = unique_component("scheduler-fail");

        crate::health::mark_component_ok(&component);
        process_due_jobs(&config, &security, vec![job], &component).await;

        let snapshot = crate::health::snapshot_json();
        let entry = &snapshot["components"][component.as_str()];
        assert_eq!(entry["status"], "ok");
    }

    #[tokio::test]
    async fn process_due_jobs_delivers_trigger_running_then_result_announcements() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let security = Arc::new(SecurityPolicy::from_config(
            &config.autonomy,
            &config.workspace_dir,
        ));
        let component = unique_component("scheduler-announce-order");
        let mut job = test_job("echo due-job-order");
        job.name = Some("ordered-due-job".into());
        job.delivery = DeliveryConfig {
            mode: "announce".into(),
            channel: Some("__test__".into()),
            to: Some("chat-due-order".into()),
            best_effort: false,
        };

        clear_test_announcements().await;
        process_due_jobs(&config, &security, vec![job], &component).await;
        let announcements = snapshot_test_announcements().await;

        assert_eq!(announcements.len(), 3);
        assert_eq!(announcements[0].0, "__test__");
        assert_eq!(announcements[0].1, "chat-due-order");
        assert!(announcements[0].2.contains("status=triggered"));
        assert!(announcements[0].2.contains("Cron triggered: id=test-job"));
        assert_eq!(announcements[1].0, "__test__");
        assert_eq!(announcements[1].1, "chat-due-order");
        assert!(announcements[1]
            .2
            .contains("status=shell command is now executing"));
        assert!(announcements[1].2.contains("Cron running: id=test-job"));
        assert_eq!(announcements[2].0, "__test__");
        assert_eq!(announcements[2].1, "chat-due-order");
        assert!(announcements[2].2.contains("stdout:"));
        assert!(announcements[2].2.contains("due-job-order"));
    }

    #[tokio::test]
    async fn process_due_jobs_agent_delivers_trigger_then_running_before_result() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let security = Arc::new(SecurityPolicy::from_config(
            &config.autonomy,
            &config.workspace_dir,
        ));
        let component = unique_component("scheduler-due-agent-announce-order");
        let mut job = test_job("");
        job.job_type = JobType::Agent;
        job.name = Some("due-agent-order".into());
        job.prompt = Some("Report cron status and execution progress".into());
        job.delivery = DeliveryConfig {
            mode: "announce".into(),
            channel: Some("__test__".into()),
            to: Some("chat-due-agent-order".into()),
            best_effort: false,
        };

        clear_test_announcements().await;
        process_due_jobs(&config, &security, vec![job], &component).await;
        let announcements = snapshot_test_announcements().await;

        assert_eq!(announcements.len(), 3);
        assert_eq!(announcements[0].0, "__test__");
        assert_eq!(announcements[0].1, "chat-due-agent-order");
        assert!(announcements[0].2.contains("status=triggered"));
        assert!(announcements[0].2.contains("type=agent"));
        assert!(announcements[1].2.contains("Cron running: id=test-job"));
        assert!(announcements[1].2.contains("status=agent is now executing"));
        assert_eq!(announcements[2].0, "__test__");
        assert_eq!(announcements[2].1, "chat-due-agent-order");
        assert!(announcements[2].2.contains("agent job failed:"));
    }

    #[tokio::test]
    async fn process_due_jobs_blocked_command_delivers_trigger_running_then_blocked_with_policy() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.allowed_commands = vec!["echo".into()];
        let security = Arc::new(SecurityPolicy::from_config(
            &config.autonomy,
            &config.workspace_dir,
        ));
        let component = unique_component("scheduler-due-shell-blocked-announce-order");
        let mut job = test_job("curl https://evil.example");
        job.name = Some("blocked-due-job".into());
        job.delivery = DeliveryConfig {
            mode: "announce".into(),
            channel: Some("__test__".into()),
            to: Some("chat-due-shell-blocked".into()),
            best_effort: false,
        };

        clear_test_announcements().await;
        process_due_jobs(&config, &security, vec![job], &component).await;
        let announcements = snapshot_test_announcements().await;

        assert_eq!(announcements.len(), 3);
        assert_eq!(announcements[0].0, "__test__");
        assert_eq!(announcements[0].1, "chat-due-shell-blocked");
        assert!(announcements[0].2.contains("status=triggered"));
        assert!(announcements[1]
            .2
            .contains("status=shell command is now executing"));
        assert_eq!(announcements[2].0, "__test__");
        assert_eq!(announcements[2].1, "chat-due-shell-blocked");
        assert!(announcements[2].2.contains("Cron blocked: id=test-job"));
        assert!(announcements[2]
            .2
            .contains("status=blocked_by_security_policy"));
        assert!(announcements[2]
            .2
            .contains("policy=autonomy.allowed_commands"));
        assert!(announcements[2]
            .2
            .contains("command=curl https://evil.example"));
        assert!(announcements[2]
            .2
            .contains("reason=Command not allowed by security policy"));
    }

    #[tokio::test]
    async fn persist_job_result_records_run_and_reschedules_shell_job() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let job = cron::add_job(&config, "*/5 * * * *", "echo ok").unwrap();
        let started = Utc::now();
        let finished = started + ChronoDuration::milliseconds(10);

        let success = persist_job_result(&config, &job, true, "ok", started, finished).await;
        assert!(success);

        let runs = cron::list_runs(&config, &job.id, 10).unwrap();
        assert_eq!(runs.len(), 1);
        let updated = cron::get_job(&config, &job.id).unwrap();
        assert_eq!(updated.last_status.as_deref(), Some("ok"));
    }

    #[tokio::test]
    async fn persist_job_result_success_deletes_one_shot() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let at = Utc::now() + ChronoDuration::minutes(10);
        let job = cron::add_agent_job(
            &config,
            Some("one-shot".into()),
            crate::cron::Schedule::At { at },
            "Hello",
            SessionTarget::Isolated,
            None,
            None,
            true,
        )
        .unwrap();
        let started = Utc::now();
        let finished = started + ChronoDuration::milliseconds(10);

        let success = persist_job_result(&config, &job, true, "ok", started, finished).await;
        assert!(success);
        let lookup = cron::get_job(&config, &job.id);
        assert!(lookup.is_err());
    }

    #[tokio::test]
    async fn persist_job_result_failure_disables_one_shot() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let at = Utc::now() + ChronoDuration::minutes(10);
        let job = cron::add_agent_job(
            &config,
            Some("one-shot".into()),
            crate::cron::Schedule::At { at },
            "Hello",
            SessionTarget::Isolated,
            None,
            None,
            true,
        )
        .unwrap();
        let started = Utc::now();
        let finished = started + ChronoDuration::milliseconds(10);

        let success = persist_job_result(&config, &job, false, "boom", started, finished).await;
        assert!(!success);
        let updated = cron::get_job(&config, &job.id).unwrap();
        assert!(!updated.enabled);
        assert_eq!(updated.last_status.as_deref(), Some("error"));
    }

    #[tokio::test]
    async fn persist_job_result_success_deletes_one_shot_shell_job() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let at = Utc::now() + ChronoDuration::minutes(10);
        let job = cron::add_once_at(&config, at, "echo one-shot-shell").unwrap();
        assert!(job.delete_after_run);
        let started = Utc::now();
        let finished = started + ChronoDuration::milliseconds(10);

        let success = persist_job_result(&config, &job, true, "ok", started, finished).await;
        assert!(success);
        let lookup = cron::get_job(&config, &job.id);
        assert!(lookup.is_err());
    }

    #[tokio::test]
    async fn persist_job_result_failure_disables_one_shot_shell_job() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let at = Utc::now() + ChronoDuration::minutes(10);
        let job = cron::add_once_at(&config, at, "echo one-shot-shell").unwrap();
        assert!(job.delete_after_run);
        let started = Utc::now();
        let finished = started + ChronoDuration::milliseconds(10);

        let success = persist_job_result(&config, &job, false, "boom", started, finished).await;
        assert!(!success);
        let updated = cron::get_job(&config, &job.id).unwrap();
        assert!(!updated.enabled);
        assert_eq!(updated.last_status.as_deref(), Some("error"));
    }

    #[tokio::test]
    async fn persist_job_result_delivery_failure_non_best_effort_marks_error() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let job = cron::add_agent_job(
            &config,
            Some("announce-job".into()),
            crate::cron::Schedule::Cron {
                expr: "*/5 * * * *".into(),
                tz: None,
            },
            "deliver this",
            SessionTarget::Isolated,
            None,
            Some(DeliveryConfig {
                mode: "announce".into(),
                channel: Some("telegram".into()),
                to: Some("123456".into()),
                best_effort: false,
            }),
            false,
        )
        .unwrap();
        let started = Utc::now();
        let finished = started + ChronoDuration::milliseconds(10);

        let success = persist_job_result(&config, &job, true, "ok", started, finished).await;
        assert!(!success);

        let updated = cron::get_job(&config, &job.id).unwrap();
        assert!(updated.enabled);
        assert_eq!(updated.last_status.as_deref(), Some("error"));

        let runs = cron::list_runs(&config, &job.id, 10).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, "error");
    }

    #[tokio::test]
    async fn persist_job_result_delivery_failure_best_effort_keeps_success() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let job = cron::add_agent_job(
            &config,
            Some("announce-job-best-effort".into()),
            crate::cron::Schedule::Cron {
                expr: "*/5 * * * *".into(),
                tz: None,
            },
            "deliver this",
            SessionTarget::Isolated,
            None,
            Some(DeliveryConfig {
                mode: "announce".into(),
                channel: Some("telegram".into()),
                to: Some("123456".into()),
                best_effort: true,
            }),
            false,
        )
        .unwrap();
        let started = Utc::now();
        let finished = started + ChronoDuration::milliseconds(10);

        let success = persist_job_result(&config, &job, true, "ok", started, finished).await;
        assert!(success);

        let updated = cron::get_job(&config, &job.id).unwrap();
        assert!(updated.enabled);
        assert_eq!(updated.last_status.as_deref(), Some("ok"));

        let runs = cron::list_runs(&config, &job.id, 10).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, "ok");
    }

    #[tokio::test]
    async fn persist_job_result_at_schedule_without_delete_after_run_is_not_deleted() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let at = Utc::now() + ChronoDuration::minutes(10);
        let job = cron::add_agent_job(
            &config,
            Some("at-no-autodelete".into()),
            crate::cron::Schedule::At { at },
            "Hello",
            SessionTarget::Isolated,
            None,
            None,
            false,
        )
        .unwrap();
        assert!(!job.delete_after_run);

        let started = Utc::now();
        let finished = started + ChronoDuration::milliseconds(10);
        let success = persist_job_result(&config, &job, true, "ok", started, finished).await;
        assert!(success);

        let updated = cron::get_job(&config, &job.id).unwrap();
        assert!(updated.enabled);
        assert_eq!(updated.last_status.as_deref(), Some("ok"));
    }

    #[tokio::test]
    async fn deliver_if_configured_handles_none_and_invalid_channel() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let mut job = test_job("echo ok");

        assert!(deliver_if_configured(&config, &job, "x").await.is_ok());

        job.delivery = DeliveryConfig {
            mode: "announce".into(),
            channel: Some("invalid".into()),
            to: Some("target".into()),
            best_effort: true,
        };
        let err = deliver_if_configured(&config, &job, "x").await.unwrap_err();
        assert!(err.to_string().contains("unsupported delivery channel"));
    }

    #[tokio::test]
    async fn deliver_if_configured_skips_no_reply_sentinel() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let mut job = test_job("echo ok");
        job.delivery = DeliveryConfig {
            mode: "announce".into(),
            channel: Some("invalid".into()),
            to: Some("target".into()),
            best_effort: true,
        };

        assert!(deliver_if_configured(&config, &job, "  no_reply  ")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn execute_and_persist_job_delivers_trigger_then_running_then_result_announcements() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);
        let mut job = test_job("echo scheduler-start-and-result");
        job.name = Some("announced-job".into());
        job.delivery = DeliveryConfig {
            mode: "announce".into(),
            channel: Some("__test__".into()),
            to: Some("chat-42".into()),
            best_effort: false,
        };

        clear_test_announcements().await;
        let (job_id, success, output) =
            execute_and_persist_job(&config, &security, &job, "scheduler-test").await;
        let announcements = snapshot_test_announcements().await;

        assert_eq!(job_id, "test-job");
        assert!(success);
        assert!(output.contains("scheduler-start-and-result"));
        assert_eq!(announcements.len(), 3);
        assert_eq!(announcements[0].0, "__test__");
        assert_eq!(announcements[0].1, "chat-42");
        assert!(announcements[0].2.contains("status=triggered"));
        assert!(announcements[0].2.contains("Cron triggered: id=test-job"));
        assert_eq!(announcements[1].0, "__test__");
        assert_eq!(announcements[1].1, "chat-42");
        assert!(announcements[1]
            .2
            .contains("status=shell command is now executing"));
        assert!(announcements[1].2.contains("Cron running: id=test-job"));
        assert_eq!(announcements[2].0, "__test__");
        assert_eq!(announcements[2].1, "chat-42");
        assert!(announcements[2].2.contains("stdout:"));
        assert!(announcements[2].2.contains("scheduler-start-and-result"));
    }

    #[tokio::test]
    async fn execute_and_persist_agent_job_delivers_trigger_then_running_before_result() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);
        let mut job = test_job("");
        job.job_type = JobType::Agent;
        job.name = Some("announced-agent-job".into());
        job.prompt = Some("Summarize cron status and report progress".into());
        job.delivery = DeliveryConfig {
            mode: "announce".into(),
            channel: Some("__test__".into()),
            to: Some("chat-agent-42".into()),
            best_effort: false,
        };

        clear_test_announcements().await;
        let (_job_id, success, output) =
            execute_and_persist_job(&config, &security, &job, "scheduler-test").await;
        let announcements = snapshot_test_announcements().await;

        assert!(!success);
        assert!(output.contains("agent job failed:"));
        assert_eq!(announcements.len(), 3);
        assert_eq!(announcements[0].0, "__test__");
        assert_eq!(announcements[0].1, "chat-agent-42");
        assert!(announcements[0].2.contains("status=triggered"));
        assert!(announcements[0].2.contains("type=agent"));
        assert!(announcements[1].2.contains("Cron running: id=test-job"));
        assert!(announcements[1].2.contains("status=agent is now executing"));
        assert_eq!(announcements[2].0, "__test__");
        assert_eq!(announcements[2].1, "chat-agent-42");
        assert!(announcements[2].2.contains("agent job failed:"));
    }

    #[tokio::test]
    async fn execute_and_persist_job_includes_policy_summary_in_blocked_result_announcement() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.autonomy.allowed_commands = vec!["echo".into()];
        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);
        let mut job = test_job("curl https://evil.example");
        job.name = Some("blocked-job".into());
        job.delivery = DeliveryConfig {
            mode: "announce".into(),
            channel: Some("__test__".into()),
            to: Some("chat-77".into()),
            best_effort: false,
        };

        clear_test_announcements().await;
        let (_job_id, success, output) =
            execute_and_persist_job(&config, &security, &job, "scheduler-test").await;
        let announcements = snapshot_test_announcements().await;

        assert!(!success);
        assert!(output.contains("blocked by security policy"));
        assert_eq!(announcements.len(), 3);
        assert!(announcements[2].2.contains("Cron blocked: id=test-job"));
        assert!(announcements[2]
            .2
            .contains("status=blocked_by_security_policy"));
        assert!(announcements[2]
            .2
            .contains("policy=autonomy.allowed_commands"));
        assert!(announcements[2]
            .2
            .contains("command=curl https://evil.example"));
    }

    #[test]
    fn build_job_result_announcement_legacy_security_block_includes_policy_and_command() {
        let job = test_job("echo legacy-shell-command");
        let announcement = build_job_result_announcement(
            &job,
            false,
            "blocked by security policy: legacy shell guard denied execution",
        );

        assert!(announcement.contains("status=blocked_by_security_policy"));
        assert!(announcement.contains("policy=autonomy.unknown"));
        assert!(announcement.contains("command=echo legacy-shell-command"));
        assert!(announcement.contains("reason=blocked by security policy"));
    }

    #[test]
    fn lifecycle_announcements_keep_identity_fields_consistent_for_blocked_shell_job() {
        let mut job = test_job("curl https://evil.example");
        job.name = Some("blocked-job".into());
        job.schedule = Schedule::Every { every_ms: 30_000 };

        let [triggered, running] = build_start_announcements(&job);
        let blocked_output = CommandPolicyViolation::from_block_event(
            "autonomy.allowed_commands",
            "Command not allowed by security policy",
            Some("curl https://evil.example"),
        )
        .format_block_message();
        let blocked = build_job_result_announcement(&job, false, &blocked_output);

        for announcement in [&triggered, &running, &blocked] {
            assert!(announcement.contains("id=test-job name=blocked-job type=shell"));
        }
        assert!(triggered.contains("schedule=every(30000ms)"));
        assert!(blocked.contains("schedule=every(30000ms)"));
        assert!(blocked.contains("status=blocked_by_security_policy"));
        assert!(blocked.contains("policy=autonomy.allowed_commands"));
        assert!(blocked.contains("command=curl https://evil.example"));
    }

    #[tokio::test]
    async fn execute_job_now_delivers_start_announcement_for_announce_mode() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp).await;
        let mut job = test_job("echo run-now-start-announce");
        job.name = Some("run-now-job".into());
        job.delivery = DeliveryConfig {
            mode: "announce".into(),
            channel: Some("__test__".into()),
            to: Some("chat-99".into()),
            best_effort: false,
        };

        clear_test_announcements().await;
        let (success, output) = execute_job_now(&config, &job).await;
        let announcements = snapshot_test_announcements().await;

        assert!(success, "{output}");
        assert!(output.contains("run-now-start-announce"));
        assert_eq!(announcements.len(), 2);
        assert_eq!(announcements[0].0, "__test__");
        assert_eq!(announcements[0].1, "chat-99");
        assert!(announcements[0].2.contains("status=triggered"));
        assert!(announcements[0].2.contains("Cron triggered: id=test-job"));
        assert_eq!(announcements[1].0, "__test__");
        assert_eq!(announcements[1].1, "chat-99");
        assert!(announcements[1]
            .2
            .contains("status=shell command is now executing"));
        assert!(announcements[1].2.contains("Cron running: id=test-job"));
    }

    #[test]
    fn build_start_announcements_includes_triggered_context_for_agent_job() {
        let mut job = test_job("echo ignored");
        job.job_type = JobType::Agent;
        job.name = Some("daily-sync".into());
        job.prompt = Some("Summarize the latest error logs and verify fixes".into());
        job.schedule = Schedule::Every { every_ms: 60_000 };

        let [message, _] = build_start_announcements(&job);
        assert!(message.contains("Cron triggered: id=test-job name=daily-sync type=agent"));
        assert!(message.contains("schedule=every(60000ms)"));
        assert!(message.contains("agent_task=Summarize the latest error logs and verify fixes"));
        assert!(message.contains("status=triggered"));
    }

    #[test]
    fn build_start_announcements_includes_running_context_for_agent_job() {
        let mut job = test_job("echo ignored");
        job.job_type = JobType::Agent;
        job.name = Some("daily-sync".into());

        let [_, message] = build_start_announcements(&job);
        assert!(message.contains("Cron running: id=test-job name=daily-sync type=agent"));
        assert!(message.contains("status=agent is now executing"));
    }

    #[test]
    fn no_reply_sentinel_matching_is_trimmed_and_case_insensitive() {
        assert!(is_no_reply_sentinel("NO_REPLY"));
        assert!(is_no_reply_sentinel("  no_reply  "));
        assert!(!is_no_reply_sentinel("NO_REPLY please"));
        assert!(!is_no_reply_sentinel(""));
    }

    #[tokio::test]
    async fn deliver_if_configured_whatsapp_web_requires_live_session_in_web_mode() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(&tmp).await;
        config.channels_config.whatsapp = Some(crate::config::schema::WhatsAppConfig {
            access_token: None,
            phone_number_id: None,
            verify_token: None,
            app_secret: None,
            session_path: Some("~/.zeroclaw/state/whatsapp-web/session.db".into()),
            pair_phone: None,
            pair_code: None,
            allowed_numbers: vec!["*".into()],
        });

        let mut job = test_job("echo ok");
        job.delivery = DeliveryConfig {
            mode: "announce".into(),
            channel: Some("whatsapp_web".into()),
            to: Some("+15551234567".into()),
            best_effort: true,
        };

        let err = deliver_if_configured(&config, &job, "x").await.unwrap_err();
        assert!(err
            .to_string()
            .contains("requires an active channels runtime session"));
    }
}
