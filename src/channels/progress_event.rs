/// Unified execution progress signal for channel-visible status updates.
#[derive(Debug)]
pub(crate) enum ExecutionSignal {
    Triggered {
        detail_label: &'static str,
        detail: String,
    },
    Running {
        status: &'static str,
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

/// Whether a progress payload should be treated as high priority and remain visible
/// even when normal progress updates are throttled/filtered.
pub(crate) fn is_high_priority_progress_update(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let status = extract_status_value(lower.as_str());
    let is_policy_block_summary =
        lower.contains("security blocked (policy=") && lower.contains("command=");
    let is_structured_running = lower.contains(" running: id=") && status.is_some();
    let is_tool_result_progress = text.lines().any(is_tool_result_progress_line);

    is_policy_block_summary
        || matches!(
            status,
            Some("blocked_by_security_policy" | "triggered" | "completed")
        )
        || is_structured_running
        || is_tool_result_progress
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

#[cfg(test)]
mod tests {
    use super::is_high_priority_progress_update;

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
        assert!(is_high_priority_progress_update(triggered));
        assert!(is_high_priority_progress_update(running));
    }

    #[test]
    fn high_priority_progress_detects_status_only_lifecycle_markers() {
        assert!(is_high_priority_progress_update(
            "status=triggered\nreason=cron scheduling completed"
        ));
        assert!(is_high_priority_progress_update(
            "status=blocked_by_security_policy\nreason=command denied"
        ));
        assert!(!is_high_priority_progress_update(
            "status=ok\nreason=regular summary"
        ));
    }

    #[test]
    fn high_priority_progress_detects_tool_result_lines() {
        assert!(is_high_priority_progress_update("✅ shell (1s)"));
        assert!(is_high_priority_progress_update(
            "❌ shell (0s): command timed out"
        ));
    }
}
