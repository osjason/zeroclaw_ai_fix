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
