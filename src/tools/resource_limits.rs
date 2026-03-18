use crate::config::ResourceLimitsConfig;

#[cfg(unix)]
pub(crate) fn prepare_shell_command(
    command: &str,
    limits: &ResourceLimitsConfig,
) -> anyhow::Result<(String, Option<String>)> {
    if !has_non_default_limits(limits) {
        return Ok((command.to_string(), None));
    }

    let memory_kb = u64::from(limits.max_memory_mb).saturating_mul(1024);
    let cpu_seconds = limits.max_cpu_time_seconds.max(1);
    let max_subprocesses = u64::from(limits.max_subprocesses).max(1);

    let wrapped = format!(
        "ulimit -v {memory_kb} && ulimit -t {cpu_seconds} && ulimit -u {max_subprocesses} && {command}"
    );

    Ok((wrapped, None))
}

#[cfg(not(unix))]
pub(crate) fn prepare_shell_command(
    command: &str,
    limits: &ResourceLimitsConfig,
) -> anyhow::Result<(String, Option<String>)> {
    let warning = if has_non_default_limits(limits) {
        Some(
            "security.resources enforcement is not supported on this platform; configured limits were not applied"
                .to_string(),
        )
    } else {
        None
    };

    Ok((command.to_string(), warning))
}

fn has_non_default_limits(limits: &ResourceLimitsConfig) -> bool {
    limits.max_memory_mb != 512
        || limits.max_cpu_time_seconds != 60
        || limits.max_subprocesses != 10
        || !limits.memory_monitoring
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_keep_command_unchanged() {
        let (command, warning) =
            prepare_shell_command("echo hello", &ResourceLimitsConfig::default()).unwrap();

        assert_eq!(command, "echo hello");
        assert!(warning.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn unix_limits_wrap_command_with_ulimit_prefix() {
        let limits = ResourceLimitsConfig {
            max_memory_mb: 256,
            max_cpu_time_seconds: 15,
            max_subprocesses: 3,
            memory_monitoring: true,
        };

        let (command, warning) = prepare_shell_command("echo hello", &limits).unwrap();

        assert_eq!(
            command,
            "ulimit -v 262144 && ulimit -t 15 && ulimit -u 3 && echo hello"
        );
        assert!(warning.is_none());
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_limits_return_warning_without_mutating_command() {
        let limits = ResourceLimitsConfig {
            max_memory_mb: 256,
            max_cpu_time_seconds: 15,
            max_subprocesses: 3,
            memory_monitoring: true,
        };

        let (command, warning) = prepare_shell_command("echo hello", &limits).unwrap();

        assert_eq!(command, "echo hello");
        assert!(warning.is_some());
    }
}
