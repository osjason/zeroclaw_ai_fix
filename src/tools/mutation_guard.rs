use super::traits::ToolResult;
use crate::security::policy::ToolOperation;
use crate::security::SecurityPolicy;

pub(crate) fn enforce_mutation_allowed(
    security: &SecurityPolicy,
    action: &str,
    precheck_rate_limit: bool,
) -> Option<ToolResult> {
    if precheck_rate_limit && security.is_rate_limited() {
        return Some(ToolResult {
            success: false,
            output: String::new(),
            error: Some("Rate limit exceeded: too many actions in the last hour".to_string()),
        });
    }

    security
        .enforce_tool_operation(ToolOperation::Act, action)
        .err()
        .map(|error| ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        })
}
