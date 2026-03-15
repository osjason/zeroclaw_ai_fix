use super::parsing::ParsedToolCall;
use crate::providers::{ChatMessage, Provider, ToolCall};
use crate::util::truncate_with_ellipsis;
use anyhow::Result;
use std::fmt::Write;

/// Keep this many most-recent non-system messages after compaction.
const COMPACTION_KEEP_RECENT_MESSAGES: usize = 20;

/// Safety cap for compaction source transcript passed to the summarizer.
const COMPACTION_MAX_SOURCE_CHARS: usize = 12_000;

/// Max characters retained in stored compaction summary.
const COMPACTION_MAX_SUMMARY_CHARS: usize = 2_000;

pub(super) struct HistoryToolResult {
    pub(super) tool_name: String,
    pub(super) tool_call_id: Option<String>,
    pub(super) output: String,
}

fn render_tool_results_text(results: &[HistoryToolResult]) -> String {
    let mut tool_results_text = String::new();
    for result in results {
        let _ = writeln!(
            tool_results_text,
            "<tool_result name=\"{}\">\n{}\n</tool_result>",
            result.tool_name, result.output
        );
    }
    tool_results_text
}

pub(super) fn push_tool_results_into_history<I, T>(
    history: &mut Vec<ChatMessage>,
    native_tool_calls: &[ToolCall],
    use_native_tools: bool,
    results: I,
) where
    I: IntoIterator<Item = T>,
    T: Into<HistoryToolResult>,
{
    let history_results: Vec<HistoryToolResult> = results.into_iter().map(Into::into).collect();

    if native_tool_calls.is_empty() {
        let all_results_have_ids = use_native_tools
            && !history_results.is_empty()
            && history_results
                .iter()
                .all(|result| result.tool_call_id.is_some());
        if all_results_have_ids {
            for result in &history_results {
                let tool_msg = serde_json::json!({
                    "tool_call_id": result.tool_call_id,
                    "content": result.output,
                });
                history.push(ChatMessage::tool(tool_msg.to_string()));
            }
        } else {
            history.push(ChatMessage::user(format!(
                "[Tool results]\n{}",
                render_tool_results_text(&history_results)
            )));
        }
        return;
    }

    for (native_call, result) in native_tool_calls.iter().zip(history_results.iter()) {
        let tool_msg = serde_json::json!({
            "tool_call_id": native_call.id,
            "content": result.output,
        });
        history.push(ChatMessage::tool(tool_msg.to_string()));
    }
}

fn assistant_history_content_value(text: &str) -> serde_json::Value {
    if text.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(text.trim().to_string())
    }
}

fn build_native_assistant_history_with_calls(
    text: &str,
    tool_calls: Vec<serde_json::Value>,
    reasoning_content: Option<&str>,
) -> String {
    let mut obj = serde_json::json!({
        "content": assistant_history_content_value(text),
        "tool_calls": tool_calls,
    });

    if let Some(rc) = reasoning_content {
        obj.as_object_mut().unwrap().insert(
            "reasoning_content".to_string(),
            serde_json::Value::String(rc.to_string()),
        );
    }

    obj.to_string()
}

pub(super) fn build_native_assistant_history(
    text: &str,
    tool_calls: &[ToolCall],
    reasoning_content: Option<&str>,
) -> String {
    let calls_json: Vec<serde_json::Value> = tool_calls
        .iter()
        .map(|tc| {
            serde_json::json!({
                "id": tc.id,
                "name": tc.name,
                "arguments": tc.arguments,
            })
        })
        .collect();

    build_native_assistant_history_with_calls(text, calls_json, reasoning_content)
}

pub(super) fn build_native_assistant_history_from_parsed_calls(
    text: &str,
    tool_calls: &[ParsedToolCall],
    reasoning_content: Option<&str>,
) -> Option<String> {
    let calls_json = tool_calls
        .iter()
        .map(|tc| {
            Some(serde_json::json!({
                "id": tc.tool_call_id.clone()?,
                "name": tc.name,
                "arguments": serde_json::to_string(&tc.arguments).unwrap_or_else(|_| "{}".to_string()),
            }))
        })
        .collect::<Option<Vec<_>>>()?;

    Some(build_native_assistant_history_with_calls(
        text,
        calls_json,
        reasoning_content,
    ))
}

pub(super) fn build_assistant_history_content(
    text: &str,
    parsed_tool_calls: &[ParsedToolCall],
    native_tool_calls: &[ToolCall],
    reasoning_content: Option<&str>,
    use_native_tools: bool,
) -> String {
    if native_tool_calls.is_empty() {
        if use_native_tools {
            build_native_assistant_history_from_parsed_calls(
                text,
                parsed_tool_calls,
                reasoning_content,
            )
            .unwrap_or_else(|| text.to_string())
        } else {
            text.to_string()
        }
    } else {
        build_native_assistant_history(text, native_tool_calls, reasoning_content)
    }
}

fn render_tool_call_tag(payload: serde_json::Value) -> String {
    format!("<tool_call>\n{payload}\n</tool_call>")
}

fn build_assistant_history_from_parsed_calls(tool_calls: &[ParsedToolCall]) -> String {
    tool_calls
        .iter()
        .map(|call| {
            let payload = if let Some(id) = &call.tool_call_id {
                serde_json::json!({
                    "id": id,
                    "name": call.name,
                    "arguments": call.arguments,
                })
            } else {
                serde_json::json!({
                    "name": call.name,
                    "arguments": call.arguments,
                })
            };
            render_tool_call_tag(payload)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn suppress_assistant_text_in_history_when_verification_pending(
    assistant_history_content: &str,
    tool_calls: &[ParsedToolCall],
    use_native_tools: bool,
) -> String {
    if use_native_tools {
        if let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(assistant_history_content)
        {
            if let Some(obj) = parsed.as_object_mut() {
                obj.insert("content".to_string(), serde_json::Value::Null);
                return parsed.to_string();
            }
        }

        if let Some(native) = build_native_assistant_history_from_parsed_calls("", tool_calls, None)
        {
            return native;
        }
    }

    build_assistant_history_from_parsed_calls(tool_calls)
}

/// Trim conversation history to prevent unbounded growth.
/// Preserves the system prompt (first message if role=system) and the most recent messages.
pub(super) fn trim_history(history: &mut Vec<ChatMessage>, max_history: usize) {
    // Nothing to trim if within limit
    let has_system = history.first().map_or(false, |m| m.role == "system");
    let non_system_count = if has_system {
        history.len() - 1
    } else {
        history.len()
    };

    if non_system_count <= max_history {
        return;
    }

    let start = if has_system { 1 } else { 0 };
    let mut trim_end = start + (non_system_count - max_history);
    // Never keep a leading `role=tool` at the trim boundary. Tool-message runs
    // must remain attached to their preceding assistant(tool_calls) message.
    while trim_end < history.len() && history[trim_end].role == "tool" {
        trim_end += 1;
    }
    history.drain(start..trim_end);
}

pub(super) fn build_compaction_transcript(messages: &[ChatMessage]) -> String {
    let mut transcript = String::new();
    for msg in messages {
        let role = msg.role.to_uppercase();
        let _ = writeln!(transcript, "{role}: {}", msg.content.trim());
    }

    if transcript.chars().count() > COMPACTION_MAX_SOURCE_CHARS {
        truncate_with_ellipsis(&transcript, COMPACTION_MAX_SOURCE_CHARS)
    } else {
        transcript
    }
}

pub(super) fn apply_compaction_summary(
    history: &mut Vec<ChatMessage>,
    start: usize,
    compact_end: usize,
    summary: &str,
) {
    let summary_msg = ChatMessage::assistant(format!("[Compaction summary]\n{}", summary.trim()));
    history.splice(start..compact_end, std::iter::once(summary_msg));
}

pub(super) async fn auto_compact_history(
    history: &mut Vec<ChatMessage>,
    provider: &dyn Provider,
    model: &str,
    max_history: usize,
    hooks: Option<&crate::hooks::HookRunner>,
) -> Result<bool> {
    let has_system = history.first().map_or(false, |m| m.role == "system");
    let non_system_count = if has_system {
        history.len().saturating_sub(1)
    } else {
        history.len()
    };

    if non_system_count <= max_history {
        return Ok(false);
    }

    let start = if has_system { 1 } else { 0 };
    let keep_recent = COMPACTION_KEEP_RECENT_MESSAGES.min(non_system_count);
    let compact_count = non_system_count.saturating_sub(keep_recent);
    if compact_count == 0 {
        return Ok(false);
    }

    let mut compact_end = start + compact_count;
    // Do not split assistant(tool_calls) -> tool runs across compaction boundary.
    while compact_end < history.len() && history[compact_end].role == "tool" {
        compact_end += 1;
    }
    let to_compact: Vec<ChatMessage> = history[start..compact_end].to_vec();
    let to_compact = if let Some(hooks) = hooks {
        match hooks.run_before_compaction(to_compact).await {
            crate::hooks::HookResult::Continue(messages) => messages,
            crate::hooks::HookResult::Cancel(reason) => {
                tracing::info!(%reason, "history compaction cancelled by hook");
                return Ok(false);
            }
        }
    } else {
        to_compact
    };
    let transcript = build_compaction_transcript(&to_compact);

    let summarizer_system = "You are a conversation compaction engine. Summarize older chat history into concise context for future turns. Preserve: user preferences, commitments, decisions, unresolved tasks, key facts. Omit: filler, repeated chit-chat, verbose tool logs. Output plain text bullet points only.";

    let summarizer_user = format!(
        "Summarize the following conversation history for context preservation. Keep it short (max 12 bullet points).\n\n{}",
        transcript
    );

    let summary_raw = provider
        .chat_with_system(Some(summarizer_system), &summarizer_user, model, 0.2)
        .await
        .unwrap_or_else(|_| {
            // Fallback to deterministic local truncation when summarization fails.
            truncate_with_ellipsis(&transcript, COMPACTION_MAX_SUMMARY_CHARS)
        });

    let summary = truncate_with_ellipsis(&summary_raw, COMPACTION_MAX_SUMMARY_CHARS);
    let summary = if let Some(hooks) = hooks {
        match hooks.run_after_compaction(summary).await {
            crate::hooks::HookResult::Continue(next_summary) => next_summary,
            crate::hooks::HookResult::Cancel(reason) => {
                tracing::info!(%reason, "post-compaction summary cancelled by hook");
                return Ok(false);
            }
        }
    } else {
        summary
    };
    apply_compaction_summary(history, start, compact_end, &summary);

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::loop_::parsing::ParsedToolCall;
    use crate::providers::{ChatRequest, ChatResponse, Provider};
    use async_trait::async_trait;

    struct StaticSummaryProvider;

    #[async_trait]
    impl Provider for StaticSummaryProvider {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: f64,
        ) -> anyhow::Result<String> {
            Ok("- summarized context".to_string())
        }

        async fn chat(
            &self,
            _request: ChatRequest<'_>,
            _model: &str,
            _temperature: f64,
        ) -> anyhow::Result<ChatResponse> {
            Ok(ChatResponse {
                text: Some("- summarized context".to_string()),
                tool_calls: Vec::new(),
                usage: None,
                reasoning_content: None,
                quota_metadata: None,
            })
        }
    }

    fn assistant_with_tool_call(id: &str) -> ChatMessage {
        ChatMessage::assistant(format!(
            "{{\"content\":\"\",\"tool_calls\":[{{\"id\":\"{id}\",\"name\":\"shell\",\"arguments\":\"{{}}\"}}]}}"
        ))
    }

    fn tool_result(id: &str) -> ChatMessage {
        ChatMessage::tool(format!("{{\"tool_call_id\":\"{id}\",\"content\":\"ok\"}}"))
    }

    #[test]
    fn tool_result_history_batch_preserves_tool_call_id_for_native_fallback() {
        let mut history = Vec::new();
        let batch = [HistoryToolResult {
            tool_name: "shell".into(),
            tool_call_id: Some("call_1".into()),
            output: "ok".into(),
        }];

        push_tool_results_into_history(&mut history, &[], true, batch);

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].role, "tool");
        assert!(history[0].content.contains("\"tool_call_id\":\"call_1\""));
        assert!(history[0].content.contains("\"content\":\"ok\""));
    }

    #[test]
    fn trim_history_avoids_orphan_tool_at_boundary() {
        let mut history = vec![
            ChatMessage::user("old"),
            assistant_with_tool_call("call_1"),
            tool_result("call_1"),
            ChatMessage::user("recent"),
        ];

        trim_history(&mut history, 2);

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].role, "user");
        assert_eq!(history[0].content, "recent");
    }

    #[tokio::test]
    async fn auto_compact_history_does_not_split_tool_run_boundary() {
        let mut history = vec![
            ChatMessage::user("oldest"),
            assistant_with_tool_call("call_2"),
            tool_result("call_2"),
        ];
        for idx in 0..19 {
            history.push(ChatMessage::user(format!("recent-{idx}")));
        }
        // 22 non-system messages => compaction with max_history=21 would
        // previously cut right before the tool result (index 2).
        assert_eq!(history.len(), 22);

        let compacted =
            auto_compact_history(&mut history, &StaticSummaryProvider, "test-model", 21, None)
                .await
                .expect("compaction should succeed");

        assert!(compacted);
        assert_eq!(history[0].role, "assistant");
        assert!(
            history[0].content.contains("[Compaction summary]"),
            "summary message should replace compacted range"
        );
        assert_ne!(
            history[1].role, "tool",
            "first retained message must not be an orphan tool result"
        );
    }

    #[test]
    fn build_native_assistant_history_includes_reasoning_content() {
        let calls = vec![ToolCall {
            id: "call_1".into(),
            name: "shell".into(),
            arguments: "{}".into(),
        }];
        let result = build_native_assistant_history("answer", &calls, Some("thinking step"));
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["content"].as_str(), Some("answer"));
        assert_eq!(parsed["reasoning_content"].as_str(), Some("thinking step"));
        assert!(parsed["tool_calls"].is_array());
    }

    #[test]
    fn build_native_assistant_history_omits_reasoning_content_when_none() {
        let calls = vec![ToolCall {
            id: "call_1".into(),
            name: "shell".into(),
            arguments: "{}".into(),
        }];
        let result = build_native_assistant_history("answer", &calls, None);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["content"].as_str(), Some("answer"));
        assert!(parsed.get("reasoning_content").is_none());
    }

    #[test]
    fn build_native_assistant_history_from_parsed_calls_includes_reasoning_content() {
        let calls = vec![ParsedToolCall {
            name: "shell".into(),
            arguments: serde_json::json!({"command": "pwd"}),
            tool_call_id: Some("call_2".into()),
        }];
        let result = build_native_assistant_history_from_parsed_calls(
            "answer",
            &calls,
            Some("deep thought"),
        );
        assert!(result.is_some());
        let parsed: serde_json::Value = serde_json::from_str(result.as_deref().unwrap()).unwrap();
        assert_eq!(parsed["content"].as_str(), Some("answer"));
        assert_eq!(parsed["reasoning_content"].as_str(), Some("deep thought"));
        assert!(parsed["tool_calls"].is_array());
    }

    #[test]
    fn build_native_assistant_history_from_parsed_calls_omits_reasoning_content_when_none() {
        let calls = vec![ParsedToolCall {
            name: "shell".into(),
            arguments: serde_json::json!({"command": "pwd"}),
            tool_call_id: Some("call_2".into()),
        }];
        let result = build_native_assistant_history_from_parsed_calls("answer", &calls, None);
        assert!(result.is_some());
        let parsed: serde_json::Value = serde_json::from_str(result.as_deref().unwrap()).unwrap();
        assert_eq!(parsed["content"].as_str(), Some("answer"));
        assert!(parsed.get("reasoning_content").is_none());
    }

    #[test]
    fn build_assistant_history_content_prefers_native_calls_when_present() {
        let parsed_calls = vec![ParsedToolCall {
            name: "file_read".into(),
            arguments: serde_json::json!({"path": "src/lib.rs"}),
            tool_call_id: Some("parsed_1".into()),
        }];
        let native_calls = vec![ToolCall {
            id: "native_1".into(),
            name: "shell".into(),
            arguments: "{\"command\":\"pwd\"}".into(),
        }];

        let result = build_assistant_history_content(
            "answer",
            &parsed_calls,
            &native_calls,
            Some("thinking step"),
            true,
        );
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(parsed["tool_calls"][0]["id"].as_str(), Some("native_1"));
        assert_eq!(parsed["tool_calls"][0]["name"].as_str(), Some("shell"));
        assert_eq!(parsed["reasoning_content"].as_str(), Some("thinking step"));
    }

    #[test]
    fn build_assistant_history_content_falls_back_to_response_text_without_native_mode() {
        let parsed_calls = vec![ParsedToolCall {
            name: "shell".into(),
            arguments: serde_json::json!({"command": "pwd"}),
            tool_call_id: Some("call_2".into()),
        }];

        let result =
            build_assistant_history_content("answer", &parsed_calls, &[], Some("thinking"), false);

        assert_eq!(result, "answer");
    }

    #[test]
    fn build_native_assistant_history_uses_null_content_for_blank_text() {
        let calls = vec![ToolCall {
            id: "call_1".into(),
            name: "shell".into(),
            arguments: "{}".into(),
        }];
        let result = build_native_assistant_history("   ", &calls, None);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["content"].is_null());
        assert!(parsed["tool_calls"].is_array());
    }

    #[test]
    fn suppress_verification_pending_native_history_nulls_content() {
        let original = serde_json::json!({
            "content": "draft answer",
            "tool_calls": [{"id": "call_1", "name": "shell", "arguments": "{}"}],
            "reasoning_content": "thinking step",
        })
        .to_string();

        let suppressed =
            suppress_assistant_text_in_history_when_verification_pending(&original, &[], true);
        let parsed: serde_json::Value = serde_json::from_str(&suppressed).unwrap();
        assert!(parsed["content"].is_null());
        assert_eq!(parsed["reasoning_content"].as_str(), Some("thinking step"));
        assert_eq!(parsed["tool_calls"][0]["id"].as_str(), Some("call_1"));
    }

    #[test]
    fn suppress_verification_pending_xml_history_keeps_only_tool_calls() {
        let calls = vec![ParsedToolCall {
            name: "shell".into(),
            arguments: serde_json::json!({"command": "pwd"}),
            tool_call_id: Some("call_2".into()),
        }];

        let suppressed = suppress_assistant_text_in_history_when_verification_pending(
            "draft answer",
            &calls,
            false,
        );

        assert!(!suppressed.contains("draft answer"));
        assert!(suppressed.contains("<tool_call>"));
        assert!(suppressed.contains("\"id\":\"call_2\""));
    }
}
