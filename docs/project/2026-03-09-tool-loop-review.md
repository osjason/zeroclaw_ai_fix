# 2026-03-09 Tool Loop / Feishu Review

## Scope

Review target: uncommitted changes related to tool-loop recovery, malformed `tool_call` handling, and Feishu/Lark channel feedback continuity.

Original user intent:

- When the same tool fails repeatedly and reaches the loop threshold, the runtime should tell the model that the current approach is bad and let it try another path.
- A malformed or incomplete `tool_call` should not terminate the turn.
- Feishu should continue receiving progress or follow-up feedback instead of stopping after a broken `tool_call` fragment.

## Findings Before Repair

### 1. `run_tool_call_loop()` and `Agent::turn()` were out of sync

- The new recovery logic was added to `src/agent/loop_.rs`.
- The generic `Agent::turn()` path in `src/agent/agent.rs` still used its own simpler loop.
- Result: malformed tool-call retries and loop-recovery prompts did not apply consistently across all agent entry points.

Impact:

- `tests/agent_loop_robustness.rs` exercised `Agent::turn()` and failed on the new recovery scenarios.

### 2. Feishu/Lark did not actually support draft streaming

- Channel orchestration in `src/channels/mod.rs` only streams progress when `supports_draft_updates()` is true.
- `LarkChannel` in `src/channels/lark.rs` only implemented basic `send/listen/health_check`.
- Result: Feishu/Lark could not provide continuous draft updates during tool execution or recovery.

Impact:

- Even if loop recovery improved internally, Feishu users would still see only final-message behavior instead of ongoing feedback.

### 3. `ack_reaction` config was wired but not enforced

- `LarkChannel` stored `ack_reaction` config.
- Reaction sending still used unconditional calls to `try_add_ack_reaction(...)`.
- Result: config existed, but behavior did not actually honor it.

### 4. Channel sanitization improved but still needed cleanup

- Outbound sanitization added handling for orphan closing tags and unclosed tool-call blocks.
- One new test still failed because sanitization left an extra blank line after removing `</tool_call>`.

## Validation Snapshot Before Repair

Commands run during review:

```powershell
cargo test --test agent_loop_robustness
cargo test sanitize_channel_response_removes_orphan_tool_close_tags
cargo test sanitize_channel_response_drops_unclosed_tool_call_block
```

Observed failures before repair:

- `agent_retries_malformed_tool_call_until_plain_answer_arrives`
- `agent_retries_orphan_tool_close_tag_until_plain_answer_arrives`
- `loop_detection_no_progress_repeat_stops_early`
- `loop_detection_ping_pong_exhausts_iteration_budget`
- `loop_detection_failure_streak_exhausts_iteration_budget`
- `sanitize_channel_response_removes_orphan_tool_close_tags`

Captured local artifacts that matched the reported issue:

- `channel_error.txt`
- `channel_error_callback.txt`

These showed:

- early hard-stop after repeated tool failure
- an outbound orphan `</tool_call>` fragment reaching the channel side

## Repair Goals

1. Unify recovery semantics so `Agent::turn()` and `run_tool_call_loop()` behave consistently.
2. Ensure malformed or incomplete tool-call payloads trigger retry instead of ending the turn immediately.
3. Keep loop detection in recovery mode long enough for the model to self-correct, bounded by iteration budget.
4. Implement real Feishu/Lark draft update support so the channel can keep sending visible progress.
5. Make `ack_reaction` config effective.
6. Keep regression coverage for both tool-loop recovery and channel sanitization.

## Repair Outcome

Implemented:

- `Agent::turn()` now mirrors the recovery semantics already present in `run_tool_call_loop()`:
  - malformed or incomplete tool-call payloads trigger an internal retry prompt
  - deferred-action text without a valid tool call also retries
  - loop detection injects self-correction prompts and continues until recovery or iteration-budget exhaustion
- Native dispatcher now falls back to XML-style tool-call parsing when structured tool calls are absent.
- Tool execution success/failure is now preserved correctly in `ToolExecutionResult`, so loop detection can see repeated failures.
- Lark/Feishu now support:
  - draft capability detection
  - initial draft send
  - throttled draft updates
  - final draft update / fallback send
  - draft cancellation
  - runtime use of `draft_update_interval_ms` and `max_draft_edits`
  - runtime use of `ack_reaction` policy selection
- Lark/Feishu constructors now respect effective group-reply mention gating.
- Outbound sanitization now removes orphan closing tags without leaving the extra blank line seen during review.

## Validation Snapshot After Repair

Commands run after repair:

```powershell
cargo test --test agent_loop_robustness
cargo test sanitize_channel_response_removes_orphan_tool_close_tags
cargo test lark_
cargo test --test channel_routing draft
```

Observed result:

- all targeted tests passed

Notable repaired regressions:

- malformed `tool_call` retry now passes
- orphan `</tool_call>` retry now passes
- no-progress / ping-pong / failure-streak recovery now exhaust iteration budget as intended in the generic `Agent::turn()` path
- Lark/Feishu runtime config for draft updates and ACK reactions is now active in code and covered by channel tests
