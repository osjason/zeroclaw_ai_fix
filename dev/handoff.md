done: 已完成 1 个具体推进并已小提交。修改了 `src/cron/scheduler.rs`：抽取 `deliver_announcements_if_configured` 统一 announce 投递路径，收敛 `deliver_if_configured` 与 `deliver_start_if_configured` 的重复逻辑（仍保持 `NO_REPLY` 跳过语义与 `triggered/running` 顺序行为不变）。已提交 commit：`9020f411`（`refactor(cron): unify announce delivery helper`）。最小验证已执行并通过：`cargo test cron::scheduler::tests::execute_and_persist_agent_job_delivers_trigger_then_running_before_result -- --exact`（1 passed）。
state: 当前子目标仍在进行中；cron 通知链路抽象继续收敛中，本轮未改动 `lark/agent` 侧。
next_files: `src/agent/loop_.rs`, `src/channels/mod.rs`, `src/channels/lark.rs`
next_action: 将同一执行事件抽象继续接到 agent 非交互执行进度上报链路（重点是 Feishu/Lark 在 agent 长任务中的“执行中可见”）。
next_verify: `cargo test channels::tests::process_channel_message_streaming_still_surfaces_policy_block_when_progress_mode_off -- --exact`
next_success: Feishu/Lark 在不依赖用户追加消息的情况下，能持续看到 agent 执行中状态；同时不破坏 progress_mode=off 的拦截信息可见性测试。
blockers: 无