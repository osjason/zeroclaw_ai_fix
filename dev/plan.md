当前子目标: 先用统一事件抽象收敛 `Feishu/cron/agent/security` 的重复分支，在不破坏兼容的前提下同时解决“进度可见 + 拦截可解释 + 默认测试降载”。

完成标准: `channels/cron/security/agent` 相关重复逻辑净减 LOC >= 80；Feishu/cron 都能观测到 `triggered -> running -> result/blocked`；拦截上报包含 `policy + command + reason`；`cargo test --tests -- --list` 默认不出现 `stress_test_*`；定点测试通过。

推进型任务:
1. 统一执行事件模型并接入 Feishu/cron/agent（做什么 / 涉及哪些文件 / 怎么验证）  
做什么: 新增统一 `ExecutionSignal`（触发/执行中/完成/失败/拦截），替换 `scheduler` 与 `lark` 的分散通知分支，先打通“cron 到点立即通知 + agent 执行中通知”。每完成一段做一次 git 小提交。  
涉及哪些文件: `src/channels/progress_event.rs`（新增）, `src/channels/mod.rs`, `src/channels/lark.rs`, `src/cron/scheduler.rs`, `src/agent/loop_.rs`。  
怎么验证: `cargo test cron::scheduler::tests::process_due_jobs_agent_delivers_trigger_then_running_before_result -- --exact`；`cargo test channels::tests::process_channel_message_streaming_still_surfaces_policy_block_when_progress_mode_off -- --exact`。

2. 统一安全拦截事件并主动汇报（做什么 / 涉及哪些文件 / 怎么验证）  
做什么: 引入 `PolicyBlockEvent` 并统一 shell/process/cron/agent 的拦截解析与消息模板，确保被拦截时主动回报“哪条策略拦截了哪条命令，原因是什么”；同时补齐 `allowed_commands="*"` 与 shell 结构限制的可解释信息。完成后小提交。  
涉及哪些文件: `src/security/policy.rs`, `src/tools/shell.rs`, `src/tools/process.rs`, `src/cron/scheduler.rs`, `src/agent/loop_.rs`。  
怎么验证: `cargo test tools::process::tests::parse_security_policy_block_event_extracts_fields -- --exact`；`cargo test cron::scheduler::tests::run_job_command_blocks_disallowed_command -- --exact`；`cargo test security::policy::tests::allow_unsafe_shell_structures_opt_in_allows_redirection -- --exact`。

3. 强化“先改后验”执行约束，抑制幻觉并可观测（做什么 / 涉及哪些文件 / 怎么验证）  
做什么: 在 agent 预设中强制“修改后读回校验 + 至少一条验证命令”，未验证时发出进度告警事件；保持现有功能兼容，不引入多余开关。完成后小提交。  
涉及哪些文件: `src/agent/loop_.rs`, `src/channels/mod.rs`（必要时 `src/config/schema.rs` 最小增量）。  
怎么验证: 新增/更新 agent loop 测试覆盖“未验证即告警”；回归 `cargo test channels::tests::effective_progress_mode_defaults_non_telegram_to_off -- --exact`。

支撑型任务:
1. 默认测试降载（做什么 / 涉及哪些文件 / 怎么验证）  
做什么: 将 `tests/stress_test_*` 置于 `stress-tests` feature gate，默认测试路径不编译/不运行压力测试，降低每轮资源消耗。  
涉及哪些文件: `Cargo.toml`, `tests/stress_test_5min.rs`, `tests/stress_test_complex_chains.rs`。  
怎么验证: `cargo test --tests -- --list`；`cargo test --features stress-tests --test stress_test_5min -- --ignored`。

2. 配置与文档对齐（做什么 / 涉及哪些文件 / 怎么验证）  
做什么: 补齐配置说明，明确“全放行命令”与“是否放行危险 shell 结构”的组合语义及风险提示，减少误判与误用。  
涉及哪些文件: `docs/config-reference.md`, `docs/troubleshooting.md`。  
怎么验证: 文档关键字检索命中 `allowed_commands`、`allow_unsafe_shell_structures`，并与测试语义一致。