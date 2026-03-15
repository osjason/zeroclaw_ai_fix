project: Rust 2021 单仓库，核心是 trait+factory 的 agent runtime；主代码在 `src/`，默认启用 `channel-lark`（覆盖 Lark/Feishu），高耦合大文件集中在配置、渠道编排、agent loop。当前分支 `release/v0.1.8`，最近提交从 `493d1aab` 后连续围绕 progress/security/cron 修复。
entrypoints: 
- CLI 与运行入口：[src/main.rs](C:\Users\osjas\MyData\PG\zeroclaw\src\main.rs), [src/lib.rs](C:\Users\osjas\MyData\PG\zeroclaw\src\lib.rs)
- agent 主循环与工具调用/验证门控：[src/agent/loop_.rs](C:\Users\osjas\MyData\PG\zeroclaw\src\agent\loop_.rs), [src/agent/prompt.rs](C:\Users\osjas\MyData\PG\zeroclaw\src\agent\prompt.rs)
- Feishu/Lark 渠道与草稿进度更新：[src/channels/lark.rs](C:\Users\osjas\MyData\PG\zeroclaw\src\channels\lark.rs), [src/channels/mod.rs](C:\Users\osjas\MyData\PG\zeroclaw\src\channels\mod.rs), [src/channels/progress_event.rs](C:\Users\osjas\MyData\PG\zeroclaw\src\channels\progress_event.rs)
- cron 生命周期公告与执行：[src/cron/scheduler.rs](C:\Users\osjas\MyData\PG\zeroclaw\src\cron\scheduler.rs)
- 安全策略与拦截结构化信息：[src/security/policy.rs](C:\Users\osjas\MyData\PG\zeroclaw\src\security\policy.rs), 配置契约：[src/config/schema.rs](C:\Users\osjas\MyData\PG\zeroclaw\src\config\schema.rs)
verify: 最小验证优先走单测过滤，避免全量 `cargo test` 压力：
1. `cargo test high_priority_progress_detects_structured_cron_lifecycle_lines --lib`
2. `cargo test lark_update_draft_triggered_running_and_blocked_progress_bypass_interval_throttle --lib`
3. `cargo test run_tool_call_loop_requires_post_action_verification_before_final_answer --lib`
4. `cargo test parse_command_policy_block_event_extracts_fields --lib`
risks: 
- 代码重复集中在进度生命周期渲染/过滤与渠道节流逻辑，容易“修一处漏一处”。
- `src/config/schema.rs` 极大（13k+ 行）且承载公开契约，改动回归面广。
- `autonomy.command_context_rules` 已进入 `src/security/policy.rs` 运行时判定链并有对应测试；当前风险不在“完全未生效”，而在 agent/channel/cron 三侧是否都统一消费其结构化拦截信息。
- 工作区已存在未提交改动（`dev/*.md`, `src/channels/progress_event.rs`），下一轮改动要避开误覆盖。
first_subgoal: 先做一个小而高收益的“进度与拦截事件统一抽象”切片：把 agent/cron/channel 共用的 lifecycle+policy-block 组包与高优先级判定收敛到单点（先不大改行为），并用 2-3 个定向测试锁住 Feishu/cron/安全拦截可见性；这一步最有机会同时降低代码量并稳定后续修 bug。
