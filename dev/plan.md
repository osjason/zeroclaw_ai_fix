当前子目标: 在本轮执行中先完成 `cron/shell` 安全预检与拦截回报的统一抽象收口，同时确保 Feishu/Lark 能主动持续播报关键进度并维持“先验证再答复”硬约束。  
完成标准:  
1. `cron_add/cron_update/process/scheduler` 的拦截路径统一输出 `policy/command/reason`，不再出现散落非结构化拦截文案。  
2. Feishu/Lark 在 cron 与长任务场景可稳定看到 `triggered -> running -> blocked|completed`，高优先级进度不被普通 draft 节流吞掉。  
3. `loop_` 在缺失执行后验证证据时禁止最终答复，且拦截时主动汇报具体策略与命令。  
4. 以下最小回归通过：  
`cargo test --lib tools::cron_add::tests::blocks_disallowed_shell_command_matches_preflight_event_fields -- --exact`  
`cargo test --lib tools::cron_update::tests::blocks_disallowed_command_updates_match_preflight_event_fields -- --exact`  
`cargo test --lib tools::process::tests::spawn_blocks_disallowed_command_matches_preflight_event_fields -- --exact`  
`cargo test --lib cron::scheduler::tests::process_due_jobs_blocked_command_delivers_trigger_running_then_blocked_with_policy -- --exact`  
`cargo test --lib agent::loop_::tests::run_tool_call_loop_requires_post_action_verification_before_final_answer -- --exact`

推进型任务:
1. 收口命令预检抽象并删重复分支：统一 [src/tools/cron_add.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/tools/cron_add.rs)、[src/tools/cron_update.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/tools/cron_update.rs)、[src/tools/process.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/tools/process.rs)、[src/tools/mod.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/tools/mod.rs)、[src/security/policy.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/security/policy.rs) 的预检返回结构；用前 3 条 tools 测试验证。  
2. 打通主动播报链路：在 [src/cron/scheduler.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/cron/scheduler.rs)、[src/channels/mod.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/channels/mod.rs)、[src/channels/lark.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/channels/lark.rs)、[src/channels/progress_event.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/channels/progress_event.rs) 强化高优先级 continuation；用 scheduler + lark 对应测试验证。  
3. 强化反幻觉硬门禁：在 [src/agent/prompt.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/agent/prompt.rs)、[src/agent/loop_.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/agent/loop_.rs) 固化“必须工具验证后才能最终答复”，并在 [src/channels/mod.rs](C:/Users/osjas/MyData/PG/zeroclaw/src/channels/mod.rs) 补齐被拦截主动汇报字段；用 loop_ 定点测试验证。

支撑型任务:
1. 建立本轮低资源验证入口：在 [dev/ci.sh](C:/Users/osjas/MyData/PG/zeroclaw/dev/ci.sh) 增加/整理仅 5 条关键测试命令组，并在 [docs/operations-runbook.md](C:/Users/osjas/MyData/PG/zeroclaw/docs/operations-runbook.md) 记录；通过实际执行确认只跑目标用例。  
2. 执行“<=10 小操作一提交”的提交卫生：按“预检收口”和“播报+门禁”至少拆 2 次小提交，每次提交前后检查 `git status --short` 与 `git log --oneline -n 5`。