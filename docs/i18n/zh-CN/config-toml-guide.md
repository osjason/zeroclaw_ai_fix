# config.toml 详细说明（简体中文）

这是一份面向 `config.toml` 的中文详解，目标不是只告诉您“这个键叫什么”，而是告诉您：

- 这个配置管什么
- 默认值意味着什么
- 哪些键是高风险开关
- 哪些键要联动调整
- 应该去哪里继续看更细的专题文档

最后对齐：**2026-03-19**。

> 约定：配置键、命令名、API 路径、模型名保持英文原样，方便直接复制到 `config.toml`。

## 先看这 4 条

1. 想看机器可校验的完整 schema：运行 `zeroclaw config schema`
2. 想看英文运行时合同文档：看 [../../config-reference.md](../../config-reference.md)
3. 想看安全配置的白话解释：看 [security-config-guide.md](security-config-guide.md)
4. 想先确认某个值当前到底生效成什么：运行 `zeroclaw config show`

## 配置文件在哪里

ZeroClaw 启动时会按顺序寻找配置：

1. `ZEROCLAW_WORKSPACE` 指向的工作区配置
2. 活跃工作区标记文件
3. 默认路径 `~/.zeroclaw/config.toml`

常用命令：

```bash
zeroclaw config show
zeroclaw config get autonomy.level
zeroclaw config set gateway.port 42617
zeroclaw config schema
```

## 顶层配置总览

下面这张表覆盖当前 `Config` 顶层可设置项。把它当成“地图”。

| 顶层键 | 用途 | 风险/说明 | 继续阅读 |
|---|---|---|---|
| `api_key` / `api_url` | 当前默认 provider 的凭据和 API 地址 | 高敏感；建议配合 `[secrets]` | [providers-reference.md](providers-reference.md) |
| `default_provider` / `default_model` / `default_temperature` | 默认模型路由 | 改错会直接影响全局模型行为 | [../../config-reference.md](../../config-reference.md) |
| `provider_api` | `custom:` provider 的协议模式 | 主要给兼容 OpenAI 风格接口 | [providers-reference.md](providers-reference.md) |
| `model_providers` | 命名 provider profile | 适合多账号、多 endpoint、多协议 | [providers-reference.md](providers-reference.md) |
| `[provider]` | provider 行为覆盖项 | 会影响 reasoning / transport | [providers-reference.md](providers-reference.md) |
| `[observability]` | 追踪、指标、OTLP 输出 | 生产环境常开 | [../../config-reference.md](../../config-reference.md) |
| `[autonomy]` | 命令、文件、审批、配额、安全边界 | 高风险核心区 | [security-config-guide.md](security-config-guide.md) |
| `[security]` | OTP、URL 访问、sandbox、审计等 | 高风险核心区 | [security-config-guide.md](security-config-guide.md) |
| `[runtime]` | native / docker / wasm 运行时 | 影响执行隔离与兼容性 | [../../config-reference.md](../../config-reference.md) |
| `[research]` | 回答前先做检索/调查 | 提高可靠性，也会增加延迟/成本 | [../../config-reference.md](../../config-reference.md) |
| `[reliability]` | 重试、回退、轮换、退避 | 生产环境重要 | 本页“可靠性与调度” |
| `[scheduler]` | 内建调度器主循环 | 和 cron / 后台任务相关 | 本页“可靠性与调度” |
| `[agent]` | tool loop、上下文、会话、子代理 | 直接影响 agent 行为 | 本页“Agent 行为” |
| `[skills]` | skills 加载、trusted roots、prompt 注入 | 会影响扩展来源与提示词体积 | 本页“扩展系统” |
| `[[model_routes]]` / `[[embedding_routes]]` | 用 `hint:*` 做模型/向量路由 | 大团队/多模型场景很有用 | [../../config-reference.md](../../config-reference.md) |
| `[query_classification]` | 自动把请求路由到不同模型 hint | 容易因规则冲突产生误路由 | 本页“路由与分类” |
| `[heartbeat]` | 定时心跳消息 | 常用于值守和巡检 | 本页“可靠性与调度” |
| `[cron]` | cron 子系统基础行为 | 和计划任务相关 | 本页“可靠性与调度” |
| `[goal_loop]` | 长周期自主目标执行 | 高风险，建议先监督模式 | 本页“可靠性与调度” |
| `[channels_config]` | Telegram/Discord/Lark/Slack 等通道 | 入口暴露面很大 | [channels-reference.md](channels-reference.md) |
| `[memory]` | sqlite / markdown / embedding / 混合检索 | 影响持久化与检索质量 | [../../config-reference.md](../../config-reference.md) |
| `[storage]` | storage provider 后端 | 主要用于更换持久化底座 | 本页“存储与记忆” |
| `[tunnel]` | Cloudflare/Tailscale/ngrok/custom 暴露网关 | 外网暴露高风险 | 本页“网络与暴露面” |
| `[gateway]` | 网关监听、配对、限流、node_control | 高风险边界 | [../../config-reference.md](../../config-reference.md) |
| `[composio]` | Composio OAuth 工具集成 | 第三方 SaaS 能力入口 | 本页“集成与身份” |
| `[secrets]` | 配置文件中的凭据加密 | 强烈建议保持默认开启 | [security-config-guide.md](security-config-guide.md) |
| `[browser]` | browser_open / 自动化 / computer-use | 高风险外部交互面 | [../../config-reference.md](../../config-reference.md) |
| `[http_request]` / `[web_fetch]` / `[web_search]` | 网络工具策略 | SSRF / 域名暴露面 | [security-config-guide.md](security-config-guide.md) |
| `[proxy]` | HTTP/HTTPS/SOCKS5 代理 | 影响所有外联流量 | 本页“网络与暴露面” |
| `[identity]` | `openclaw` / `aieos` 身份文档 | 影响系统提示身份注入 | 本页“集成与身份” |
| `[cost]` | 花费跟踪与预算 | 生产/付费模型建议开启 | 本页“预算与经济模型” |
| `[economic]` | 经济生存模型 | 偏实验特性 | 本页“预算与经济模型” |
| `[peripherals]` / `[hardware]` | 板卡、串口、探针、数据手册 | 物理世界风险面 | [../../hardware-peripherals-design.md](../../hardware-peripherals-design.md) |
| `[agents]` / `[coordination]` | delegate 子代理与协调总线 | 多代理场景关键 | 本页“多代理与协同” |
| `[hooks]` | 生命周期 hook | 和主进程同权限，需谨慎 | 本页“扩展系统” |
| `[plugins]` | 插件系统、allow/deny、per-plugin config | 代码执行扩展面 | 本页“扩展系统” |
| `[transcription]` | 语音转文字 | 需要外部 API key | 本页“多模态与媒体” |
| `[agents_ipc]` | 同机多进程 agent IPC | 会引入共享 SQLite 总线 | [../../config-reference.md](../../config-reference.md) |
| `[mcp]` | 外部 MCP server 接入 | 外部工具边界 | 本页“扩展系统” |
| `model_support_vision` | 强制开/关视觉支持 | 仅在 provider 自动判断不准时用 | 本页“多模态与媒体” |
| `[wasm]` | WASM 插件引擎总开关与资源限制 | 扩展能力面 | 本页“扩展系统” |

## 1. 核心模型选择

### 全局基础键

| 键 | 作用 | 常见值/建议 |
|---|---|---|
| `default_provider` | 默认 provider 名称或别名 | 如 `openrouter`、`openai`、`ollama` |
| `default_model` | 默认模型 ID | 和 provider 对应 |
| `default_temperature` | 默认温度 | 多数生产场景 `0.2` 到 `0.7` |
| `api_key` | 当前默认 provider 的密钥 | 建议不要明文长期裸放 |
| `api_url` | provider API 地址覆盖 | 自建兼容接口常用 |
| `provider_api` | `custom:` provider 的协议模式 | 只在自定义兼容接口时改 |
| `model_support_vision` | 强制视觉开/关 | 只有自动判断不准时才改 |

### `model_providers` 命名 profile

适合这些场景：

- 同时接多个 OpenAI-compatible endpoint
- 同一 provider 下分开管理生产/测试密钥
- 需要某个 profile 固定 `wire_api` 或固定 `default_model`

常见键：

| 键 | 作用 |
|---|---|
| `name` | provider 类型/名称覆盖 |
| `base_url` | profile 自己的 API 根地址 |
| `wire_api` | 协议类型，如 `responses` / `chat_completions` |
| `default_model` | 这个 profile 的默认模型 |
| `api_key` | 这个 profile 的专属密钥 |
| `requires_openai_auth` | 需要加载 OpenAI/Codex auth 材料 |

### `[provider]`

| 键 | 作用 | 什么时候改 |
|---|---|---|
| `reasoning_level` | 覆盖 reasoning effort | 对 OpenAI Codex 这类显式支持等级的 provider 很有用 |
| `transport` | 指定 `auto` / `websocket` / `sse` | 排查连接问题或固定传输协议时 |

## 2. Agent 行为

### `[agent]`

| 键 | 默认 | 作用 |
|---|---|---|
| `compact_context` | `true` | 压缩上下文，适合小模型 |
| `max_tool_iterations` | `20` | 每条消息最大 tool loop 次数 |
| `max_history_messages` | `50` | 会话历史保留条数 |
| `parallel_tools` | `false` | 单轮是否并行跑多个工具 |
| `tool_dispatcher` | `auto` | tool 调度策略 |
| `loop_detection_no_progress_threshold` | `3` | 无进展重复检测阈值 |
| `loop_detection_ping_pong_cycles` | `2` | A/B 来回抖动检测 |
| `loop_detection_failure_streak` | `3` | 连续失败阈值 |
| `safety_heartbeat_interval` | `5` | tool loop 中间插入安全提醒 |
| `safety_heartbeat_turn_interval` | `10` | 对话轮次级安全提醒 |

联动建议：

- 小模型/小内存设备：保持 `compact_context = true`
- 工具较多时：先不要急着开 `parallel_tools`
- 如果模型会在失败工具上死循环：优先调低 3 个 `loop_detection_*`

### `[agent.session]`

| 键 | 默认 | 作用 |
|---|---|---|
| `backend` | `none` | `memory` / `sqlite` / `none` |
| `strategy` | `per-sender` | 会话按谁隔离 |
| `ttl_seconds` | `3600` | 会话过期时间 |
| `max_messages` | `50` | 单会话最大消息数 |

### `[agent.teams]` 与 `[agent.subagents]`

这两组都控制代理分工，但关注点不同：

- `teams`：同步委派、自动挑选 team member
- `subagents`：后台子代理、并发队列、限流与负载均衡

如果您只是在单机上偶尔 `delegate`，先保留默认值即可；
如果开始批量并行委派，再重点看：

- `enabled`
- `auto_activate`
- `max_agents` / `max_concurrent`
- `strategy`
- `load_window_secs`
- `queue_wait_ms`

## 3. 自主性与安全边界

### `[autonomy]` 是最关键的一组

这里控制：

- 能跑什么命令
- 能碰哪些路径
- 哪些动作要审批
- 哪些工具自动放行
- 每小时动作预算和每天成本预算

优先阅读：

- [security-config-guide.md](security-config-guide.md)
- [../../config-reference.md](../../config-reference.md#autonomy)

最重要的键：

| 键 | 默认 | 重点 |
|---|---|---|
| `level` | `supervised` | `read_only` / `supervised` / `full` |
| `workspace_only` | `true` | 限制绝对路径/工作区外访问 |
| `allowed_commands` | 内置常用命令 | 命令白名单 |
| `command_context_rules` | `[]` | 对命令再加域名/路径上下文规则 |
| `unrestricted_commands` | `[]` | 真正的 break-glass，慎用 |
| `forbidden_paths` | 内置敏感列表 | 目录级 deny |
| `allowed_roots` | `[]` | 工作区外显式 allow |
| `allow_unsafe_shell_structures` | `false` | 是否允许重定向、替换、后台链 |
| `shell_env_passthrough` | `[]` | 子进程额外允许看到的环境变量名 |
| `auto_approve` | `file_read,memory_recall` | 永久自动批准的工具 |
| `always_ask` | `[]` | 即使已批准也总要再问 |
| `non_cli_excluded_tools` | 内置排除列表 | 非 CLI 通道不暴露的工具 |

两条这次修复后需要特别记住的语义：

1. `forbidden_paths` 和 `allowed_roots` 冲突时，**更具体的前缀优先**
2. `command_context_rules` 里的 `allowed_path_prefixes` / `denied_path_prefixes`，allow 规则也按 **更具体前缀优先** 处理

也就是说：

```toml
[autonomy]
forbidden_paths = ["A"]
allowed_roots = ["A/B"]
```

现在 `A/B/C` 会被允许，而不是被父级 `A` 一刀切拦掉。

### `[security]`

`[security]` 本身是一个大分区，重点子区有：

- `[security.otp]`
- `[[security.roles]]`
- `[security.estop]`
- `[security.url_access]`
- `[security.syscall_anomaly]`
- `[security.perplexity_filter]`
- `[security.outbound_leak_guard]`
- `[security.sandbox]`
- `[security.resources]`
- `[security.audit]`

这些键的白话说明已经在 [security-config-guide.md](security-config-guide.md) 里写得最细，这里只抓重点：

| 子区 | 主要用途 | 默认倾向 |
|---|---|---|
| `security.otp` | 对高风险动作或域名加二次验证 | 默认开启 |
| `security.roles` | 做细粒度用户/工具授权 | 默认空 |
| `security.estop` | 紧急停机/恢复 | 默认关闭，但生产建议打开 |
| `security.url_access` | SSRF / 域名允许名单 / 首访审批 | 默认偏保守 |
| `security.sandbox` | OS 级执行隔离 | 默认自动探测 |
| `security.resources` | CPU / 内存 / 子进程上限 | 默认保守 |
| `security.audit` | 审计日志 | 默认开启 |

## 4. 运行时、可靠性与调度

### `[runtime]`

| 键 | 默认 | 作用 |
|---|---|---|
| `kind` | `native` | `native` / `docker` / `wasm` |
| `reasoning_enabled` | `None` | 强制 provider 开/关 thinking |
| `reasoning_level` | `None` | 兼容旧键，建议改用 `[provider].reasoning_level` |

#### `[runtime.docker]`

| 键 | 默认 | 作用 |
|---|---|---|
| `image` | `alpine:3.20` | shell 执行容器镜像 |
| `network` | `none` | 容器网络模式 |
| `memory_limit_mb` | `512` | 容器内存上限 |
| `cpu_limit` | `1.0` | CPU 上限 |
| `read_only_rootfs` | `true` | 根文件系统只读 |
| `mount_workspace` | `true` | 挂载工作区 |
| `allowed_workspace_roots` | `[]` | Docker 挂载允许根 |

#### `[runtime.wasm]`

控制运行时级 WASM 沙箱，与顶层 `[wasm]`（插件引擎发现/资源限制）互补。

重点键：

- `tools_dir`
- `fuel_limit`
- `memory_limit_mb`
- `max_module_size_mb`
- `allow_workspace_read`
- `allow_workspace_write`
- `allowed_hosts`
- `[runtime.wasm.security]`

#### `[runtime.wasm.security]`

高价值键：

- `require_workspace_relative_tools_dir`
- `reject_symlink_modules`
- `reject_symlink_tools_dir`
- `strict_host_validation`
- `capability_escalation_mode`
- `module_hash_policy`
- `module_sha256`

### `[research]`

如果您希望 ZeroClaw 在回答前先主动查资料、搜代码、调工具，这一组就是开关。

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `false` | 启用研究阶段 |
| `trigger` | `never` | 何时触发 |
| `keywords` | 内置关键词 | 关键词触发列表 |
| `min_message_length` | `50` | 长文本触发阈值 |
| `max_iterations` | `5` | 研究阶段最大工具轮次 |
| `show_progress` | `true` | 是否展示研究进度 |
| `system_prompt_prefix` | `""` | 自定义研究提示前缀 |

### `[reliability]`

这组容易被忽视，但生产里很重要。

| 键 | 默认 | 作用 |
|---|---|---|
| `provider_retries` | `2` | provider 内重试次数 |
| `provider_backoff_ms` | `500` | 重试退避 |
| `fallback_providers` | `[]` | provider 级回退链 |
| `api_keys` | `[]` | 额外 API key 轮换 |
| `model_fallbacks` | `{}` | 模型级回退链 |
| `channel_initial_backoff_secs` | `2` | 通道重启初始退避 |
| `channel_max_backoff_secs` | `60` | 通道重启最大退避 |
| `scheduler_poll_secs` | `15` | 调度轮询间隔 |
| `scheduler_retries` | `2` | 调度重试次数 |

### `[scheduler]` / `[heartbeat]` / `[cron]` / `[goal_loop]`

| 区块 | 作用 | 关键键 |
|---|---|---|
| `scheduler` | 内建调度执行器 | `enabled`, `max_tasks`, `max_concurrent` |
| `heartbeat` | 周期性健康消息 | `enabled`, `interval_minutes`, `target`, `to` |
| `cron` | cron 子系统基础设置 | `enabled`, `max_run_history` |
| `goal_loop` | 自主长任务循环 | `enabled`, `interval_minutes`, `step_timeout_secs`, `max_steps_per_cycle` |

## 5. 网络、外联与暴露面

### `[gateway]`

| 键 | 默认 | 作用 |
|---|---|---|
| `host` | `127.0.0.1` | 监听地址 |
| `port` | `42617` | 监听端口 |
| `require_pairing` | `true` | 配对后才接受 bearer 请求 |
| `allow_public_bind` | `false` | 防止误绑公网 |
| `pair_rate_limit_per_minute` | `10` | `/pair` 限流 |
| `webhook_rate_limit_per_minute` | `60` | `/webhook` 限流 |
| `trust_forwarded_headers` | `false` | 仅在可信反代后启用 |
| `rate_limit_max_keys` | `10000` | 限流 key 容量 |
| `idempotency_ttl_secs` | `300` | 幂等键 TTL |
| `idempotency_max_keys` | `10000` | 幂等键容量 |

`[gateway.node_control]` 是实验能力，建议只在明确需要时开启：

- `enabled`
- `auth_token`
- `allowed_node_ids`

### `[tunnel]`

可把 gateway 暴露到外部网络。支持：

- `provider = "none"`
- `provider = "cloudflare"`
- `provider = "tailscale"`
- `provider = "ngrok"`
- `provider = "custom"`

子区：

- `[tunnel.cloudflare]`：`token`
- `[tunnel.tailscale]`：`funnel`, `hostname`
- `[tunnel.ngrok]`：`auth_token`, `domain`
- `[tunnel.custom]`：`start_command`, `health_url`, `url_pattern`

### `[proxy]`

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `false` | 总开关 |
| `http_proxy` | unset | HTTP 代理 |
| `https_proxy` | unset | HTTPS 代理 |
| `all_proxy` | unset | 所有协议代理 |
| `no_proxy` | `[]` | 直连绕过名单 |
| `scope` | `zeroclaw` | 代理作用范围 |
| `services` | `[]` | `scope = "services"` 时的服务选择器 |

建议：

- 想只代理少数外联服务时，用 `scope = "services"`
- 想完全沿用系统环境变量时，用 `scope = "environment"`

### `[browser]` / `[http_request]` / `[web_fetch]` / `[web_search]`

这几组都是外联工具面。

- `[browser]`：控制 `browser_open`、浏览器后端、computer-use sidecar
- `[http_request]`：控制 HTTP 请求工具的允许域名、超时、方法限制
- `[web_fetch]`：控制网页抓取、HTML 转 Markdown、allow/blocklist
- `[web_search]`：控制搜索 provider、fallback、结果上限

如果您是安全优先：

1. 先把 `[security.url_access]` 设严格
2. 再逐个开放 `browser/http_request/web_fetch/web_search`
3. 生产中建议启用首访审批或全局 allowlist

## 6. 存储与记忆

### `[memory]`

| 关注点 | 说明 |
|---|---|
| backend | `sqlite` / `markdown` / `lucid` / `none` |
| auto_save | 是否自动保存用户输入 |
| embedding_provider / embedding_model | 向量化后端 |
| embedding_dimensions | 维度要和模型匹配 |
| vector_weight / keyword_weight | 混合检索权重 |

### `[storage]`

`[storage]` 更像底层持久化后端配置，常见于替换默认存储实现。

重点结构：

- `[storage.provider.config]`
- `provider`
- `db_url`
- `schema`
- `table`

如果您没有明确的外部存储需求，通常保持默认即可。

## 7. 路由与分类

### `[[model_routes]]` 与 `[[embedding_routes]]`

这是把“业务 hint”映射到模型的关键能力。

| 类型 | 必填键 | 常见用途 |
|---|---|---|
| `model_routes` | `hint`, `provider`, `model` | `hint:reasoning`, `hint:fast`, `hint:code` |
| `embedding_routes` | `hint`, `provider`, `model` | `hint:semantic`, `hint:archive` |

常用配套键：

- `max_tokens`
- `api_key`
- `transport`
- `dimensions`

### `[query_classification]`

自动把不同输入路由到不同 hint。

关键结构：

- `enabled`
- `rules = []`
- 每条规则支持：`hint`, `keywords`, `patterns`, `min_length`, `max_length`, `priority`

适合：

- 简短问候走快模型
- 代码问题走 code 模型
- 长问题走 reasoning 模型

## 8. 扩展系统

### `[skills]`

| 键 | 默认 | 作用 |
|---|---|---|
| `open_skills_enabled` | `false` | 是否加载社区 skills 仓库 |
| `open_skills_dir` | unset | 本地 skills 仓库路径 |
| `trusted_skill_roots` | `[]` | 允许的 skill 真实路径根 |
| `allow_scripts` | `false` | 是否允许脚本型 skill 文件 |
| `prompt_injection_mode` | `full` | skill 注入系统提示的方式 |
| `clawhub_token` | unset | ClawhHub 下载 token |

### `[hooks]`

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `true` | 生命周期 hook 总开关 |
| `builtin.boot_script` | `false` | 启动注入提示 |
| `builtin.command_logger` | `false` | 记录命令 |
| `builtin.session_memory` | `false` | 会话提示持久化 |

注意：hook 和主进程同权限，安全要求比普通插件更高。

### `[plugins]`

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `true` | 插件系统总开关 |
| `allow` | `[]` | 允许名单；空表示全部候选 |
| `deny` | `[]` | 拒绝名单 |
| `load_paths` | `[]` | 额外扫描目录 |
| `entries` | `{}` | 每个插件的单独配置 |

每个插件条目形如：

```toml
[plugins.entries.hello-world]
enabled = true

[plugins.entries.hello-world.config]
greeting = "Howdy"
```

### `[wasm]`

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `true` | 是否加载 WASM 工具 |
| `memory_limit_mb` | `64` | 每次调用的线性内存上限 |
| `fuel_limit` | `1000000000` | 指令预算 |
| `registry_url` | ZeroMarket 公共地址 | `skill install` 的注册表 |

### `[mcp]`

MCP 允许您接外部工具服务器。

关键键：

- `enabled`
- `servers = []`
- 每个 server 支持：`name`, `transport`, `url`, `command`, `args`, `env`, `headers`, `tool_timeout_secs`

## 9. 多代理与协同

### `[agents.<name>]`

每个条目定义一个 delegate profile。

关键键：

- `provider`
- `model`
- `system_prompt`
- `api_key`
- `enabled`
- `capabilities`
- `priority`
- `temperature`
- `max_depth`
- `agentic`
- `allowed_tools`
- `max_iterations`

### `[coordination]`

这是 delegate 协调总线的运行时配置。

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `true` | 协调总线开关 |
| `lead_agent` | `delegate-lead` | 协调者身份 |
| `max_inbox_messages_per_agent` | `256` | 每个 agent 收件箱上限 |
| `max_dead_letters` | `256` | 死信上限 |
| `max_context_entries` | `512` | 共享上下文条目上限 |
| `max_seen_message_ids` | `4096` | 去重窗口 |

### `[agents_ipc]`

同一台机器上多个 ZeroClaw 实例之间的 IPC。

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `false` | 总开关 |
| `db_path` | `~/.zeroclaw/agents.db` | 共享 SQLite 路径 |
| `staleness_secs` | `300` | 离线判定窗口 |

## 10. 通道、身份与集成

### `[channels_config]`

这是所有通信入口的总表。

常见子区包括：

- `telegram`
- `discord`
- `slack`
- `mattermost`
- `whatsapp`
- `lark`
- `feishu`
- `nextcloud_talk`
- `email`
- `irc`
- `nostr`
- 以及 `ack_reaction`、`message_timeout_secs`

建议阅读：

- [channels-reference.md](channels-reference.md)
- 对应通道 setup 文档（例如 `mattermost-setup.md`、`nextcloud-talk-setup.md` 等）

### `[identity]`

| 键 | 默认 | 作用 |
|---|---|---|
| `format` | `openclaw` | 身份文档格式 |
| `extra_files` | `[]` | 额外注入的工作区文件 |
| `aieos_path` | unset | AIEOS JSON 文件路径 |
| `aieos_inline` | unset | 内联 AIEOS JSON |

### `[composio]`

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `false` | Composio 集成开关 |
| `api_key` | unset | Composio API key |
| `entity_id` | `default` | 多用户场景的实体 ID |

### `[secrets]`

| 键 | 默认 | 作用 |
|---|---|---|
| `encrypt` | `true` | 是否加密 `config.toml` 中的敏感凭据 |

## 11. 多模态、媒体与硬件

### `[multimodal]`

| 键 | 默认 | 作用 |
|---|---|---|
| `max_images` | `4` | 单次请求最多图片数 |
| `max_image_size_mb` | `5` | 单张图片最大尺寸 |
| `allow_remote_fetch` | `false` | 是否允许拉远程图片 URL |

### `[transcription]`

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `false` | 启用语音转写 |
| `api_key` | unset | 转写服务 API key |
| `api_url` | Groq Whisper API | 转写接口地址 |
| `model` | `whisper-large-v3-turbo` | 转写模型 |
| `language` | unset | 语言提示 |
| `max_duration_secs` | `120` | 最大音频时长 |

### `[hardware]`

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `false` | 硬件访问总开关 |
| `transport` | `none` | `native` / `serial` / `probe` |
| `serial_port` | unset | 串口路径 |
| `baud_rate` | `115200` | 波特率 |
| `probe_target` | unset | 探针目标芯片 |
| `workspace_datasheets` | `false` | 工作区 datasheet 检索 |

### `[peripherals]`

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `false` | 外设板卡支持开关 |
| `boards` | `[]` | 板卡列表 |
| `datasheet_dir` | unset | datasheet 目录 |

`[[peripherals.boards]]` 常见键：

- `board`
- `transport`
- `path`
- `baud`

## 12. 预算与经济模型

### `[cost]`

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `false` | 成本跟踪总开关 |
| `daily_limit_usd` | `10.0` | 日预算 |
| `monthly_limit_usd` | `100.0` | 月预算 |
| `warn_at_percent` | `80` | 预警阈值 |
| `allow_override` | `false` | 是否允许超预算强制继续 |
| `prices` | 内置若干模型价格 | 自定义价格表 |
| `enforcement` | 预算执行策略 | 见下方 |

`[cost.enforcement]`：

- `mode = "warn" | "route_down" | "block"`
- `route_down_model = "hint:fast"`（默认）
- `reserve_percent = 10`

### `[economic]`

偏实验，用来模拟 agent 经济生存模型。

| 键 | 默认 | 作用 |
|---|---|---|
| `enabled` | `false` | 总开关 |
| `initial_balance` | `1000.0` | 初始余额 |
| `token_pricing` | 有默认值 | 输入/输出 token 价格 |
| `min_evaluation_threshold` | `0.6` | 达标才结算 |
| `data_path` | unset | 状态持久化目录 |

## 13. 我该怎么改，才不容易改乱

推荐按这个顺序改：

1. 先定模型：`default_provider`、`default_model`
2. 再定入口：`channels_config`、`gateway`
3. 再定安全边界：`autonomy`、`security`
4. 再定记忆与路由：`memory`、`model_routes`、`query_classification`
5. 最后才开扩展：`skills`、`plugins`、`mcp`、`wasm`

## 14. 两套推荐起步配置

### 单机开发机（偏稳）

- `autonomy.level = "supervised"`
- `autonomy.workspace_only = true`
- `security.url_access.require_first_visit_approval = true`
- `security.estop.enabled = true`
- `secrets.encrypt = true`
- `proxy.enabled = false`（除非您明确知道自己在做什么）

### 小团队长期运行（偏生产）

- `gateway.require_pairing = true`
- `gateway.allow_public_bind = false`
- `security.audit.enabled = true`
- `security.otp.enabled = true`
- `security.sandbox.enabled = true`
- `cost.enabled = true`
- `reliability.fallback_providers = [...]`
- `scheduler.enabled = true` 但保持 `max_concurrent` 保守

## 15. 继续阅读

- 中文配置参考（简版）：[config-reference.md](config-reference.md)
- 中文安全配置白话指南：[security-config-guide.md](security-config-guide.md)
- 中文 Provider 参考：[providers-reference.md](providers-reference.md)
- 中文 Channel 参考：[channels-reference.md](channels-reference.md)
- 英文配置参考（运行时合同）：[../../config-reference.md](../../config-reference.md)
