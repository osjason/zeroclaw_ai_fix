# ZeroClaw 安全配置白话指南

最后核对：**2026-03-09**。

这篇指南写给会改 `config.toml`，但不想被安全术语绕晕的人。

它不只解释“这个键是什么意思”，更重点解释：

- 它到底在防什么
- 为什么您会需要它
- 什么情况下最好当成必选
- 什么情况下可以暂时不开
- 改松了会出什么问题

说明：

- 配置键、字段名、命令名保持英文原样，方便您直接照着改。
- 默认值以当前代码为准，不盲目照抄旧文档。
- 这里说的“安全配置”不只包括 `[security]`，也包括 `[gateway]`、`[secrets]`、网络工具、聊天通道允许名单等真正会影响安全边界的设置。

## 怎么用这篇文档

您不需要从头到尾背下来。

推荐按这个顺序看：

1. 先看“5 分钟判断表”
2. 再看和您场景最接近的那一章
3. 真要改某个配置时，再回来看它对应的小节

如果您只记住一句话，请记这句：

- 只要 ZeroClaw 不是“只在本机、只给自己、只做手动试用”，大多数保护都应该从“建议开启”提升到“默认别关”。

## 5 分钟判断表

### 1. 您现在属于哪一类使用方式

| 您的情况 | 风险等级 | 应该重点看 |
|---|---|---|
| 只在本机终端里手动试用 | 低 | `gateway.host`、`allow_public_bind`、`secrets.encrypt` |
| 在同一局域网里给自己手机/平板用 | 中 | `[gateway]`、`require_pairing`、`allow_public_bind`、channel 允许名单 |
| 接了 Telegram / Discord / Slack / WhatsApp / GitHub webhook | 高 | channel 允许名单、`webhook_secret`/`verify_token`、`security.otp`、`security.estop` |
| 长期开着，您不是一直盯着屏幕 | 高 | `security.estop`、`security.otp`、`security.url_access`、`security.outbound_leak_guard` |
| 会跑命令、写文件、访问网站 | 高 | `[autonomy]`、`security.otp`、`security.estop`、`security.url_access` |

### 2. 哪些配置大多数人不该关

| 配置 | 当前默认 | 为什么大多数人不该关 |
|---|---|---|
| `gateway.require_pairing` | `true` | 少一层“先配对再调用”的门 |
| `secrets.encrypt` | `true` | 关了更容易把 token 明文落地 |
| `security.otp.enabled` | `true` | 高风险动作少一道“你确定吗” |
| `security.outbound_leak_guard.enabled` | `true` | 回复前少一层防泄露检查 |
| `security.url_access.block_private_ip` | `true` | 更容易碰到家里和公司内网设备 |
| `autonomy.block_high_risk_commands` | `true` | 高风险命令更可能直接执行 |
| `autonomy.require_approval_for_medium_risk` | `true` | 中风险动作更容易不经确认就执行 |

### 3. 哪些配置一旦开了，就要连着看别的项

| 您要开的东西 | 同时还应该看 |
|---|---|
| `gateway.allow_public_bind = true` | `gateway.require_pairing`、channel 允许名单、各种 webhook secret |
| `http_request.enabled = true` | `http_request.allowed_domains`、`security.url_access` |
| `web_fetch.enabled = true` | `web_fetch.allowed_domains`、`security.url_access` |
| `browser.enabled = true` | `browser.allowed_domains`、`security.url_access` |
| `security.estop.enabled = true` | `security.estop.require_otp_to_resume`、`security.otp.enabled` |
| 聊天机器人接群聊 | `allowed_users` 同类字段、`non_cli_natural_language_approval_mode` |

### 4. 三个最容易误会的写法

| 写法 | 很多人误以为 | 实际更接近 |
|---|---|---|
| `allowed_users = ["*"]` | “先这样方便一点，应该没事” | “谁都可以来试着触发机器人” |
| `allow_public_bind = true` | “只是让网络更通” | “把门开到局域网甚至更外面” |
| `allowed_node_ids = []` | “空名单更安全” | 当前实现里更接近“不额外限制” |

### 5. 如果您完全不确定，先用这套保守方案

```toml
[gateway]
host = "127.0.0.1"
require_pairing = true
allow_public_bind = false

[security.otp]
enabled = true

[security.estop]
enabled = true
require_otp_to_resume = true

[security.url_access]
block_private_ip = true
allow_loopback = false
enforce_domain_allowlist = false

[secrets]
encrypt = true

[security.outbound_leak_guard]
enabled = true
action = "redact"
```

## 先学会看“必须”这两个字

本文里说“几乎算必需”，意思不是“代码跑不起来”，而是：

- 不开也许还能用
- 但一旦出事，您很可能会后悔当时没开

对普通用户来说，下面几种情况会让某些保护从“建议”升级到“几乎算必需”：

- 接了外部聊天平台
- 开始长期后台运行
- 您不再是全程盯着屏幕
- 它可以跑命令、改文件、联网访问
- 它不只服务您一个人

## A. 谁能访问您的 ZeroClaw

这部分防的是“外人能不能碰到您”和“谁发来的消息会被它当真”。

### `[gateway]`

这是最基础的一扇门。

#### 先看结论

| 配置 | 默认值 | 大白话结论 |
|---|---|---|
| `host` | `127.0.0.1` | 默认只让本机访问 |
| `port` | `42617` | 门牌号，不是门锁 |
| `require_pairing` | `true` | 先配对再用，别随便关 |
| `allow_public_bind` | `false` | 不想让别的设备来连，就别开 |
| `trust_forwarded_headers` | `false` | 不在可信代理后面就别开 |

#### `host`

- 默认值：`127.0.0.1`
- 它在防什么：防止服务默认暴露给别的设备。
- 为什么会需要它：因为只要您想从别的设备访问，就一定要让服务监听到别的地址上。
- 开着默认值时会怎样：只有这台电脑自己能连。
- 改成 `0.0.0.0` 一类地址会怎样：同一局域网、代理后的其他机器，甚至公网转发，都可能连到它。

什么时候几乎算必需改：

- 您明确要从手机、平板、另一台电脑访问这台机器
- 您放在服务器上，要让反向代理转发进来

什么时候通常不要改：

- 只在本机终端里使用
- 本机临时试用配置

例子：

- 自己电脑上本机用：保持 `127.0.0.1`
- 想让手机在同一 Wi‑Fi 下访问：才会考虑放开

#### `port`

- 默认值：`42617`
- 它在防什么：它本身不负责防护，主要是入口编号。
- 为什么需要知道它：因为别人要连，最终还是连到某个端口。
- 风险：如果您已经把 `host` 放开，这个端口就变成别人能尝试访问的门牌号。

普通建议：

- 只是换端口，不等于更安全
- 真正关键的是 `host`、`require_pairing`、允许名单、secret

#### `require_pairing`

- 默认值：`true`
- 它在防什么：防止“只要能连到地址，就能直接调用”。
- 为什么会需要它：因为一旦网关能被别的设备碰到，您就需要一层“先配对拿凭证”的门。

什么时候几乎算必需：

- 您开了局域网访问
- 您通过代理、隧道、服务器对外提供访问
- 您不是唯一会碰这台机器的人

什么时候可以考虑关：

- 您非常清楚还有别的强认证层已经挡在前面
- 并且您知道关掉这层后是谁来兜底

大白话理解：

- 开着：不是知道地址就能用
- 关着：更接近“能连上就能继续试”

#### `allow_public_bind`

- 默认值：`false`
- 它在防什么：防止您手滑把服务直接开到局域网或公网。
- 为什么会需要它：因为默认只给本机；想让别的设备访问时，迟早会碰到它。

什么时候几乎算必需：

- 您要从同一 Wi‑Fi 的手机、平板、另一台电脑访问
- 您需要让反向代理或其他机器转发进来

什么时候绝对不是必需：

- 只在本机终端里用
- 您只是本机调试，没有远程访问需求

开了以后代表什么：

- 不是“网络更通了”
- 而是“门开大了”

开了以后通常还要一起做的事：

- 保留 `require_pairing = true`
- 不要把聊天通道允许名单留成 `"*"`
- 能配 `webhook_secret` / `verify_token` 的都配上

例子：

- 家里电脑上跑 ZeroClaw，只想本机用：不要开
- 想让手机来连：可能要开，但不能只开这一项就算完

#### `pair_rate_limit_per_minute`

- 默认值：`10`
- 它在防什么：防止别人不停试配对。
- 调低：更早拦住反复尝试，但自己输错时也更容易短暂被拦
- 调高：自己更宽松，别人暴力尝试空间也更大
- 普通建议：默认值通常够用

#### `webhook_rate_limit_per_minute`

- 默认值：`60`
- 它在防什么：防止 webhook 被高频猛打。
- 调低：更保守，但可能误伤高峰流量
- 调高：更宽松，但更抗不住刷接口

#### `trust_forwarded_headers`

- 默认值：`false`
- 它在防什么：防止有人伪造“来访者是谁”的地址信息。
- 为什么会需要它：如果您前面放了自己控制的反向代理，就可能需要让 ZeroClaw 相信代理转发过来的真实来源地址。

什么时候几乎算必需开：

- 您明确在可信反向代理后面运行，而且限流/来源识别要基于真实客户端 IP

什么时候不要开：

- 您不确定自己前面是不是可信代理
- 您只是直接裸跑服务

#### `rate_limit_max_keys`

- 默认值：`10000`
- 它在防什么：不是直接防护，而是控制限流记录最多记多少来源。
- 太小：来源一多，旧记录更快被挤掉，限流效果变差
- 太大：更占内存

#### `idempotency_ttl_secs`

- 默认值：`300`
- 它在防什么：防止同一个请求短时间被当成新请求重复处理。
- 为什么有用：现实里上游平台会重试，网络抖动也会重发。

#### `idempotency_max_keys`

- 默认值：`10000`
- 它在防什么：限制最多记住多少个“别重复处理”的请求标记。
- 主要影响：内存和去重能力之间的平衡

### `[gateway.node_control]`

这是实验性质的远程节点控制入口。

如果您没有明确做多节点控制，可以直接把它当成“默认不用碰”的区域。

#### `enabled`

- 默认值：`false`
- 它在防什么：防止额外远程控制入口被无意打开。
- 为什么会需要它：只有您真的在做远程节点控制时才需要。
- 普通建议：不用就一直关着。

#### `auth_token`

- 默认值：未设置
- 它在防什么：给节点控制再加一把口令。
- 普通建议：如果您真的打开了 `enabled`，尽量同时设上它。

#### `allowed_node_ids`

- 默认值：`[]`
- 它在防什么：限制哪些远端节点 ID 可以操作。
- 重要提醒：这里空数组按当前实现更接近“不额外限制”，不是“全部拒绝”。
- 普通建议：真要用时，写明确名单，不要留空。

### 各聊天通道里的允许名单

名字可能不同，但核心意思几乎一样：

- `allowed_users`
- `allowed_from`
- `allowed_numbers`
- `allowed_senders`
- `allowed_contacts`
- `allowed_pubkeys`
- GitHub 场景里类似的是 `allowed_repos`

#### 为什么它几乎总是重要

- bot token 不是允许名单
- access token 不是允许名单
- webhook 地址也不是允许名单

这些东西解决的是“机器人怎么连上平台”，不是“谁发来的内容可以被当真”。

允许名单真正解决的是：

- 谁能让机器人理他
- 谁的话会进入后续工具调用
- 谁有机会触发写文件、跑命令、发请求

#### 三种最常见写法

| 写法 | 白话意思 | 适合什么场景 | 风险 |
|---|---|---|---|
| `[]` | 谁都不允许 | 先锁死、先排错 | 机器人像“没反应” |
| `["*"]` | 谁都允许 | 临时验证接入是否正常 | 最容易放过头 |
| `["具体ID"]` | 只允许名单里的人 | 长期使用 | 需要您自己维护名单 |

#### 什么时候几乎算必需写具体名单

- 机器人在群里
- 机器人接了公开或半公开平台
- 机器人可以跑命令、写文件、联网
- 不只您一个人能接触这个通道

#### 什么时候可以临时用 `["*"]`

- 第一次接平台，只想确认 webhook 通不通
- 正在排查“为什么机器人完全不回”

但建议：

- 只临时用
- 测通后尽快改回具体名单

#### 例子

- Telegram：`allowed_users = ["123456789"]`
- Signal：`allowed_from = ["+8613800000000"]`
- WhatsApp/WATI：`allowed_numbers = ["*"]` 只适合短暂验证

### 各种 `webhook_secret`、`signing_secret`、`verify_token`、`secret`

这些字段名字不同，但作用接近：让 ZeroClaw 判断“这个回调是不是真的来自平台，而不是别人伪造的”。

常见字段：

- `channels_config.webhook.secret`
- `channels_config.whatsapp.verify_token`
- `channels_config.whatsapp.app_secret`
- `channels_config.linq.signing_secret`
- `channels_config.github.webhook_secret`
- `channels_config.nextcloud_talk.webhook_secret`
- `channels_config.wati.webhook_secret`
- `channels_config.bluebubbles.webhook_secret`

#### 用白话理解

| 类型 | 更像什么 | 作用 |
|---|---|---|
| `verify_token` | 对暗号 | 初始化或验证时确认双方说的是同一套暗号 |
| `webhook_secret` / `signing_secret` / `app_secret` | 验签密钥 | 检查这条回调是不是被平台正确签过名 |
| `secret` | 共享小口令 | 额外确认请求方知道约定好的口令 |

#### 为什么它几乎算必需

- 一旦您把 webhook 暴露出来，就意味着别人也可能打到这个地址
- 没有 secret / 签名验证时，分辨伪造请求会更难

#### 普通建议

- 支持就尽量配
- 不要用太简单的值
- 不要公开截图、贴到群里、发进 issue

## B. ZeroClaw 能替您做多危险的事

这部分防的是“不是外人闯进来，而是 ZeroClaw 自己做过头”。

### `[autonomy]`

这一组决定它有多大行动自由。

#### 先看最关键的 6 个项

| 配置 | 默认值 | 最该记住的一句话 |
|---|---|---|
| `level` | `supervised` | 大多数人就留在这个档位 |
| `workspace_only` | `true` | 尽量别让它跑出当前工作区 |
| `allowed_commands` | 内置常用命令 | 不要随便写成 `"*"` |
| `block_high_risk_commands` | `true` | 别轻易关 |
| `require_approval_for_medium_risk` | `true` | 别让中风险动作悄悄直接过 |
| `allow_sensitive_file_reads` / `allow_sensitive_file_writes` | `false` / `false` | 敏感文件平时别放开 |

#### `level`

- 默认值：`supervised`
- 它在防什么：防止给 ZeroClaw 过大的整体行动自由。

三档可以这样理解：

| 值 | 白话理解 | 适合谁 |
|---|---|---|
| `read_only` | 主要看和分析，不轻易动手 | 非常保守的只读场景 |
| `supervised` | 危险动作前先问您 | 大多数人 |
| `full` | 放得更开 | 非常清楚后果的人 |

普通建议：

- 大多数人保持 `supervised`
- 没有充分理由，不要直接升到 `full`

#### `workspace_only`

- 默认值：`true`
- 它在防什么：防止它随便跑出当前工作区去碰别的目录。
- 为什么重要：很多人以为“我只是让它帮我改项目”，但如果这项放松，它可能碰到项目外的文件。
- 普通建议：除非明确需要跨目录工作，否则保持 `true`。

#### `allowed_commands`

- 默认值：内置常用命令，如 `git`、`cargo`、`ls`、`cat`
- 它在防什么：防止它调用您根本没打算开放的系统命令。
- 为什么重要：命令名越宽，能做的事越多。

最容易踩坑的写法：

| 写法 | 后果 |
|---|---|
| 只放少量必要命令 | 最稳 |
| 放很多自己都没想清楚的命令 | 风险快速上升 |
| `"*"` | 几乎不再限制命令种类 |

#### `command_context_rules`

- 默认值：空
- 它在防什么：给命令再加更细的场景限制。
- 适合谁：已经知道自己要按命令参数、路径、上下文做精细控制的人。
- 普通建议：新手先不碰。

#### `forbidden_paths`

- 默认值：内置系统目录和敏感目录，如 `/etc`、`~/.ssh`、`~/.aws`
- 它在防什么：防止就算别的地方放松了，也碰到明显敏感的位置。
- 普通建议：保留默认值，不要为了图省事随便删。

#### `allowed_roots`

- 默认值：空
- 它在防什么：这是“工作区外的额外放行名单”。
- 什么时候会需要：您确实需要访问工作区外某个固定目录。
- 风险：加得越多，ZeroClaw 能碰到的范围越大。

#### `max_actions_per_hour`

- 默认值：`100`
- 它在防什么：防止一小时里连续做太多步动作。
- 为什么它重要：出问题时，限制总动作数通常比“事后后悔”更有用。
- 调低：更保守
- 调高：更适合长流程，但事故时也可能连续做更多步

#### `max_cost_per_day_cents`

- 默认值：`1000`
- 它在防什么：防止一天内花费失控。
- 白话换算：`1000` 美分就是 10 美元。
- 普通建议：预算敏感的场景可以适当调低。

#### `require_approval_for_medium_risk`

- 默认值：`true`
- 它在防什么：防止中等风险动作默默直接执行。
- 普通建议：大多数人保留 `true`。

#### `block_high_risk_commands`

- 默认值：`true`
- 它在防什么：防止高风险命令就算被放进行名单，也直接跑起来。
- 什么时候几乎算必需：您只要没完全搞清楚自己放开的每一类命令，基本都应该保留它。

#### `allow_sensitive_file_reads`

- 默认值：`false`
- 它在防什么：防止敏感文件被读出来。
- 什么时候可以临时开：排查 `.env`、凭据文件、证书文件相关问题时
- 什么时候应该关：平时长期运行时

#### `allow_sensitive_file_writes`

- 默认值：`false`
- 它在防什么：防止敏感文件被改坏、覆盖、泄露。
- 普通建议：除非您明确要自动改这些文件，否则保持关。

#### `shell_env_passthrough`

- 默认值：空
- 它在防什么：避免把额外环境变量，尤其是带 secret 的变量，白送给子进程。
- 普通建议：只放您真需要透传的变量名。

#### `auto_approve`

- 默认值：`["file_read", "memory_recall"]`
- 它在防什么：防止您为了方便把太多动作变成“自动放行”。
- 普通建议：只给真正低风险、以读取为主的工具自动通过。

#### `always_ask`

- 默认值：`[]`
- 它在防什么：这是“我对某些动作特别不放心，所以每次都问”的清单。
- 适合谁：想对个别高风险动作再加一道人工确认的人。

#### `non_cli_excluded_tools`

- 默认值：内置一批高风险工具在非命令行通道默认不暴露
- 它在防什么：防止聊天平台里直接看到太多危险工具。
- 普通建议：保留默认值。

#### `non_cli_approval_approvers`

- 默认值：空
- 它在防什么：限制聊天平台里谁有资格做批准操作。
- 重要提醒：空数组按当前实现，不是“谁都不行”，而是更接近“只要已经通过该通道允许名单的人都可以”。
- 团队场景建议：写明确名单。

#### `non_cli_natural_language_approval_mode`

- 默认值：`direct`
- 它在防什么：防止聊天里一句自然语言就过于直接地产生批准效果。

| 值 | 白话理解 | 适合场景 |
|---|---|---|
| `direct` | 说了就生效 | 私聊自己用 |
| `request_confirm` | 先挂起，再确认一次 | 群聊或团队聊天 |
| `disabled` | 不接受自然语言批准 | 最保守 |

#### `non_cli_natural_language_approval_mode_by_channel`

- 默认值：空
- 它在防什么：让不同通道用不同的批准强度。
- 适合场景：私聊自己走 `direct`，群聊走 `request_confirm`。

### `[security.otp]`

这是一层“危险动作前，再问您一次”的保护。

请注意：按当前代码，`security.otp.enabled` 默认值是 `true`。

#### 为什么它存在

很多事故不是“完全陌生人入侵”，而是：

- 您自己一句话描述得不够清楚
- 模型误解了意思
- 某个聊天消息刚好看起来像命令
- 机器人已经接到群里，您不想一条危险操作直接生效

OTP 解决的是：

- 在真正危险的那一步前，再停一下，确认一次

#### 什么时候它几乎算必需

- 接了聊天平台长期运行
- 允许跑命令、写文件、打开浏览器、删除内容
- 您不是一直盯着屏幕
- 不只您一个人能接触这个通道

#### 什么时候可以暂时不开得那么重

- 只在本机终端手动试用
- 您全程盯着
- 没开放高风险工具

#### `enabled`

- 默认值：`true`
- 它在防什么：防止高风险动作少了最后一道人工确认。
- 开着：危险动作前再问您一遍
- 关着：相信当前会话永远不会做错

#### `method`

- 默认值：`totp`
- 它在防什么：决定验证码从哪里来。
- 白话理解：`totp` 就是常见验证器 App 那种每 30 秒换一次码。
- 普通建议：保持 `totp`。

#### `token_ttl_secs`

- 默认值：`30`
- 它在防什么：控制一个验证码每轮有效多久。
- 调短：更严格，但更容易来不及
- 调长：更宽松，但有效时间更长

#### `cache_valid_secs`

- 默认值：`300`
- 它在防什么：避免您刚验证完，下一步马上又被要求再输一次。
- 调高：更方便，但短时间里会更宽松
- 调低：更严格，但更容易烦

#### `gated_actions`

- 默认值：`["shell", "file_write", "browser_open", "browser", "memory_forget"]`
- 它在防什么：决定哪些动作必须走这次二次确认。

为什么默认会把这些动作放进去：

| 动作 | 为什么危险 |
|---|---|
| `shell` | 能直接跑系统命令 |
| `file_write` | 能改坏代码、配置、数据 |
| `browser_open` / `browser` | 可能打开登录页、付款页、后台页 |
| `memory_forget` | 可能删掉重要记忆 |

#### `gated_domains`

- 默认值：空
- 它在防什么：防止访问特定敏感网站时一步走太快。
- 适合放进去的网站：银行、邮箱、身份登录站点、支付站点。

#### `gated_domain_categories`

- 默认值：空
- 它在防什么：让您不用手写一大串域名，也能给一整类敏感网站加二次确认。

#### `challenge_delivery`

- 默认值：`dm`
- 它在防什么：防止验证码挑战在不合适的地方出现。

| 值 | 白话理解 | 普通建议 |
|---|---|---|
| `dm` | 私信给您 | 最稳 |
| `thread` | 发在线程里 | 次选 |
| `ephemeral` | 临时只给您看的消息 | 平台支持时也不错 |

#### `challenge_timeout_secs`

- 默认值：`120`
- 它在防什么：防止一次挑战挂太久还有效。

#### `challenge_max_attempts`

- 默认值：`3`
- 它在防什么：防止一条挑战里反复乱试太多次。

### `[security.estop]`

`estop` 可以把它理解成“紧急刹车”。

它不是给您天天按的，而是为了“现在立刻先停住”。

#### 它到底在防什么

它防的是这种场面：

- 您发现它开始做不该做的事
- 它开始重复跑命令，像停不下来
- 它开始访问奇怪的网站
- 聊天平台里有人明显在试探、刷、误触
- 您刚放开自动化能力，想留一把“出事立刻拉闸”的手柄

#### 为什么很多人其实应该把它当成必选

很多人一开始会觉得：

- “我平时小心一点就好了”
- “真出事我手动停进程就行”

但真实问题在于：

- 出事时您可能不在屏幕前
- 手动停进程不一定快
- 重启服务后，危险状态如果没有被记住，可能又继续跑

所以 `estop` 的价值不是“日常更方便”，而是“出事时别手忙脚乱”。

#### 什么时候它几乎算必需

满足下面任意两条，就很建议把它当成基础配置：

- 接了聊天平台
- 长期开着
- 您不是一直盯着
- 它能跑命令
- 它能写文件
- 它能访问网络

#### 什么时候可以暂时不开

- 只在本机终端手动试用
- 全程盯着
- 没开放高风险工具
- 只是短时间测试

但只要开始长期运行，`estop` 就更像“安全带”，而不是“可有可无的配件”。

#### `enabled`

- 默认值：`false`
- 它在防什么：防止您根本没有现成的“先停下”机制。

把它说得更直白一点：

- 开着：出问题时，您有一个明确、统一、可重复使用的急停办法
- 关着：出问题时，您只能临时想办法停进程、断网、关服务

后者不是不能做，只是通常更乱，也更慢。

#### `state_file`

- 默认值：`~/.zeroclaw/estop-state.json`
- 它在防什么：防止服务一重启，刚才的急停就像没发生过。
- 为什么重要：这是把“刹车状态”记下来，避免重启后又继续危险动作。

#### `require_otp_to_resume`

- 默认值：`true`
- 它在防什么：防止刚拉下的刹车被别人轻易偷偷恢复。
- 普通建议：保留 `true`。

### `[security.sandbox]`

这里的 `sandbox` 可以简单理解成“给它能启动的程序套围栏”。

#### 什么时候它重要

- 只要您允许 ZeroClaw 跑命令，它就开始重要
- 这层围栏不是唯一保护，但能在程序真的启动后，再多一道约束

#### `enabled`

- 默认值：自动判断
- 它在防什么：尽量让命令执行被围在更小范围里。
- 普通建议：能开就尽量开。

#### `backend`

- 默认值：`auto`
- 它在防什么：决定用哪种围栏方式。

| 值 | 白话理解 | 普通建议 |
|---|---|---|
| `auto` | 自动选可用方案 | 大多数人用这个 |
| `landlock` / `firejail` / `bubblewrap` / `docker` | 指定某种方案 | 知道自己环境的人再指定 |
| `none` | 不用围栏 | 一般不建议 |

#### `firejail_args`

- 默认值：空
- 它在防什么：这不是新增防护，而是自定义 `firejail` 行为。
- 风险：写错可能让围栏失效，或者把功能锁死。
- 普通建议：新手别动。

### `[security.resources]`

这组可以理解成“别让一次动作吃太多资源”。

它不直接防入侵，但能降低“跑飞、卡死、过载”的风险。

| 配置 | 默认值 | 它在防什么 |
|---|---|---|
| `max_memory_mb` | `512` | 防止单次命令吃太多内存 |
| `max_cpu_time_seconds` | `60` | 防止单次命令跑太久 |
| `max_subprocesses` | `10` | 防止一下子炸出太多子进程 |
| `memory_monitoring` | `true` | 保持内存监控开启 |

普通建议：

- 不清楚时保留默认值
- 如果机器配置比较小，可以适当调低

## C. ZeroClaw 能访问哪些网站和地址

这部分防的是“它会不会碰到您本来不想让它碰的网络目标”。

### `[security.url_access]`

这是所有“访问网址”功能共用的大门卫。

#### 先看最关键的 5 个项

| 配置 | 默认值 | 大白话结论 |
|---|---|---|
| `block_private_ip` | `true` | 不清楚时千万别关 |
| `allow_loopback` | `false` | 不要轻易让它碰本机服务 |
| `require_first_visit_approval` | `false` | 想更稳可以开 |
| `enforce_domain_allowlist` | `false` | 长期运行建议朝这个方向收紧 |
| `domain_blocklist` | `[]` | 有不想碰的网站就放这里 |

#### `block_private_ip`

- 默认值：`true`
- 它在防什么：防止它去碰本地和内网地址。
- 为什么这项常常该当成必需：很多最敏感的东西不在公网，而在您自己家里或公司里。

比如：

- 路由器管理页
- NAS
- 公司内部 API
- 测试后台
- 本机数据库和面板

一旦关掉：

- 它能碰到的东西会突然多很多
- 而且这些东西往往比公网网页更敏感

#### `allow_cidrs`

- 默认值：空
- 它在防什么：这是“内网例外放行网段”。
- 什么时候用：您明确知道要访问哪段内网。
- 普通建议：只写最小范围，不要图省事放太大。

#### `allow_domains`

- 默认值：空
- 它在防什么：让某些会解析到内网的域名例外放行。
- 风险：写太宽会给内网保护开口子。

#### `allow_loopback`

- 默认值：`false`
- 它在防什么：防止它碰 `localhost`、`127.0.0.1`、`::1`。
- 为什么重要：本机上往往跑着数据库、管理面板、开发服务。
- 普通建议：除非明确需要访问本机服务，否则别开。

#### `require_first_visit_approval`

- 默认值：`false`
- 它在防什么：防止第一次见到陌生域名时直接就访问。
- 适合谁：比较谨慎，希望“第一次先问我”的人。

#### `enforce_domain_allowlist`

- 默认值：`false`
- 它在防什么：让访问规则变成“没写进总允许名单，就不准去”。
- 什么时候几乎算必需：长期自动化、半公开部署、对外通道比较多时。

#### `domain_allowlist`

- 默认值：空
- 它在防什么：这是长期稳定的总允许名单。
- 普通建议：只放您真正长期信任的网站。

#### `domain_blocklist`

- 默认值：空
- 它在防什么：这是总拒绝名单。
- 特点：优先级最高，适合“这个站现在立刻别碰”。

#### `approved_domains`

- 默认值：空
- 它在防什么：这是人工批准过的域名记录。
- 适合谁：用“第一次先问，之后不再重复问”的模式。

### `[http_request]`

这是直接发 HTTP 请求的工具。

#### 先看重点

| 配置 | 默认值 | 重点 |
|---|---|---|
| `enabled` | `false` | 不用就别开 |
| `allowed_domains` | `[]` | 空就是全拒绝，最关键 |
| `credential_profiles` | `{}` | 比把 token 直接塞进参数更安全 |

#### `enabled`

- 默认值：`false`
- 它在防什么：不开就没有这条直接发请求的能力。
- 普通建议：不用就保持关。

#### `allowed_domains`

- 默认值：空
- 它在防什么：限制只允许请求哪些域名。
- 重要提醒：空数组在当前实现里是“全部拒绝”。

| 写法 | 意思 |
|---|---|
| `[]` | 谁都不放行 |
| `["api.example.com"]` | 只让它打这个站 |
| `["*"]` | 放行所有公网域名，但仍受 `security.url_access` 限制 |

普通建议：

- 尽量写具体域名
- 不要长期用 `"*"`

#### `max_response_size`

- 默认值：`1000000`
- 它在防什么：防止一次请求拖回过大的数据。

#### `timeout_secs`

- 默认值：`30`
- 它在防什么：防止请求卡太久。

#### `user_agent`

- 默认值：`ZeroClaw/1.0`
- 它主要影响兼容性，不是核心安全门。

#### `credential_profiles`

- 默认值：空
- 它在防什么：防止把 token 直接裸写到工具参数或提示词里。
- 为什么推荐：让真正的 secret 留在环境变量中，只在发请求时注入。

子字段结构化说明：

| 子字段 | 默认值 | 白话意思 |
|---|---|---|
| `header_name` | `Authorization` | 把 secret 塞进哪个请求头 |
| `env_var` | 空 | 真正的 secret 藏在哪个环境变量里 |
| `value_prefix` | `Bearer ` | 要不要自动补前缀 |

### `[web_fetch]`

这是“抓网页正文”的工具，不是搜索引擎。

#### 关键点

- `enabled` 默认关
- `allowed_domains` 默认是 `["*"]`
- 即使 `allowed_domains = ["*"]`，也仍会继续受 `[security.url_access]` 约束

#### 结构化说明

| 配置 | 默认值 | 白话解释 |
|---|---|---|
| `enabled` | `false` | 不用就别开 |
| `allowed_domains` | `["*"]` | 默认放行所有公网域名，范围偏宽 |
| `blocked_domains` | `[]` | 不想碰的网站放这里 |
| `max_response_size` | `500000` | 防止抓太大 |
| `timeout_secs` | `30` | 防止等太久 |

额外提醒：

- 这里的默认比 `http_request` 宽松
- 如果您只抓固定站点，建议手动收紧 `allowed_domains`

### `[web_search]`

这是“找网站入口”的工具。

安全上最重要的不是它选哪家搜索服务，而是它会不会把搜索范围放得太散。

#### 结构化说明

| 配置 | 默认值 | 白话解释 |
|---|---|---|
| `enabled` | `false` | 不用就别开 |
| `provider` | `duckduckgo` | 用哪家搜索服务 |
| `domain_filter` | `[]` | 只在某些网站里搜 |
| `language_filter` | `[]` | 偏向哪些语言 |
| `country` | 未设置 | 偏向哪个地区 |
| `recency_filter` | 未设置 | 偏向最近多久 |
| `max_results` | `5` | 一次带回多少结果 |
| `timeout_secs` | `15` | 最多等多久 |

其余和 secret 相关的项：

- `api_key`
- `brave_api_key`
- `perplexity_api_key`
- `exa_api_key`
- `jina_api_key`

这些都应按密钥管理，不要随便明文传播。

### `[browser]`

如果您会用 `browser_open` 或浏览器自动化，这组也和安全强相关。

#### `enabled`

- 默认值：`false`
- 它在防什么：不开就没有浏览器打开能力。

#### `allowed_domains`

- 默认值：空
- 它在防什么：限制只允许打开哪些域名。
- 普通建议：只放您真要访问的网站。

### `[multimodal]`

这一组大多是图片数量和大小限制，但有一个字段会扩大网络接触面。

#### `allow_remote_fetch`

- 默认值：`false`
- 它在防什么：防止它根据远程图片 URL 自己去网上抓图。
- 开着：处理图片时可能主动访问远程地址
- 关着：只处理您已经上传或本地已有的图片
- 普通建议：不确定来源是否可信时，保持 `false`

### `[browser.computer_use]`

这组是“通过侧车服务代您点鼠标、按键盘、截图”。

一旦它跨机器，就不只是“浏览器工具”了，而是“远程控制能力”。

#### 先看重点

| 配置 | 默认值 | 重点 |
|---|---|---|
| `endpoint` | `http://127.0.0.1:8787/v1/actions` | 默认本机较稳 |
| `api_key` | 未设置 | 有认证能力就尽量配 |
| `allow_remote_endpoint` | `false` | 不清楚时别开 |
| `window_allowlist` | `[]` | 想只让它碰某个程序时很好用 |

#### `endpoint`

- 默认值：`http://127.0.0.1:8787/v1/actions`
- 它在防什么：默认把控制面留在本机。
- 风险：改成远程地址后，控制能力会跨机器传出去。

#### `api_key`

- 默认值：未设置
- 它在防什么：给侧车服务再加一把口令。
- 普通建议：支持就配。

#### `timeout_ms`

- 默认值：`15000`
- 主要是稳定性，不是核心安全门。

#### `allow_remote_endpoint`

- 默认值：`false`
- 它在防什么：防止把鼠标键盘控制能力轻易扩展到远程机器。
- 普通建议：不清楚时别开。

#### `window_allowlist`

- 默认值：空
- 它在防什么：限制它只碰某些窗口或进程。
- 适合场景：您只允许它操作某个浏览器或某个专用程序。

#### `max_coordinate_x` / `max_coordinate_y`

- 默认值：未设置
- 它在防什么：限制鼠标点击的可活动范围。
- 适合场景：防止它乱点到屏幕别处。

## D. 密钥和敏感内容会不会泄露

这部分防的是“秘密是不是会被存得太裸、读出来、或者发出去”。

### `[secrets]`

#### `encrypt`

- 默认值：`true`
- 它在防什么：防止配置中的 secret 过于裸露地落在本地文件里。

什么时候几乎算必需：

- 您存了任何 API key、bot token、access token、secret
- 这台机器不是只有您能接触
- 您会做备份、同步、截图、远程协助

普通建议：

- 大多数人不要关
- 关掉不是“更简单”，而是“更容易明文存 secret”

### `[security.outbound_leak_guard]`

这是一层“消息发出去前，先看看里面有没有像密钥的东西”。

#### 为什么它重要

很多泄露不是因为配置文件被偷，而是因为机器人自己回复出去了。

比如：

- 工具输出里带了 token
- 报错里带了 secret
- 它把配置内容原样贴回聊天窗口

它防的就是这种“已经拿到了内容，又差点原样发出去”的场景。

#### `enabled`

- 默认值：`true`
- 它在防什么：防止敏感内容直接原样回复出去。
- 普通建议：保留开启。

#### `action`

- 默认值：`redact`

| 值 | 白话理解 | 适合场景 |
|---|---|---|
| `redact` | 遮掉敏感部分后继续发 | 个人使用，兼顾可用性 |
| `block` | 发现可疑内容就不发原文 | 更严格场景 |

#### `sensitivity`

- 默认值：`0.7`
- 它在防什么：控制这层检查有多敏感。
- 调高：更容易拦，也更容易误判
- 调低：更宽松，也更可能漏掉

### `[security.audit]`

这组是“记安全日志”。

它更多是在出事后帮助您回看，而不是直接挡住问题。

#### 结构化说明

| 配置 | 默认值 | 白话解释 |
|---|---|---|
| `enabled` | `true` | 是否记录审计日志 |
| `log_path` | `audit.log` | 日志写哪里 |
| `max_size_mb` | `100` | 多大开始轮换 |
| `sign_events` | `false` | 是否给日志加签，方便判断有没有被改过 |

普通建议：

- 个人使用也建议保留 `enabled = true`
- `sign_events` 更偏严肃审计场景，按需开启

## E. 偏进阶的保护

这部分不是大多数人第一天就要调的，但知道它们在干什么有帮助。

### `[security.syscall_anomaly]`

可以把它理解成“盯着底层动作有没有突然很怪”。

如果您只是日常使用，保留默认值通常就够了。

#### 结构化说明

| 配置 | 默认值 | 白话解释 |
|---|---|---|
| `enabled` | `true` | 开不开这层异常监测 |
| `strict_mode` | `false` | 更严格地把一些被拒绝动作也当异常 |
| `alert_on_unknown_syscall` | `true` | 没见过的底层动作要不要报警 |
| `max_denied_events_per_minute` | `5` | 每分钟最多容忍多少次“被拒绝”异常 |
| `max_total_events_per_minute` | `120` | 每分钟最多容忍多少条总事件 |
| `max_alerts_per_minute` | `30` | 每分钟最多报多少次警 |
| `alert_cooldown_secs` | `20` | 同样警报隔多久再报 |
| `log_path` | `syscall-anomalies.log` | 异常记到哪里 |
| `baseline_syscalls` | 内置名单 | 什么算“正常常见动作” |

普通建议：

- 不懂就别改 `baseline_syscalls`
- 只在您真的要调异常报警灵敏度时，再去动这些值

### `[security.perplexity_filter]`

这个名字比较绕，您可以把它理解成“先看看输入像不像恶意乱码或奇怪尾巴，再决定要不要送给模型”。

#### 结构化说明

| 配置 | 默认值 | 白话解释 |
|---|---|---|
| `enable_perplexity_filter` | `false` | 开不开这层额外输入过滤 |
| `perplexity_threshold` | `18.0` | 多怪才算可疑 |
| `suffix_window_chars` | `64` | 重点检查尾部多少字符 |
| `min_prompt_chars` | `32` | 太短就不查 |
| `symbol_ratio_threshold` | `0.20` | 符号比例多高更像异常 |

普通建议：

- 普通本机使用可以不急着开
- 如果您担心公开通道里有人乱塞恶意提示，可以考虑开启

## 三套最常见的安全配置思路

### 1. 只在自己电脑上用

适合：

- 只在本机终端里试用
- 全程自己盯着
- 不接外部平台

建议：

- `gateway.host = "127.0.0.1"`
- `gateway.allow_public_bind = false`
- `gateway.require_pairing = true`
- `security.url_access.block_private_ip = true`
- `secrets.encrypt = true`
- `security.otp.enabled = true`
- 如果开始让它做自动化动作，建议把 `security.estop.enabled = true`

### 2. 家里局域网里给自己手机或平板用

适合：

- 您明确想从同一 Wi‑Fi 下另一台设备访问

建议：

- 只有在明确需要时才开 `gateway.allow_public_bind = true`
- 保留 `gateway.require_pairing = true`
- 不要同时把任何通道允许名单也放成 `"*"`
- 保留 `security.otp.enabled = true`
- 很建议开启 `security.estop.enabled = true`

### 3. 接聊天平台长期运行

适合：

- Telegram、Discord、Slack、WhatsApp、GitHub webhook 等长期在线

建议：

- 每个通道都写明确允许名单
- 能设 `webhook_secret` / `signing_secret` / `app_secret` / `verify_token` 的都设上
- 保留 `security.otp.enabled = true`
- 把 `security.estop.enabled = true` 当成基础项
- 把 `security.url_access.enforce_domain_allowlist = true` 当成长期目标
- 对敏感场景，考虑 `security.outbound_leak_guard.action = "block"`
- 群聊里尽量不要让自然语言批准直接生效

## 最后再提醒一次

- `allowed_users = ["*"]` 适合临时排错，不适合长期上线。
- `allow_public_bind = true` 不是“网络更通畅”，而是“门开得更大了”。
- `secrets.encrypt = false` 不是“更简单”，而是“更容易把秘密明文落地”。
- `security.url_access.block_private_ip = false` 不是“更方便联网”，而是“更容易碰到您自己家里和公司里的设备”。
- `security.otp.enabled` 当前代码默认是 `true`。如果您在别处看到 `false`，请优先以代码和实际运行行为为准。
- `security.estop.enabled` 默认是 `false`，但一旦进入长期运行、接平台、可跑命令的场景，就很值得从“可选”升级成“基础配置”。

## 相关文档

- 中文配置参考：[config-reference.md](config-reference.md)
- 英文配置参考：[../../config-reference.md](../../config-reference.md)
- 英文 Channel 参考：[../../channels-reference.md](../../channels-reference.md)
- 英文安全文档入口：[../../security/README.md](../../security/README.md)
