# 配置参考（简体中文）

这是中文配置参考的入口页，适合您快速查找：

- 某个配置区块大概是干什么的
- 默认值和风险边界应该看哪里
- 英文运行时合同文档与中文详解文档分别在哪

## 先看哪一份文档

根据目标，建议这样选：

| 您要做的事 | 建议先看 |
|---|---|
| 快速查某个配置键/默认值 | [../../config-reference.md](../../config-reference.md) |
| 想系统理解 `config.toml` 所有分区 | [config-toml-guide.md](config-toml-guide.md) |
| 想知道“改这个值到底会发生什么” | [security-config-guide.md](security-config-guide.md) |
| 想看 provider / channel 的专题配置 | [providers-reference.md](providers-reference.md) / [channels-reference.md](channels-reference.md) |

## 推荐阅读顺序

1. 先看 [config-toml-guide.md](config-toml-guide.md) 把全局地图过一遍
2. 再用 [../../config-reference.md](../../config-reference.md) 查精确默认值和运行时合同
3. 涉及安全边界时，再配合 [security-config-guide.md](security-config-guide.md)

## 常用入口

- `config.toml` 全量中文详解：[config-toml-guide.md](config-toml-guide.md)
- 安全配置白话指南：[security-config-guide.md](security-config-guide.md)
- 英文配置参考：[../../config-reference.md](../../config-reference.md)
- 中文文档入口：[README.md](README.md)

## 使用建议

- 配置键保持英文，避免本地化改写键名。
- 如果英文合同文档与中文说明出现不一致，以英文运行时合同为准。
- 想看机器可校验的完整结构，请运行 `zeroclaw config schema`。
