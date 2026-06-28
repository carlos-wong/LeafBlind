# leafblind

> **Blinded by a leaf.** — 一叶障目，不见泰山。

pi-agent 扩展：在所有 LLM API 请求发出前，用正则擦除 access token / 密码 / 私钥 / 环境变量值，保留变量名。

专为 [pi-agent](https://github.com/earendil-works/pi-coding-agent) 设计，已在 0.80.2 及以上版本测试通过。

**设计假设：** LLM agent 只需要知道*哪些*环境变量被设置了，不需要知道
它们的真实值。本扩展确保值永远不会到达模型，同时保留变量名和声明语法，
让 agent 仍能推理环境配置。

[English](README.md)

## 效果展示

**未安装 leafblind** — LLM 看到并复述了原始凭据：

![未安装](assets/screenshot-original.png)

**安装 leafblind 后** — 值被替换为 `[REDACTED]`，变量名保留：

![安装后](assets/screenshot-blinded.png)

---

## 安装

在 pi 的 `settings.json` 加 `extensions` 指向你克隆本仓库的路径：

```json
{
  "extensions": ["<本仓库克隆路径>"]
}
```

或把本目录 symlink/复制到 `~/.pi/agent/extensions/leafblind/`（pi 自动发现
`extensions/*/index.ts`）。

## 机制

- 拦截 `context` 事件（模型无关，每轮 LLM 调用前触发，位于
  `convertToLlm` 之前）。
- 拦截 `before_provider_request` 事件，捕获流式 provider 中的工具返回结果。
- `redact()` 是确定性纯函数：相同输入 → 相同输出，占位符固定
  `[REDACTED]`，不破坏 prompt cache prefix。
- **语法驱动全擦**：凡环境变量声明，值一律替换为 `[REDACTED]`，保留变量
  名与 `export`/`declare`/`set` 等关键字（不靠变量名判断敏感性）。
- 保留变量名：`export VAR=sk-xxx` → `export VAR=[REDACTED]`。
- 已知 token 格式（AWS/OpenAI/GitHub/Slack/JWT/Bearer）和 PEM 私钥整体替换。
- 命令参数（`--opt=val`）、JSON 键、函数参数（`func(arg=val)`）不属于
  声明，不擦。
- 多行 PEM 私钥整体替换。
- 邮箱 / 手机号 / 普通 PII 不命中。

## 命中范围

### 环境变量声明语法（值擦除，变量名保留）

| 语法 | 示例 |
|------|------|
| `export VAR=val` | `export PASS_ZTE=xxx` |
| 裸 `VAR=val`（行首 / ; & 后） | `PASS_ZTE=xxx` |
| `VAR: val`（YAML / 冒号） | `wifi_pass: xxx` |
| `declare -x VAR=val` | `declare -x SECRET=xxx` |
| `env VAR=val cmd` | `env API_KEY=xxx cmd` |
| `set VAR=val`（Windows） | `set DB_PASS=xxx` |
| `$env:VAR = "val"`（PowerShell） | `$env:TOKEN = "xxx"` |
| `set -x VAR val`（fish） | `set -x MY_PWD xxx` |
| `os.environ["VAR"] = "val"`（Python） | `os.environ["PSK"] = "xxx"` |

### Token 格式（整体替换）

已知 token 格式（包括 AWS access key、OpenAI key、GitHub token、
Slack token、JWT、Bearer token 及 PEM 私钥块）通过正则匹配后整体替换为
`[REDACTED]`。

## 性能

1MB 文本过滤 ≤ 50ms（实测 8ms 含 50 secret / 4ms 无 secret）。

## 测试

```bash
node --experimental-strip-types --test leafblind.test.mjs
node --experimental-strip-types --test leafblind.integration.test.mjs
```

73 条用例，全部使用纯虚构占位值（fake/test 标记），无真实 secret。
