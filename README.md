# leafblind

> **Blinded by a leaf.** — 一叶障目，不见泰山。

pi-agent 扩展：在所有 LLM API 请求发出前，用正则擦除 access token / 密码 / 私钥 / 环境变量值，保留变量名。

## 安装

在 pi 的 `settings.json` 加 `extensionSources` 指向本目录：

```json
{
  "extensionSources": ["~/Projects/zz-secret-filter"]
}
```

或把本目录 symlink/复制到 `~/.pi/agent/extensions/zz-secret-filter/`（pi 自动发现 `extensions/*/index.ts`）。

## 机制

- 拦截 `context` 事件（模型无关，每轮 LLM 调用前触发，位于 convertToLlm 之前）
- `redact()` 是确定性纯函数：相同输入 → 相同输出，占位符固定 `[REDACTED]`，不破坏 prompt cache prefix
- **语法驱动全擦**：凡环境变量声明，值一律替换为 `[REDACTED]`，保留变量名与 `export`/`declare`/`set` 等关键字（不靠变量名判断敏感性）
- 保留变量名：`export VAR=sk-xxx` → `export VAR=[REDACTED]`；`export PASS_ZTE=FAKEpass0001` → `export PASS_ZTE=[REDACTED]`
- 已知 token 格式（AWS/OpenAI/GitHub/Slack/JWT/Bearer）和 PEM 私钥整体替换
- 命令参数（`--opt=val`）、JSON 键、函数参数（`func(arg=val)`）不属于声明，不擦
- 多行 PEM 私钥整体替换
- 邮箱 / 手机号 / 普通 PII 不命中

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

| 类型 | 正则 |
|------|------|
| AWS access key | `AKIA[0-9A-Z]{16}` | <!-- pragma: allowlist secret -->
| OpenAI key | `sk-[A-Za-z0-9]{20,}` | <!-- pragma: allowlist secret -->
| GitHub token | `gh[oprsuca]_[A-Za-z0-9]{36,}` | <!-- pragma: allowlist secret -->
| Slack token | `xox[baprs]-[0-9a-zA-Z-]{10,}` | <!-- pragma: allowlist secret -->
| JWT | `eyJ...三段` | <!-- pragma: allowlist secret -->
| Bearer token | `\bBearer\s+[A-Za-z0-9._-]{20,}\b` | <!-- pragma: allowlist secret -->
| PEM 私钥块 | `-----BEGIN ... PRIVATE KEY----- ... -----END...` |

## 性能

1MB 文本过滤 ≤ 50ms（实测 8ms 含 50 secret / 4ms 无 secret）。

## 测试

```bash
node --experimental-strip-types --test zz-secret-filter.test.mjs
```

60 条用例，全部使用纯虚构占位值（fake/test 标记），无真实 secret。
