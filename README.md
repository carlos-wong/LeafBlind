# leafblind

> **Blinded by a leaf.** — 一叶障目，不见泰山。

A pi-agent extension that redacts access tokens, passwords, private keys, and
environment variable values from all LLM API requests using deterministic regex
matching — while preserving variable names.

Designed for and tested on [pi-agent](https://github.com/earendil-works/pi-coding-agent).

---

- [English](#english)
- [中文](#中文)

---

## English

### Installation

Add `extensionSources` in pi's `settings.json` pointing to your clone of this
repo:

```json
{
  "extensionSources": ["<path-to-cloned-repo>"]
}
```

Or symlink/copy this directory into `~/.pi/agent/extensions/leafblind/` (pi
auto-discovers `extensions/*/index.ts`).

### Mechanism

- Hooks the `context` event (model-agnostic, fires before every LLM call,
  prior to `convertToLlm`).
- `redact()` is a deterministic pure function: same input → same output,
  fixed placeholder `[REDACTED]` — does not break prompt cache prefix.
- **Syntax-driven, redact-all-values**: every environment-variable
  declaration has its VALUE replaced with `[REDACTED]`; the variable name and
  declaration keyword (`export`/`declare`/`set`/etc.) are preserved.
  Sensitivity is NOT decided by the variable name.
- Variable name preserved: `export VAR=sk-xxx` → `export VAR=[REDACTED]`.
- Known token formats (AWS/OpenAI/GitHub/Slack/JWT/Bearer) and PEM private
  key blocks are replaced in their entirety.
- Command options (`--opt=val`), JSON keys, and function arguments
  (`func(arg=val)`) are NOT declarations and are left untouched.
- Multi-line PEM private key blocks are fully replaced.
- Email / phone numbers / general PII are NOT matched.

### Coverage

#### Environment Variable Declaration Syntaxes (value redacted, name kept)

| Syntax | Example |
|--------|---------|
| `export VAR=val` | `export PASS_ZTE=xxx` |
| Bare `VAR=val` (line start / after `;` `&`) | `PASS_ZTE=xxx` |
| `VAR: val` (YAML / colon) | `wifi_pass: xxx` |
| `declare -x VAR=val` | `declare -x SECRET=xxx` |
| `env VAR=val cmd` | `env API_KEY=xxx cmd` |
| `set VAR=val` (Windows) | `set DB_PASS=xxx` |
| `$env:VAR = "val"` (PowerShell) | `$env:TOKEN = "xxx"` |
| `set -x VAR val` (fish) | `set -x MY_PWD xxx` |
| `os.environ["VAR"] = "val"` (Python) | `os.environ["PSK"] = "xxx"` |

#### Token Formats (whole match replaced)

Known token formats — including AWS access keys, OpenAI keys, GitHub tokens,
Slack tokens, JWTs, Bearer tokens, and PEM private key blocks — are matched
via regex and replaced in their entirety with `[REDACTED]`.

### Performance

1 MB text filtering ≤ 50 ms (measured: 8 ms with 50 secrets / 4 ms
without secrets).

### Testing

```bash
node --experimental-strip-types --test leafblind.test.mjs
node --experimental-strip-types --test leafblind.integration.test.mjs
```

73 test cases, all using purely fictional placeholder values (marked
`fake`/`test`). No real secrets.

---

## 中文

pi-agent 扩展，专为 [pi-agent](https://github.com/earendil-works/pi-coding-agent) 设计，已在当前版本上测试通过。

### 安装

在 pi 的 `settings.json` 加 `extensionSources` 指向你克隆本仓库的路径：

```json
{
  "extensionSources": ["<本仓库克隆路径>"]
}
```

或把本目录 symlink/复制到 `~/.pi/agent/extensions/leafblind/`（pi 自动发现
`extensions/*/index.ts`）。

### 机制

- 拦截 `context` 事件（模型无关，每轮 LLM 调用前触发，位于
  `convertToLlm` 之前）。
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

### 命中范围

#### 环境变量声明语法（值擦除，变量名保留）

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

#### Token 格式（整体替换）

已知 token 格式（包括 AWS access key、OpenAI key、GitHub token、
Slack token、JWT、Bearer token 及 PEM 私钥块）通过正则匹配后整体替换为
`[REDACTED]`。

### 性能

1MB 文本过滤 ≤ 50ms（实测 8ms 含 50 secret / 4ms 无 secret）。

### 测试

```bash
node --experimental-strip-types --test leafblind.test.mjs
node --experimental-strip-types --test leafblind.integration.test.mjs
```

73 条用例，全部使用纯虚构占位值（fake/test 标记），无真实 secret。
