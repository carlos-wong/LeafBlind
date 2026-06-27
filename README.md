# zz-secret-filter

pi-agent 扩展：在所有 LLM API 请求发出前，用正则擦除 access token / 密码 / 私钥，保留变量名。

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
- 保留变量名：`export VAR=sk-xxx` → `export VAR=[REDACTED]`
- 多行 PEM 私钥整体替换
- 邮箱 / 手机号 / 普通 PII 不命中

## 命中范围

| 类型 | 正则 |
|------|------|
| AWS access key | `AKIA[0-9A-Z]{16}` |
| OpenAI key | `sk-[A-Za-z0-9]{20,}` |
| GitHub token | `gh[op]_[A-Za-z0-9]{36,}` |
| Slack token | `xox[baprs]-[0-9a-zA-Z-]{10,}` |
| JWT | `eyJ...三段` |
| Bearer token | `Bearer\s+[A-Za-z0-9._-]{20,}` |
| password 赋值 | 保留变量名，替换值 |
| PEM 私钥块 | `-----BEGIN ... PRIVATE KEY----- ... -----END...` |

## 性能

1MB 文本过滤 ≤ 50ms（实测 8ms 含 50 secret / 4ms 无 secret）。

## 配置

`settings.json` 可选：

```json
{ "secretFilter": { "enabled": false } }
```

设为 `false` 禁用（不卸载扩展）。

## 测试

```bash
node --experimental-strip-types --test zz-secret-filter.test.mjs
```

27 条用例，全部使用纯虚构占位值（fake/test 标记），无真实 secret。
