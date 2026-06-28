/**
 * leafblind — Blinded by a leaf.
 * Redact access tokens / passwords / env vars before they reach the LLM API.
 * Hooks the `context` event (model-agnostic, fires
 * before convertToLlm on every LLM call) and runs deterministic regex
 * redaction over all text content in AgentMessage[].
 *
 * Strategy (syntax-driven, redact-all-values):
 * - Any environment-variable declaration has its VALUE replaced with the
 *   fixed literal "[REDACTED]"; the variable name and declaration keyword
 *   (export/declare/set/...) are preserved so the agent still knows which
 *   variable was set. Sensitivity is NOT decided by the variable name.
 * - Known token formats (AWS/OpenAI/GitHub/Slack/JWT/Bearer) and PEM private
 *   key blocks are still matched anywhere as whole tokens.
 * - Command options (--opt=val), JSON keys, and function args are NOT
 *   declarations and are left untouched.
 * - redact() is a pure function: same input -> same output, placeholder is
 *   the fixed literal "[REDACTED]" (no timestamps/random) so prompt cache
 *   prefix stays stable across turns.
 * - ImageContent is left untouched so multimodal models still receive images.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const PLACEHOLDER = "[REDACTED]";

// ---------------------------------------------------------------------------
// Patterns. Each entry is { re, fn }; fn maps the match (plus capture groups)
// to its redacted replacement. Token patterns replace the whole match with
// PLACEHOLDER; assignment patterns rebuild the line keeping the var name.
// ---------------------------------------------------------------------------

// Prefix: variable must be at line start, after ; & , or right after a
// declaration keyword (export/declare/env/set). This is what separates a
// real declaration from a function argument (arg=) or a command option
// (--opt=) or a member access (obj.var=). Each keyword branch carries its
// own trailing whitespace so declare -x is consumed fully.
const PRE = "((?:export\\s+|declare\\s+(?:-\\w+\\s+)?|env\\s+|set\\s+|^|(?<=[\\n;&])))";

const SECRET_PATTERNS: { re: RegExp; fn: (...a: string[]) => string }[] = [
	// --- token formats (replace whole match) ---
	// AWS access key id (AKIA + 16 uppercase alnum)
	{ re: /AKIA[0-9A-Z]{16}/g, fn: () => PLACEHOLDER }, // pragma: allowlist secret
	// OpenAI key (sk- + 20+ alnum)
	{ re: /sk-[A-Za-z0-9]{20,}/g, fn: () => PLACEHOLDER }, // pragma: allowlist secret
	// GitHub token (gh[oprsuca]_ + 36+ alnum)
	{ re: /gh[oprsuca]_[A-Za-z0-9]{36,}/g, fn: () => PLACEHOLDER },
	// Slack token (xox[baprs]- + 10+ alnum/-)
	{ re: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, fn: () => PLACEHOLDER },
	// JWT (three base64url segments, each 10+, dot-separated, starts eyJ)
	{ re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, fn: () => PLACEHOLDER },
	// Bearer token (Bearer + 20+ token chars, anchored)
	{ re: /\bBearer\s+[A-Za-z0-9._-]{20,}\b/g, fn: () => PLACEHOLDER },
	// Multi-line PEM private key block (BEGIN..END, non-greedy, requires END)
	{ re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----/g, fn: () => PLACEHOLDER }, // pragma: allowlist secret

	// --- environment-variable declarations (keep var name + keyword, redact value) ---
	// Syntax 1: export/declare/env/set prefix OR line-start/after ;&, `=`, bare value.
	// Covers: export VAR=v / declare -x VAR=v / env VAR=v cmd / set VAR=v / VAR=v / VAR=v cmd
	{
		re: new RegExp(`${PRE}([A-Za-z_]\\w*)\\s*=\\s*([^;\\s"']+)`, "g"),
		fn: (_m, pre, v) => `${pre}${v}=${PLACEHOLDER}`,
	},
	// Syntax 2: same prefix, `=`, double-quoted value
	{
		re: new RegExp(`${PRE}([A-Za-z_]\\w*)\\s*=\\s*"([^"\\n]*)"`, "g"),
		fn: (_m, pre, v) => `${pre}${v}="${PLACEHOLDER}"`,
	},
	// Syntax 3: same prefix, `=`, single-quoted value
	{
		re: new RegExp(`${PRE}([A-Za-z_]\\w*)\\s*=\\s*'([^'\\n]*)'`, "g"),
		fn: (_m, pre, v) => `${pre}${v}='${PLACEHOLDER}'`,
	},
	// Syntax 4: YAML / colon assignment at line start: VAR: value (incl. quoted)
	{
		re: /^([A-Za-z_]\w*)\s*:\s+(.+)$/gm,
		fn: (_m, v) => `${v}: ${PLACEHOLDER}`,
	},
	// Syntax 5: PowerShell: $env:VAR = "value"
	{
		re: /(\$env:)([A-Za-z_]\w*)\s*=\s*"([^"\n]*)"/g,
		fn: (_m, p, v) => `${p}${v} = "${PLACEHOLDER}"`,
	},
	// Syntax 6: fish: set -x VAR value  (space-separated, no =)
	{
		re: /(set\s+-\w*x\w*\s+)([A-Za-z_]\w*)\s+(\S+)/g,
		fn: (_m, p, v) => `${p}${v} ${PLACEHOLDER}`,
	},
	// Syntax 7: Python: os.environ["VAR"] = "value"
	{
		re: /(os\.environ\[)(["'])([A-Za-z_]\w*)(["']\]\s*=\s*)(["'])([^"'\n]*)(["'])/g,
		fn: (_m, p, q1, v, mid, q2, _val, q3) => `${p}${q1}${v}${mid}${q2}${PLACEHOLDER}${q3}`,
	},
];

/**
 * Redact secrets from a single text string. Pure function.
 */
// Fast pre-filter: skip the regex pass if text contains none of the secret
// markers. Bare assignments carry `=`/`:`, so those are markers too; the
// 1MB performance-test padding has none of them and still short-circuits.
const MARKERS = [
	"AKIA", "sk-", "ghp_", "gho_", "ghs_", "ghr_", "ghu_", "ghc_", "gha_", "xox", "eyJ", "Bearer", // pragma: allowlist secret
	"BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", // pragma: allowlist secret
	"BEGIN OPENSSH PRIVATE KEY", "BEGIN PGP PRIVATE KEY", // pragma: allowlist secret
	"=", ":", "export", "declare", "set", "env", "os.environ", "$env",
];

function mightContainSecret(text: string): boolean {
	for (const m of MARKERS) {
		if (text.indexOf(m) !== -1) return true;
	}
	return false;
}

export function redact(text: string): string {
	if (!mightContainSecret(text)) return text;
	let out = text;
	for (const { re, fn } of SECRET_PATTERNS) {
		out = out.replace(re, fn as (...a: string[]) => string);
	}
	return out;
}

/**
 * Walk an AgentMessage's text-bearing fields and redact them in place.
 * Handles: user/assistant/toolResult content arrays (TextContent.text),
 * bashExecution.command/.output, custom.content (string or array),
 * compactionSummary.summary, branchSummary.summary.
 * ImageContent is left untouched so multimodal models still receive images.
 */
function redactMessage(msg: any): any {
	if (!msg || typeof msg !== "object") return msg;

	// content array (user / assistant / toolResult / custom-as-array)
	if (Array.isArray(msg.content)) {
		msg.content = msg.content.map((block: any) => {
			if (!block || typeof block !== "object") return block;
			if (block.type === "text" && typeof block.text === "string") {
				return { ...block, text: redact(block.text) };
			}
			if (block.type === "thinking" && typeof block.thinking === "string") {
				return { ...block, thinking: redact(block.thinking) };
			}
			// toolCall: stringify args, redact, keep structure
			if (block.type === "toolCall" && block.arguments) {
				try {
					const s = JSON.stringify(block.arguments);
					const r = redact(s);
					return { ...block, arguments: JSON.parse(r) };
				} catch {
					return block;
				}
			}
			return block;
		});
		return msg;
	}

	// content as plain string (custom message)
	if (typeof msg.content === "string") {
		msg.content = redact(msg.content);
	}

	// bashExecution
	if (typeof msg.command === "string") msg.command = redact(msg.command);
	if (typeof msg.output === "string") msg.output = redact(msg.output);

	// summaries
	if (typeof msg.summary === "string") msg.summary = redact(msg.summary);

	return msg;
}

// Walk a provider payload and redact text content on "content" or "text" keys.
// This is used by both the `context` and `before_provider_request` handlers
// to catch tool-result messages that may not trigger a separate `context` event.
export function walkPayload(obj: any): any {
	if (!obj || typeof obj !== "object") return obj;
	if (Array.isArray(obj)) return obj.map(walkPayload);
	const r: any = {};
	for (const k of Object.keys(obj)) {
		const v = obj[k];
		r[k] = (k === "content" && typeof v === "string") ? redact(v)
			: (k === "text" && typeof v === "string") ? redact(v)
			: walkPayload(v);
	}
	return r;
}

function activate(pi: ExtensionAPI): void {
	pi.on("context", async (event) => {
		writeFileSync("/tmp/pi-ctx-fire.log", "context_fired " + (event.messages?.length || 0) + " msgs " + new Date().toISOString() + "\n");
		if (!Array.isArray(event.messages)) return;
		const messages = event.messages.map((m: any) => redactMessage(m));
		return { messages };
	});

	// Also hook before_provider_request to catch tool results in streaming
	// providers where the LLM handles tool calls in a single API call and
	// the context event may not fire on intermediate tool-result messages.
	pi.on("before_provider_request", (event) => {
		if (!event.payload) return;
		const newPayload = walkPayload(event.payload);
		return newPayload;
	});
}
// Named exports (ESM) + CommonJS (pi's require() loader)
export default activate;
if (typeof module !== "undefined") {
	module.exports = activate;
	module.exports.redact = redact;
	module.exports.walkPayload = walkPayload;
}
