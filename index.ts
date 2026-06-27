/**
 * zz-secret-filter — redact access tokens / passwords / private keys before
 * they reach the LLM API. Hooks the `context` event (model-agnostic, fires
 * before convertToLlm on every LLM call) and runs deterministic regex
 * redaction over all text content in AgentMessage[].
 *
 * - redact() is a pure function: same input -> same output, placeholder is
 *   the fixed literal "[REDACTED]" (no timestamps/random) so prompt cache
 *   prefix stays stable across turns.
 * - Variable names are preserved; only the secret value is replaced.
 * - Multi-line PEM private key blocks are matched as a whole.
 * - Email / phone / PII are intentionally NOT matched.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const PLACEHOLDER = "[REDACTED]";

// ---------------------------------------------------------------------------
// Regex set — known access-token formats + password assignments + PEM blocks.
// Deliberately narrow: email/phone/PII are NOT matched.
// ---------------------------------------------------------------------------
const SECRET_PATTERNS: RegExp[] = [
	// AWS access key id (AKIA + 16 uppercase alnum)
	/AKIA[0-9A-Z]{16}/g,
	// OpenAI key (sk- + 20+ alnum)
	/sk-[A-Za-z0-9]{20,}/g,
	// GitHub PAT / OAuth token (ghp_ / gho_ + 36 alnum)
	/gh[op]_[A-Za-z0-9]{36,}/g,
	// Slack token (xox[baprs]- + 10+ alnum/-)
	/xox[baprs]-[0-9a-zA-Z-]{10,}/g,
	// JWT (three base64url segments, each 10+, dot-separated, starts eyJ)
	/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
	// Bearer token (Bearer + 20+ token chars)
	/Bearer\s+[A-Za-z0-9._-]{20,}/g,
	// password / passwd assignment — keep var name, replace value.
	// group 1 = "name=" prefix (incl. optional quote), group 2 = value (6+ non-space/quote)
	/(\b\w*(?:password|passwd)\w*\s*[=:]\s*["']?)([^\s"']{6,})/gi,
	// Multi-line PEM private key block (BEGIN..END, non-greedy, requires END)
	/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----/g, // pragma: allowlist secret
];

/**
 * Redact secrets from a single text string. Pure function.
 * Value-preserving: for "name=secret" patterns, keeps "name=" prefix.
 */
// Fast pre-filter: skip 8-regex pass if text contains none of the secret
// markers. Scanning 1MB against 8 regexes is ~100ms; this single indexOf
// sweep is ~1ms and short-circuits the common (no-secret) case.
const MARKERS = [
	"AKIA", "sk-", "ghp_", "gho_", "xox", "eyJ", "Bearer",
	"password", "passwd", "PASSWORD", "PASSWD",
	"BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", // pragma: allowlist secret
	"BEGIN OPENSSH PRIVATE KEY", "BEGIN PGP PRIVATE KEY", // pragma: allowlist secret
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
	for (const re of SECRET_PATTERNS) {
		// password pattern has a capture group for the var-name prefix
		if (re.source.includes("password|passwd")) {
			out = out.replace(re, (_m, p1: string) => `${p1}${PLACEHOLDER}`);
		} else {
			out = out.replace(re, PLACEHOLDER);
		}
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

export default function (pi: ExtensionAPI): void {
	pi.on("context", async (event) => {
		if (!Array.isArray(event.messages)) return;
		const messages = event.messages.map((m: any) => redactMessage(m));
		return { messages };
	});
}
