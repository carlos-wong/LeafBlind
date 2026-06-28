// zz-secret-filter tests — all values are PURE FICTIONAL placeholders
// (marked with fake/test/EXAMPLE). No real keys/passwords/private keys.
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { redact } from "./index.ts";

const R = "[REDACTED]";

describe("REQ-004 secret types hit (8/8)", () => {
	test("AWS access key (AKIA+16)", () => {
		const s = "AWS_KEY=AKIATESTFAKE00000ABC"; // 16 chars after AKIA, fictional  # pragma: allowlist secret
		const out = redact(s);
		assert.equal(out, `AWS_KEY=${R}`);
		assert.ok(out.includes("AWS_KEY"), "var name preserved");
	});
	test("OpenAI key (sk-+20)", () => {
		const s = "openai=sk-fakeproject0000aaaa1111bbbb2222cccc"; // fictional
		assert.equal(redact(s), `openai=${R}`);
	});
	test("GitHub token ghp_ (36+)", () => {
		const s = "gh=ghp_fakefakefakefakefakefakefakefakefake"; // 36 fictional  # pragma: allowlist secret
		assert.equal(redact(s), `gh=${R}`);
	});
	test("GitHub OAuth gho_ (36+)", () => {
		const s = "gho_fakefakefakefakefakefakefakefakefake";
		assert.equal(redact(s), R);
	});
	test("Slack token xoxb-", () => {
		const s = "slack=xoxb-fakefakefakefakefakefakefakefakefake";
		assert.equal(redact(s), `slack=${R}`);
	});
	test("JWT (eyJ three segments)", () => {
		const s = "jwt=eyJfakefakefake.eyJfakefakefake.fakefakefake"; // fictional
		assert.equal(redact(s), `jwt=${R}`);
	});
	test("password assignment", () => {
		const s = "my_password=fakepassword123";
		assert.equal(redact(s), `my_password=${R}`);
		assert.ok(redact(s).includes("my_password="), "var name kept");
	});
	test("Bearer token", () => {
		const s = "Authorization: Bearer fakefakefakefakefakefakefake0000"; // 32 fictional
		const out = redact(s);
		assert.ok(out.includes(R), "redacted");
		assert.ok(!out.includes("fakefake"), "value gone");
	});
});

describe("REQ-004 multi-line PEM private key (REQ-007)", () => {
	test("single PEM block replaced as whole", () => {
		const s = "header\n-----BEGIN RSA PRIVATE KEY-----\nFAKEFAKEFAKE\nmorefakebase64\n-----END RSA PRIVATE KEY-----\ntrailer"; // pragma: allowlist secret
		const out = redact(s);
		assert.equal(out, `header\n${R}\ntrailer`);
		assert.ok(!out.includes("FAKEFAKE"), "key body gone");
	});
	test("multiple consecutive PEM blocks each replaced", () => {
		const block = "-----BEGIN PRIVATE KEY-----\nFAKE1\n-----END PRIVATE KEY-----"; // pragma: allowlist secret
		const s = `${block} middle ${block}`;
		const out = redact(s);
		assert.equal(out, `${R} middle ${R}`);
	});
	test("BEGIN without END -> not matched", () => {
		const s = "-----BEGIN PRIVATE KEY-----\nFAKE no end here"; // pragma: allowlist secret
		assert.equal(redact(s), s, "incomplete block must not be redacted");
	});
});

describe("REQ-004 syntax-driven: bare assignments redacted (was non-sensitive)", () => {
	// Strategy changed: ANY declaration has its value redacted regardless of
	// the variable name. These used to assert "not hit"; now they assert the
	// value is redacted while the var name is preserved.
	test("contact=user@example.com -> value redacted", () => {
		const s = "contact=user@example.com";
		assert.equal(redact(s), `contact=${R}`);
	});
	test("phone=13800138000 -> value redacted", () => {
		const s = "phone=13800138000";
		assert.equal(redact(s), `phone=${R}`);
	});
	test("normal_var=hello world -> value (up to space) redacted", () => {
		const s = "normal_var=hello world";
		assert.equal(redact(s), `normal_var=${R} world`);
	});
	test("api_key_name=my-service -> value redacted", () => {
		const s = "api_key_name=my-service";
		assert.equal(redact(s), `api_key_name=${R}`);
	});
});

describe("REQ-006 variable name preserved", () => {
	test("export VAR=value keeps VAR name", () => {
		const s = "export CARLOS_NEWAPI_KEY=sk-fakeproject0000aaaa1111bbbb2222cccc";
		const out = redact(s);
		assert.ok(out.startsWith("export CARLOS_NEWAPI_KEY="), "prefix + var name kept");
		assert.ok(out.endsWith(R), "value replaced");
		assert.ok(!out.includes("sk-fake"));
	});
	test("colon-separated keeps name", () => {
		const s = 'password: "fakepassword456"';
		const out = redact(s);
		assert.ok(out.includes("password:"), "name kept");
		assert.ok(out.includes(R));
	});
});

describe("REQ-003 determinism (pure function)", () => {
	test("same input twice -> byte-identical output", () => {
		const s = "a=sk-fakeproject0000aaaa1111bbbb2222cccc b=AKIATESTFAKE00000AB"; // pragma: allowlist secret
		assert.equal(redact(s), redact(s));
	});
	test("placeholder is literal, no timestamp/random", () => {
		const out = redact("x=sk-fakeproject0000aaaa1111bbbb2222cccc");
		assert.ok(out.includes("[REDACTED]"));
		assert.ok(!/\d{10}/.test(out), "no timestamp-like digits in placeholder");
	});
	test("same secret appears twice -> both replaced identically", () => {
		const k = "sk-fakeproject0000aaaa1111bbbb2222cccc";
		const out = redact(`a=${k} b=${k}`);
		assert.equal(out, `a=${R} b=${R}`);
	});
});

describe("REQ-008 performance (<=50ms for 1MB)", () => {
	test("1MB text with ~50 fictional secrets < 50ms", () => {
		// build ~1MB text (≈ 1MB total)
		const line = "normal line of text for padding "; // 30 chars
		const secret = "k=sk-fakeproject0000aaaa1111bbbb2222cccc";
		let big = "";
		// ~33000 lines * 30 = ~1MB
		for (let i = 0; i < 33000; i++) big += line + "\n";
		for (let i = 0; i < 50; i++) big += secret + "\n";
		assert.ok(big.length > 900_000 && big.length < 1_200_000, `size ~1MB, got ${big.length}`);
		const t0 = process.hrtime.bigint();
		redact(big);
		const ms = Number(process.hrtime.bigint() - t0) / 1e6;
		assert.ok(ms <= 50, `took ${ms.toFixed(2)}ms, must be <= 50ms`);
	});
	test("1MB text with no secrets still fast", () => {
		const line = "normal line of text for padding ";
		let big = "";
		for (let i = 0; i < 33000; i++) big += line + "\n";
		assert.ok(big.length > 900_000, `~1MB, got ${big.length}`);
		const t0 = process.hrtime.bigint();
		redact(big);
		const ms = Number(process.hrtime.bigint() - t0) / 1e6;
		assert.ok(ms <= 50, `no-secret scan took ${ms.toFixed(2)}ms, must be <= 50ms`);
	});
});

describe("boundary / edge cases", () => {
	test("empty string returns empty", () => {
		assert.equal(redact(""), "");
	});
	test("short sk- (under 20) not matched", () => {
		assert.equal(redact("sk-short123"), "sk-short123");
	});
	test("AKIA with <16 trailing not matched", () => {
		assert.equal(redact("AKIASHORT12345"), "AKIASHORT12345"); // 11 trailing < 16
	});
	test("ghp_ with <36 not matched", () => {
		assert.equal(redact("ghp_shortvalue"), "ghp_shortvalue");
	});
	test("image blocks are left untouched", () => {
		// redact() only handles strings; image blocks pass through unchanged
		// so multimodal models still receive them
		assert.equal(redact("plain"), "plain");
	});
});

describe("REQ-001 GitHub token expanded prefixes (7/7)", () => {
	test("ghs_ token redacted", () => {
		const s = "ghs_fakefakefakefakefakefakefakefakefakefakefake"; // 36 fictional  # pragma: allowlist secret
		assert.equal(redact(s), R);
	});
	test("ghr_ token redacted", () => {
		const s = "ghr_fakefakefakefakefakefakefakefakefakefakefake"; // pragma: allowlist secret
		assert.equal(redact(s), R);
	});
	test("ghu_ token redacted", () => {
		const s = "ghu_fakefakefakefakefakefakefakefakefakefakefake"; // pragma: allowlist secret
		assert.equal(redact(s), R);
	});
	test("ghc_ token redacted", () => {
		const s = "ghc_fakefakefakefakefakefakefakefakefakefakefake"; // pragma: allowlist secret
		assert.equal(redact(s), R);
	});
	test("gha_ token redacted", () => {
		const s = "gha_fakefakefakefakefakefakefakefakefakefakefake"; // pragma: allowlist secret
		assert.equal(redact(s), R);
	});
	test("ghs_ with <36 not matched", () => {
		assert.equal(redact("ghs_short"), "ghs_short");
	});
	test("gha_ with <36 not matched", () => {
		assert.equal(redact("gha_tooshortvalue"), "gha_tooshortvalue");
	});
});

describe("REQ-002 password semicolon preserved", () => {
	test("password=abcdef; keeps semicolon", () => {
		const s = "password=abcdef;";
		const out = redact(s);
		assert.equal(out, `password=${R};`);
		assert.ok(out.endsWith(";"), "semicolon preserved after placeholder");
	});
	test("passwd=value; keeps semicolon", () => {
		const s = "passwd=testval;";
		const out = redact(s);
		assert.equal(out, `passwd=${R};`);
	});
	test("password= (empty value) not matched", () => {
		assert.equal(redact("password="), "password=");
	});
	test('password="abcdef"; keeps semicolon outside quote', () => {
		const s = 'password="abcdef";';
		const out = redact(s);
		assert.equal(out, `password="${R}";`);
	});
});

describe("REQ-003 Bearer token anchored", () => {
	test("prefixBearer ... should not match", () => {
		const s = "prefixBearer fakefakefakefakefakefakefake0000";
		assert.equal(redact(s), s, "Bearer inside a word must not trigger");
	});
	test("Authorization: Bearer ... still matched", () => {
		const s = "Authorization: Bearer fakefakefakefakefakefakefake0000";
		const out = redact(s);
		assert.ok(out.includes(R), "standard header still redacted");
		assert.ok(!out.includes("fakefake"), "value gone");
	});
});

describe("e2e: experiment prompts (pi -p -e ...)", () => {
	// These are the exact prompts used in the live pi-agent experiment.
	// The redact() output matches what the LLM actually received (confirmed
	// via agent response and stderr debug log).

	test("experiment 1: agent cannot repeat the fake key", () => {
		const prompt = "请完整复述我给你发了什么内容，不要遗漏。我的 OpenAI key 是 sk-fakeproject0000aaaa1111bbbb2222cccc"; // pragma: allowlist secret
		const out = redact(prompt);
		// key replaced but surrounding text intact
		assert.ok(out.includes("请完整复述我给你发了什么内容"), "prefix preserved");
		assert.ok(out.includes("不要遗漏"), "middle preserved");
		assert.ok(!out.includes("sk-fakeproject"), "openai key gone");
		assert.ok(out.includes(R), "placeholder present");
		// verify exact: the agent saw this exact string
		assert.equal(
			out,
			`请完整复述我给你发了什么内容，不要遗漏。我的 OpenAI key 是 ${R}`,
		);
	});

	test("experiment 2: agent reports [REDACTED] as literal value", () => {
		const prompt = "我的 OpenAI key 是 sk-fakeproject0000aaaa1111bbbb2222cccc。请告诉我，你看到我的 key 的值是什么？不要猜，直接输出你看到的字面值。"; // pragma: allowlist secret
		const out = redact(prompt);
		assert.ok(!out.includes("sk-fakeproject"), "openai key gone");
		assert.ok(out.includes(R), "placeholder present");
		assert.ok(out.includes("不要猜"), "trailing text preserved");
		assert.equal(
			out,
			`我的 OpenAI key 是 ${R}。请告诉我，你看到我的 key 的值是什么？不要猜，直接输出你看到的字面值。`,
		);
	});

	// Manual e2e run (requires API key):
	//   mkdir -p /tmp/pi-secret-test && cd /tmp/pi-secret-test
	//   pi -p -nc -ne -e ~/Projects/zz-secret-filter \
	//     "我的 OpenAI key 是 sk-fakeproject0000aaaa1111bbbb2222cccc。" \
	//     "请告诉我，你看到我的 key 的值是什么？"
	// Expected: agent outputs [REDACTED], cannot repeat the fake key.
});

describe("REQ-002 env declaration syntaxes (9/9) — value redacted, var name kept", () => {
	// All values fictional (fake/test/EXAMPLE).
	test("1. export VAR=val (bare value)", () => {
		assert.equal(redact("export PASS_ZTE=FAKEpass0001"), `export PASS_ZTE=${R}`); // pragma: allowlist secret
	});
	test("1b. export VAR preserves keyword", () => {
		const out = redact("export PATH=/usr/local/bin:/usr/bin");
		assert.ok(out.startsWith("export PATH="), "export + var name kept");
		assert.ok(!out.includes("/usr/local"), "value gone");
	});
	test("2. bare VAR=val (line start)", () => {
		assert.equal(redact("PASS_ZTE=FAKEpass0001"), `PASS_ZTE=${R}`); // pragma: allowlist secret
	});
	test("3. VAR: val (YAML/colon)", () => {
		assert.equal(redact("wifi_pass: FAKEpass0001"), `wifi_pass: ${R}`); // pragma: allowlist secret
	});
	test("3b. VAR: \"val\" (YAML quoted)", () => {
		assert.equal(redact('token: "fakefakefakefake"'), `token: ${R}`);
	});
	test("4. declare -x VAR=val", () => {
		const out = redact('declare -x MY_SECRET="fakepw123456"');
		assert.ok(out.startsWith('declare -x MY_SECRET='), "declare + var kept");
		assert.ok(!out.includes("fakepw123456"), "value gone");
	});
	test("5. env VAR=val cmd (prefix)", () => {
		assert.equal(redact("env API_KEY=fakekey123456 python app.py"), `env API_KEY=${R} python app.py`);
	});
	test("6. set VAR=val (Windows)", () => {
		assert.equal(redact("set DB_PASS=fakepass789"), `set DB_PASS=${R}`);
	});
	test("7. $env:VAR = \"val\" (PowerShell)", () => {
		assert.equal(redact('$env:TOKEN = "fakefakefake123"'), `$env:TOKEN = "${R}"`);
	});
	test("8. set -x VAR val (fish)", () => {
		assert.equal(redact("set -x MY_PWD fakepwd999"), `set -x MY_PWD ${R}`);
	});
	test("9. os.environ[\"VAR\"] = \"val\" (Python)", () => {
		assert.equal(redact('os.environ["PSK"] = "fakefakefake"'), `os.environ["PSK"] = "${R}"`);
	});
	test("quote variant: export VAR='val' (single quote)", () => {
		assert.equal(redact("export SECRET='fakefake123'"), `export SECRET='${R}'`);
	});
	test("quote variant: export VAR=\"val\" (double quote)", () => {
		assert.equal(redact('export SECRET="fakefake123"'), `export SECRET="${R}"`);
	});
});

describe("REQ-003 non-declaration contexts NOT redacted", () => {
	test("git --author=Carlos not redacted", () => {
		const s = "git log --author=Carlos";
		assert.equal(redact(s), s);
	});
	test("JSON {\"name\": \"Carlos\"} not redacted", () => {
		const s = '{"name": "Carlos", "version": "1.0"}';
		assert.equal(redact(s), s);
	});
	test("func(arg=value, opt=2) not redacted", () => {
		const s = "func(arg=value, opt=2)";
		assert.equal(redact(s), s);
	});
	test("python -c \"print(1)\" not redacted", () => {
		const s = 'python -c "print(1)"';
		assert.equal(redact(s), s);
	});
	test("inline cmd --flag=val not redacted", () => {
		const s = "curl --data=name=Carlos http://x";
		// --data=name=Carlos : "name" preceded by =, not a declaration
		assert.equal(redact(s), s);
	});
});

const walkPayload = await import("./index.ts").then(m => m.walkPayload);
const R2 = "[REDACTED]";

describe("REQ-002 before_provider_request payload walk", () => {
	test("OpenAI format: message.content string is redacted", () => {
		const payload = {
			model: "test-model",
			messages: [
				{ role: "user", content: "export PASS_ZTE=FAKEpass0001" },
				{ role: "assistant", content: "OK" },
				{ role: "tool", tool_call_id: "call_1", content: "export PASS_ZTE=FAKEpass0001\n" },
			],
		};
		const out = walkPayload(payload);
		// user message redacted
		assert.equal(out.messages[0].content, `export PASS_ZTE=${R2}`);
		// assistant unchanged
		assert.equal(out.messages[1].content, "OK");
		// tool result redacted
		assert.equal(out.messages[2].content, `export PASS_ZTE=${R2}\n`);
		// original not mutated
		assert.ok(payload.messages[0].content.includes("FAKEpass0001"), "original unmuted");
	});

	test("Anthropic format: content[].text is redacted", () => {
		const payload = {
			model: "claude-sonnet",
			messages: [
				{
					role: "user",
					content: [
						{ type: "text", text: "export PASS_ZTE=FAKEpass0001" },
					],
				},
				{
					role: "user",
					content: [
						{
							type: "tool_result",
							tool_use_id: "xxx",
							content: [
								{ type: "text", text: "export PASS_ZTE=FAKEpass0001\n" },
							],
						},
					],
				},
			],
		};
		const out = walkPayload(payload);
		assert.equal(out.messages[0].content[0].text, `export PASS_ZTE=${R2}`);
		assert.equal(out.messages[1].content[0].content[0].text, `export PASS_ZTE=${R2}\n`);
	});

	test("OpenAI format: read tool result with real file content is redacted", () => {
		// Simulate what pi sends for a read tool result
		const payload = {
			model: "glm-5.2",
			messages: [
				{ role: "user", content: "read this file" },
				{
					role: "tool",
					tool_call_id: "call_read_1",
					content: "export PASS_ZTE=FAKEpass0001\n",
				},
			],
		};
		const out = walkPayload(payload);
		assert.equal(out.messages[1].content, `export PASS_ZTE=${R2}\n`);
		assert.ok(!out.messages[1].content.includes("FAKEpass0001"), "value gone");
	});

	test("nested objects with text key deep in structure", () => {
		const payload = {
			request: {
				body: {
					text: "export PASS_ZTE=FAKEpass0001",
				},
			},
		};
		const out = walkPayload(payload);
		assert.equal(out.request.body.text, `export PASS_ZTE=${R2}`);
	});

	test("string values at non-content/text keys are left alone", () => {
		const payload = {
			model: "deepseek-v4",
			messages: [{ role: "user", content: "normal text" }],
		};
		const out = walkPayload(payload);
		assert.equal(out.model, "deepseek-v4");
		assert.equal(out.messages[0].content, "normal text");
	});
});
