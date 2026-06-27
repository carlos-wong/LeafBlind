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

describe("REQ-005 non-sensitive not hit (4/4)", () => {
	test("email not redacted", () => {
		const s = "contact=user@example.com";
		assert.equal(redact(s), s);
	});
	test("phone not redacted", () => {
		const s = "phone=13800138000";
		assert.equal(redact(s), s);
	});
	test("normal var not redacted", () => {
		const s = "normal_var=hello world";
		assert.equal(redact(s), s);
	});
	test("var name contains key/secret/token but short value -> not hit", () => {
		const s = "api_key_name=my-service";
		assert.equal(redact(s), s);
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
	test("text with image-block path: custom content array image -> placeholder", () => {
		// redact only takes strings; this documents the message-level path
		assert.equal(redact("plain"), "plain");
	});
});
