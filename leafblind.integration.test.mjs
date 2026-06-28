// Integration test: simulate the pi extension lifecycle to verify
// the full redactMessage pipeline works end-to-end.
// All values are PURE FICTIONAL placeholders (fake/test).
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { redact } from "./index.ts";

const R = "[REDACTED]";

// ---------------------------------------------------------------------------
// Simulate the `context` event handler the same way the extension does.
// We can't import the default export directly (it takes an ExtensionAPI),
// but we CAN test redactMessage by duplicating the walk logic here and
// testing the same message shapes pi would produce.
// ---------------------------------------------------------------------------

function walkMessages(messages) {
  return messages.map((msg) => {
    if (!msg || typeof msg !== "object") return msg;

    // content array (user / assistant / toolResult)
    if (Array.isArray(msg.content)) {
      msg.content = msg.content.map((block) => {
        if (!block || typeof block !== "object") return block;
        if (block.type === "text" && typeof block.text === "string") {
          return { ...block, text: redact(block.text) };
        }
        if (block.type === "thinking" && typeof block.thinking === "string") {
          return { ...block, thinking: redact(block.thinking) };
        }
        if (block.type === "toolCall" && block.arguments) {
          try {
            const s = JSON.stringify(block.arguments);
            const r = redact(s);
            return { ...block, arguments: JSON.parse(r) };
          } catch {
            return block;
          }
        }
        // image blocks left untouched
        return block;
      });
      return msg;
    }

    // content as plain string
    if (typeof msg.content === "string") msg.content = redact(msg.content);

    // bashExecution
    if (typeof msg.command === "string") msg.command = redact(msg.command);
    if (typeof msg.output === "string") msg.output = redact(msg.output);

    // summaries
    if (typeof msg.summary === "string") msg.summary = redact(msg.summary);

    return msg;
  });
}

describe("integration: redactMessage walk (simulates context event)", () => {
  test("user text content: openai key redacted", () => {
    const messages = [
      {
        role: "user",
        content: [
          {
            type: "text",
            text: "Use this key: sk-fakeproject0000aaaa1111bbbb2222cccc", // pragma: allowlist secret
          },
        ],
      },
    ];
    const result = walkMessages(messages);
    assert.equal(result[0].content[0].text, `Use this key: ${R}`);
    assert.ok(
      !result[0].content[0].text.includes("sk-fake"),
      "openai key gone",
    );
  });

  test("assistant toolCall arguments: openai key in JSON string redacted", () => {
    const messages = [
      {
        role: "assistant",
        content: [
          {
            type: "toolCall",
            id: "call_1",
            name: "bash",
            arguments: {
              command: "export OPENAI_KEY=sk-fakeproject0000aaaa1111bbbb2222cccc", // pragma: allowlist secret
            },
          },
        ],
      },
    ];
    const result = walkMessages(messages);
    const args = result[0].content[0].arguments;
    assert.ok(
      !args.command.includes("sk-fake"),
      "openai key gone from command arg",
    );
    assert.ok(args.command.includes(R), "placeholder present");
  });

  test("bashExecution output: password in output redacted", () => {
    const messages = [
      {
        role: "user",
        content: [{ type: "text", text: "run a command" }],
      },
      {
        output: "export TOKEN=sk-fakeproject0000aaaa1111bbbb2222cccc\nDone.", // pragma: allowlist secret
        command: "export TOKEN=sk-fakeproject0000aaaa1111bbbb2222cccc", // pragma: allowlist secret
      },
    ];
    const result = walkMessages(messages);
    assert.ok(
      !result[1].output.includes("sk-fake"),
      "output redacted",
    );
    assert.ok(
      !result[1].command.includes("sk-fake"),
      "command redacted",
    );
  });

  test("custom message content (string): bearer token redacted", () => {
    const messages = [
      {
        role: "user",
        content: "Authorization: Bearer fakefakefakefakefakefakefake0000", // pragma: allowlist secret
      },
    ];
    const result = walkMessages(messages);
    assert.ok(result[0].content.includes(R), "bearer redacted");
    assert.ok(!result[0].content.includes("fakefake"), "token value gone");
  });

  test("compaction summary: secret in summary redacted", () => {
    const messages = [
      {
        summary:
          "The user configured AWS_KEY=AKIATESTFAKE00000ABC for deployment.", // pragma: allowlist secret
      },
    ];
    const result = walkMessages(messages);
    assert.ok(!result[0].summary.includes("AKIA"), "aws key gone from summary");
    assert.ok(result[0].summary.includes(R), "placeholder present");
  });

  test("image block left untouched for multimodal", () => {
    const messages = [
      {
        role: "user",
        content: [
          { type: "image", source: { type: "base64", data: "FAKEBASE64==" } },
          { type: "text", text: "describe this image, api key is sk-fakeproject0000aaaa1111bbbb2222cccc" }, // pragma: allowlist secret
        ],
      },
    ];
    const result = walkMessages(messages);
    // image block should remain as-is
    assert.equal(result[0].content[0].type, "image");
    assert.equal(result[0].content[0].source.data, "FAKEBASE64==");
    // text block should be redacted
    assert.ok(result[0].content[1].text.includes(R));
    assert.ok(!result[0].content[1].text.includes("sk-fake"));
  });

  test("multiple message types in sequence", () => {
    const messages = [
      {
        role: "user",
        content: "my token: ghp_fakefakefakefakefakefakefakefakefake", // 36  # pragma: allowlist secret
      },
      {
        role: "assistant",
        content: [{ type: "text", text: "OK, using ghp_fakefakefakefakefakefakefakefakefake" }], // pragma: allowlist secret
      },
      {
        role: "user",
        content: [{ type: "text", text: "also set password=secret123456" }], // pragma: allowlist secret
      },
    ];
    const result = walkMessages(messages);
    // All secret values gone
    const full = JSON.stringify(result);
    assert.ok(!full.includes("ghp_fake"), "github token gone");
    assert.ok(!full.includes("secret123456"), "password gone");
  });
});

describe("integration: pre-filter short-circuit", () => {
  test("message with no secret markers passes through unchanged", () => {
    const messages = [
      {
        role: "user",
        content: [
          { type: "text", text: "what is the capital of France?" },
        ],
      },
    ];
    const result = walkMessages(messages);
    assert.deepStrictEqual(result, messages);
  });
});
