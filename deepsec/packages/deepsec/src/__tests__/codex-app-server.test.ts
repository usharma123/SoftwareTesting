import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CodexAppServerClient } from "../explore/codex-app-server.js";

const FIXTURE = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures/fake-codex-app-server.mjs",
);

function client(): CodexAppServerClient {
  return new CodexAppServerClient({
    args: [FIXTURE],
    command: process.execPath,
    reasoningEffort: "high",
    sourceCodexHome: path.join(os.tmpdir(), "deepsec-no-codex-home"),
    timeoutMs: 5_000,
  });
}

describe("CodexAppServerClient", () => {
  it("lists models and verifies reasoning effort", async () => {
    await expect(client().assertModelAvailable("gpt-5.6-sol")).resolves.toBeUndefined();
    await expect(client().assertModelAvailable("missing-model")).rejects.toThrow(/unavailable/);
  });

  it("adapts a structured app-server turn into ModelClient output", async () => {
    const response = await client().complete({
      model: "gpt-5.6-sol",
      messages: [{ role: "user", content: "Return structured JSON." }],
      responseFormat: {
        type: "json_schema",
        name: "test",
        schema: { type: "object" },
      },
    });

    expect(JSON.parse(response.text)).toEqual({
      effort: "high",
      hasSchema: true,
      model: "gpt-5.6-sol",
    });
    expect(response.usage).toEqual({ inputTokens: 11, outputTokens: 10 });
  });

  it("rejects any app-server tool execution", async () => {
    await expect(
      client().complete({
        model: "gpt-5.6-sol",
        messages: [{ role: "user", content: "TRIGGER_TOOL" }],
      }),
    ).rejects.toThrow(/attempted disabled tools/);
  });
});
