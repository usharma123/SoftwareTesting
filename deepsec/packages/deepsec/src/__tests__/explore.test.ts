import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensureProject, readFileRecord, reportJsonPath, writeFileRecord } from "@deepsec/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  exploreArtifactsCommand,
  exploreAttemptCommand,
  exploreAuditCommand,
  exploreBundleCommand,
  exploreCiCommand,
  exploreEvidenceCommand,
  exploreFindingsCommand,
  exploreListCommand,
  exploreManifestCommand,
  exploreStatusExitCode,
  exploreVerifyBundleCommand,
  exploreVerifyManifestCommand,
} from "../commands/explore.js";
import {
  parseExploreAction,
  parseValidationAction,
  runAgenticExploreLoop,
  validateBugReport,
} from "../explore/agent-loop.js";
import { BudgetedModelClient } from "../explore/budget.js";
import {
  assertSafeContainerCommand,
  redactCommandExecution,
  redactSensitiveText,
  sanitizeExploreEnv,
  truncateOutput,
} from "../explore/command-policy.js";
import { shouldCopyProjectPath, validateContainerInspectRuntime } from "../explore/docker.js";
import { writeExploreIntegrityManifest } from "../explore/integrity.js";
import { checkOpenRouterModelReachability } from "../explore/model-check.js";
import { OpenRouterResponsesClient } from "../explore/openrouter.js";
import {
  exploreRepairPrompt,
  exploreSystemPrompt,
  finalExploreTurnPrompt,
  finalValidationTurnPrompt,
  validationPrompt,
  validationRepairPrompt,
} from "../explore/prompts.js";
import {
  collectProductionFileSummaries,
  collectProductionFileSummariesFromRunner,
  normalizeRankings,
  parseContainerFileSummaries,
  parseRankingsFromText,
  selectTopRankedFiles,
} from "../explore/ranking.js";
import { mergeAcceptedExploreAttempt } from "../explore/records.js";
import {
  JSON_OBJECT_RESPONSE_FORMAT,
  RANKING_RESPONSE_FORMAT,
} from "../explore/response-formats.js";
import { summarizeExploreRun } from "../explore/status.js";
import { StubExploreModelClient } from "../explore/stub-model.js";
import type {
  BugReport,
  ContainerRunner,
  ExploreProgressEvent,
  ModelClient,
  RankedFile,
  SourceFileSummary,
} from "../explore/types.js";
import { collectWorkspaceChanges } from "../explore/workspace-changes.js";

const tempRoots: string[] = [];
const originalDataRoot = process.env.DEEPSEC_DATA_ROOT;
const originalFetch = globalThis.fetch;
const originalExitCode = process.exitCode;

afterEach(() => {
  process.env.DEEPSEC_DATA_ROOT = originalDataRoot;
  globalThis.fetch = originalFetch;
  process.exitCode = originalExitCode;
  vi.restoreAllMocks();
  for (const root of tempRoots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

describe("explore ranking", () => {
  const files: SourceFileSummary[] = [
    { filePath: "src/main/java/A.java", bytes: 10, heuristicScore: 2, preview: "class A {}" },
    {
      filePath: "src/main/java/Parser.java",
      bytes: 20,
      heuristicScore: 5,
      preview: "class Parser {}",
    },
    { filePath: "build.gradle", bytes: 5, heuristicScore: 1, preview: "plugins {}" },
  ];

  it("parses, normalizes, and selects top-N ranked files", () => {
    const parsed = parseRankingsFromText(`
      Here is the ranking:
      {"rankings":[
        {"filePath":"src/main/java/A.java","score":3,"reason":"logic"},
        {"filePath":"src/main/java/Parser.java","score":5,"reason":"parses raw messages"}
      ]}
    `);
    const normalized = normalizeRankings(files, parsed);
    expect(normalized).toEqual([
      { filePath: "src/main/java/Parser.java", score: 5, reason: "parses raw messages" },
      { filePath: "src/main/java/A.java", score: 3, reason: "logic" },
      {
        filePath: "build.gradle",
        score: 1,
        reason: "Model omitted this file; using local production-risk heuristic.",
      },
    ]);
    expect(selectTopRankedFiles(normalized, 2).map((r) => r.filePath)).toEqual([
      "src/main/java/Parser.java",
      "src/main/java/A.java",
    ]);
  });

  it("fails closed on malformed model ranking output", () => {
    expect(() =>
      parseRankingsFromText('{"rankings":[{"filePath":"A.java","score":9,"reason":"bad"}]}'),
    ).toThrow(/1 to 5/);
    expect(() => parseRankingsFromText("no json here")).toThrow(/JSON/);
  });

  it("keeps model-ranked files ahead of heuristic fallback files", () => {
    const normalized = normalizeRankings(files, [
      { filePath: "src/main/java/A.java", score: 4, reason: "model-selected" },
    ]);

    expect(selectTopRankedFiles(normalized, 2).map((r) => r.filePath)).toEqual([
      "src/main/java/A.java",
      "src/main/java/Parser.java",
    ]);
    expect(normalized[1]?.reason).toContain("local production-risk heuristic");
  });

  it("excludes generated files and package markers from ranking inventory", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-ranking-"));
    tempRoots.push(root);
    fs.mkdirSync(path.join(root, "src/generated/java/com/acme"), { recursive: true });
    fs.mkdirSync(path.join(root, "src/main/java/com/acme/parser"), { recursive: true });
    fs.writeFileSync(
      path.join(root, "src/generated/java/com/acme/SchemeConstantsA.java"),
      "class C {}",
    );
    fs.writeFileSync(
      path.join(root, "src/main/java/com/acme/parser/package-info.java"),
      "package x;",
    );
    fs.writeFileSync(
      path.join(root, "src/main/java/com/acme/parser/MessageParser.java"),
      "public class MessageParser { void parse(String raw) {} }",
    );

    expect(collectProductionFileSummaries(root).map((f) => f.filePath)).toEqual([
      "src/main/java/com/acme/parser/MessageParser.java",
    ]);
  });

  it("collects ranking inventory through a container runner", async () => {
    let requestedOutputLimit = 0;
    const runner: ContainerRunner = {
      async exec(_command: string, _timeoutMs?: number, outputLimit?: number) {
        requestedOutputLimit = outputLimit ?? 0;
        return {
          command: "inventory",
          exitCode: 0,
          durationMs: 10,
          stdout:
            "\x1esrc/main/java/com/acme/parser/MessageParser.java\n42\npublic class MessageParser { void parse(String raw) {} }\x1f\n" +
            "\x1esrc/test/java/com/acme/parser/MessageParserTest.java\n10\nclass Test {}\x1f\n",
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      },
    };

    const summaries = await collectProductionFileSummariesFromRunner(runner);

    expect(requestedOutputLimit).toBeGreaterThan(64_000);
    expect(summaries).toEqual([
      {
        filePath: "src/main/java/com/acme/parser/MessageParser.java",
        bytes: 42,
        heuristicScore: 5,
        preview: "public class MessageParser { void parse(String raw) {} }",
      },
    ]);
  });

  it("parses container inventory output deterministically", () => {
    const parsed = parseContainerFileSummaries(
      "\x1esrc/main/java/A.java\n10\nclass A {}\x1f\n\x1esrc/generated/java/B.java\n10\nclass B {}\x1f\n",
    );
    expect(parsed.map((f) => f.filePath)).toEqual(["src/main/java/A.java"]);
  });

  it("redacts secret-looking values from ranking previews", () => {
    const parsed = parseContainerFileSummaries(
      '\x1esrc/main/java/A.java\n80\nclass A { String key = "sk-or-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; }\x1f\n',
    );
    expect(parsed[0]?.preview).toContain("[REDACTED:openrouter-api-key]");
    expect(parsed[0]?.preview).not.toContain("sk-or-v1-aaaaaaaa");
  });
});

describe("explore runtime enforcement", () => {
  function hardenedInspect(overrides: Record<string, unknown> = {}) {
    return [
      {
        HostConfig: {
          Runtime: "runsc",
          NetworkMode: "none",
          ReadonlyRootfs: true,
          Privileged: false,
          SecurityOpt: ["no-new-privileges"],
          CapDrop: ["ALL"],
          PidsLimit: 512,
          Memory: 4_294_967_296,
          NanoCpus: 2_000_000_000,
          ...overrides,
        },
        Mounts: [
          { Destination: "/workspace/target" },
          { Destination: "/workspace/out" },
          { Destination: "/workspace/home" },
          { Destination: "/workspace/gradle-cache" },
        ],
      },
    ];
  }

  it("accepts only fully hardened runsc containers", () => {
    expect(validateContainerInspectRuntime(hardenedInspect())).toMatchObject({
      runtime: "runsc",
      networkMode: "none",
      readOnlyRootfs: true,
      noNewPrivileges: true,
      capDropAll: true,
      privileged: false,
      pidsLimit: 512,
      memoryBytes: 4_294_967_296,
      nanoCpus: 2_000_000_000,
      mountDestinations: [
        "/workspace/gradle-cache",
        "/workspace/home",
        "/workspace/out",
        "/workspace/target",
      ],
    });
    expect(() => validateContainerInspectRuntime(hardenedInspect({ Runtime: "runc" }))).toThrow(
      /runtime must be runsc/,
    );
    expect(() =>
      validateContainerInspectRuntime(hardenedInspect({ NetworkMode: "bridge" })),
    ).toThrow(/network must be none/);
    expect(() =>
      validateContainerInspectRuntime(hardenedInspect({ ReadonlyRootfs: false })),
    ).toThrow(/read-only/);
    expect(() => validateContainerInspectRuntime(hardenedInspect({ CapDrop: [] }))).toThrow(
      /drop all/,
    );
    expect(() =>
      validateContainerInspectRuntime([
        {
          ...hardenedInspect()[0],
          Mounts: [
            ...(hardenedInspect()[0]?.Mounts ?? []),
            { Destination: "/var/run/docker.sock" },
          ],
        },
      ]),
    ).toThrow(/Docker socket/);
  });
});

describe("explore source copy filtering", () => {
  it("excludes common credential files and dependency/build directories", () => {
    for (const rel of [
      ".env",
      ".env.local",
      "config/.env.production",
      ".ssh/id_rsa",
      ".aws/credentials",
      "deploy/private.pem",
      "deploy/signing.key",
      "certs/client.p12",
      "secret-token.txt",
      "service.credentials.json",
      "node_modules/pkg/index.js",
      "build/classes/Main.class",
      "target/classes/Main.class",
      ".git/config",
    ]) {
      expect(shouldCopyProjectPath(rel), rel).toBe(false);
    }
  });

  it("allows normal source files and build definitions", () => {
    for (const rel of [
      "",
      "src/main/java/com/acme/Parser.java",
      "src/main/resources/application.yml",
      "build.gradle",
      "settings.gradle",
      "README.md",
    ]) {
      expect(shouldCopyProjectPath(rel), rel).toBe(true);
    }
  });
});

describe("explore workspace change capture", () => {
  it("captures redacted source edits while ignoring generated build outputs", () => {
    const original = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-original-"));
    const target = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-target-"));
    tempRoots.push(original, target);
    fs.mkdirSync(path.join(original, "src/main/java/com/acme"), { recursive: true });
    fs.writeFileSync(path.join(original, "src/main/java/com/acme/Main.java"), "class Main {}\n");
    fs.writeFileSync(
      path.join(original, "src/main/java/com/acme/DeleteMe.java"),
      "class DeleteMe {}\n",
    );
    fs.cpSync(original, target, { recursive: true });
    fs.writeFileSync(
      path.join(target, "src/main/java/com/acme/Main.java"),
      'class Main { String key = "sk-or-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; }\n',
    );
    fs.writeFileSync(path.join(target, "src/main/java/com/acme/Added.java"), "class Added {}\n");
    fs.rmSync(path.join(target, "src/main/java/com/acme/DeleteMe.java"));
    fs.mkdirSync(path.join(target, "build/classes"), { recursive: true });
    fs.writeFileSync(path.join(target, "build/classes/Ignored.class"), "ignored");

    const changes = collectWorkspaceChanges(original, target);

    expect(changes.totalChanges).toBe(3);
    expect(changes.changes.map((change) => `${change.status}:${change.path}`).sort()).toEqual([
      "added:src/main/java/com/acme/Added.java",
      "deleted:src/main/java/com/acme/DeleteMe.java",
      "modified:src/main/java/com/acme/Main.java",
    ]);
    const modified = changes.changes.find((change) => change.status === "modified");
    expect(modified?.afterPreview).toContain("[REDACTED:openrouter-api-key]");
    expect(modified?.afterPreview).not.toContain("sk-or-v1-aaaaaaaa");
    expect(modified?.redacted).toBe(true);
  });
});

describe("explore OpenRouter client", () => {
  it("uses a tiny JSON-object request for live model reachability checks", async () => {
    let sentBody: Record<string, unknown> | undefined;
    globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
      sentBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(
        JSON.stringify({
          output_text: '{"ok":true}',
          usage: { input_tokens: 9, output_tokens: 3, cost: "0.001" },
        }),
        { status: 200 },
      );
    }) as typeof fetch;

    const client = new OpenRouterResponsesClient(
      "key",
      "https://openrouter.ai/api/v1",
      10_000,
      256,
    );
    const usage = await checkOpenRouterModelReachability({
      client,
      model: "anthropic/claude-opus-4.8",
    });

    expect(sentBody?.model).toBe("anthropic/claude-opus-4.8");
    expect(sentBody?.max_output_tokens).toBe(256);
    expect(sentBody?.response_format).toEqual({ type: "json_object" });
    expect(usage).toEqual({ inputTokens: 9, outputTokens: 3, costUsd: 0.001 });
  });

  it("rejects unexpected live model check output", async () => {
    const client: ModelClient = {
      async complete() {
        return { text: '{"ok":false}', raw: {} };
      },
    };

    await expect(
      checkOpenRouterModelReachability({ client, model: "anthropic/claude-opus-4.8" }),
    ).rejects.toThrow(/unexpected response/);
  });

  it("sends OpenRouter response_format for JSON schema requests", async () => {
    let sentBody: Record<string, unknown> | undefined;
    globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
      sentBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(JSON.stringify({ output_text: '{"rankings":[]}' }), { status: 200 });
    }) as typeof fetch;

    const client = new OpenRouterResponsesClient(
      "key",
      "https://openrouter.ai/api/v1",
      10_000,
      512,
    );
    await client.complete({
      model: "anthropic/claude-opus-4.8",
      messages: [{ role: "user", content: "rank" }],
      responseFormat: RANKING_RESPONSE_FORMAT,
    });

    expect(sentBody?.response_format).toEqual({
      type: "json_schema",
      json_schema: {
        name: "deepsec_file_rankings",
        strict: true,
        schema:
          RANKING_RESPONSE_FORMAT.type === "json_schema" ? RANKING_RESPONSE_FORMAT.schema : {},
      },
    });
  });

  it("sends OpenRouter JSON object mode for agent action requests", async () => {
    let sentBody: Record<string, unknown> | undefined;
    globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
      sentBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(JSON.stringify({ output_text: '{"action":"final"}' }), { status: 200 });
    }) as typeof fetch;

    const client = new OpenRouterResponsesClient(
      "key",
      "https://openrouter.ai/api/v1",
      10_000,
      512,
    );
    await client.complete({
      model: "anthropic/claude-opus-4.8",
      messages: [{ role: "user", content: "act" }],
      responseFormat: JSON_OBJECT_RESPONSE_FORMAT,
    });

    expect(sentBody?.response_format).toEqual({ type: "json_object" });
  });

  it("falls back without response_format when OpenRouter rejects structured outputs", async () => {
    const sentFormats: unknown[] = [];
    globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      sentFormats.push(body.response_format);
      if (sentFormats.length === 1) {
        return new Response(
          JSON.stringify({ error: { message: "response_format json_schema is unsupported" } }),
          { status: 400 },
        );
      }
      return new Response(JSON.stringify({ output_text: '{"ok":true}' }), { status: 200 });
    }) as typeof fetch;

    const client = new OpenRouterResponsesClient(
      "key",
      "https://openrouter.ai/api/v1",
      10_000,
      512,
    );
    const response = await client.complete({
      model: "anthropic/claude-opus-4.8",
      messages: [{ role: "user", content: "rank" }],
      responseFormat: RANKING_RESPONSE_FORMAT,
    });

    expect(response.text).toBe('{"ok":true}');
    expect(sentFormats[0]).toBeTruthy();
    expect(sentFormats[1]).toBeUndefined();
  });

  it("retries 402 credit reservation failures with the affordable output cap", async () => {
    const requestedCaps: number[] = [];
    globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      requestedCaps.push(body.max_output_tokens);
      if (requestedCaps.length === 1) {
        return new Response(
          JSON.stringify({
            error: {
              message:
                "This request requires more credits. You requested up to 4096 tokens, but can only afford 704.",
            },
          }),
          { status: 402 },
        );
      }
      return new Response(JSON.stringify({ output_text: '{"ok":true}' }), { status: 200 });
    }) as typeof fetch;

    const client = new OpenRouterResponsesClient(
      "key",
      "https://openrouter.ai/api/v1",
      10_000,
      4096,
    );
    const response = await client.complete({
      model: "anthropic/claude-opus-4.8",
      messages: [{ role: "user", content: "hi" }],
    });

    expect(response.text).toBe('{"ok":true}');
    expect(requestedCaps).toEqual([4096, 672]);
  });

  it("retries transient fetch termination", async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      if (calls === 1) throw new Error("terminated");
      return new Response(JSON.stringify({ output_text: "ok" }), { status: 200 });
    }) as typeof fetch;

    const client = new OpenRouterResponsesClient(
      "key",
      "https://openrouter.ai/api/v1",
      10_000,
      512,
    );
    const response = await client.complete({
      model: "anthropic/claude-opus-4.8",
      messages: [{ role: "user", content: "hi" }],
    });

    expect(response.text).toBe("ok");
    expect(calls).toBe(2);
  });

  it("extracts token and cost usage from Responses API results", async () => {
    globalThis.fetch = (async () => {
      return new Response(
        JSON.stringify({
          output_text: "ok",
          usage: {
            input_tokens: 123,
            output_tokens: 45,
            cost: "0.006789",
          },
        }),
        { status: 200 },
      );
    }) as typeof fetch;

    const client = new OpenRouterResponsesClient(
      "key",
      "https://openrouter.ai/api/v1",
      10_000,
      512,
    );
    const response = await client.complete({
      model: "anthropic/claude-opus-4.8",
      messages: [{ role: "user", content: "hi" }],
    });

    expect(response.usage).toEqual({
      inputTokens: 123,
      outputTokens: 45,
      costUsd: 0.006789,
    });
  });
});

describe("explore model budget", () => {
  it("allows the response that reaches the token cap and denies the next call", async () => {
    const inner: ModelClient = {
      async complete() {
        return {
          text: '{"ok":true}',
          raw: {},
          usage: { inputTokens: 7, outputTokens: 3 },
        };
      },
    };
    const client = new BudgetedModelClient(inner, { maxTokens: 10 });

    await expect(
      client.complete({ model: "stub", messages: [{ role: "user", content: "first" }] }),
    ).resolves.toMatchObject({ text: '{"ok":true}' });
    await expect(
      client.complete({ model: "stub", messages: [{ role: "user", content: "second" }] }),
    ).rejects.toThrow(/token budget exhausted/);
    expect(client.currentUsage()).toEqual({ inputTokens: 7, outputTokens: 3 });
  });

  it("denies later calls once provider-reported cost reaches the cap", async () => {
    const inner: ModelClient = {
      async complete() {
        return {
          text: '{"ok":true}',
          raw: {},
          usage: { inputTokens: 1, outputTokens: 1, costUsd: 0.02 },
        };
      },
    };
    const client = new BudgetedModelClient(inner, { maxCostUsd: 0.01 });

    await client.complete({ model: "stub", messages: [{ role: "user", content: "first" }] });
    await expect(
      client.complete({ model: "stub", messages: [{ role: "user", content: "second" }] }),
    ).rejects.toThrow(/cost budget exhausted/);
  });
});

describe("explore stub model", () => {
  it("emits ranking JSON and command/final actions for CLI harness testing", async () => {
    const client = new StubExploreModelClient();
    const ranking = await client.complete({
      model: "stub-explore",
      messages: [
        {
          role: "user",
          content:
            "Rank these production-relevant files\nFILE: src/Main.java\nFILE: src/Auth.java\n",
        },
      ],
    });
    expect(parseRankingsFromText(ranking.text).map((r) => r.filePath)).toEqual([
      "src/Main.java",
      "src/Auth.java",
    ]);

    const command = await client.complete({
      model: "stub-explore",
      messages: [{ role: "user", content: "Focus file: src/Main.java\n" }],
    });
    expect(parseExploreAction(command.text)).toMatchObject({
      action: "run_command",
      command: "test -f 'src/Main.java' && sed -n '1,40p' 'src/Main.java'",
    });

    const denied = await client.complete({
      model: "stub-explore",
      messages: [{ role: "user", content: "Focus file: src/DeniedParser.java\n" }],
    });
    expect(parseExploreAction(denied.text)).toMatchObject({
      action: "run_command",
      command: "curl https://example.com/denied",
    });

    const final = await client.complete({
      model: "stub-explore",
      messages: [{ role: "user", content: "Command observation:\n{}" }],
    });
    expect(parseExploreAction(final.text)).toMatchObject({
      action: "final",
      result: { outcome: "no-bug" },
    });
  });

  it("can deterministically produce and validate an accepted stub finding", async () => {
    const client = new StubExploreModelClient();
    const bug = await client.complete({
      model: "stub-explore",
      messages: [
        {
          role: "user",
          content: 'Command observation:\n{"stdout":"DEEPSEC_STUB_BUG"}',
        },
      ],
    });
    const action = parseExploreAction(bug.text);
    expect(action).toMatchObject({
      action: "final",
      result: { outcome: "bug", vulnSlug: "deepsec-stub-bug" },
    });
    if (action.action !== "final" || action.result.outcome !== "bug") {
      throw new Error("Expected deterministic stub bug.");
    }

    const validation = await validateBugReport({
      client,
      model: "stub-explore",
      report: action.result,
      transcript: [],
      maxTurns: 4,
      container: {
        containerId: "validation",
        runtime: "runsc",
        networkMode: "none",
        image: "fixture",
      },
      runner: {
        async exec(command: string) {
          return {
            command,
            exitCode: 0,
            durationMs: 1,
            stdout: "src/main/java/com/acme/AAuthParser.java:4:DEEPSEC_STUB_BUG",
            stderr: "",
            timedOut: false,
            truncated: false,
          };
        },
      },
    });

    expect(validation.verdict).toMatchObject({
      verdict: "true-positive",
      reproducible: true,
      interesting: true,
      adjustedSeverity: "MEDIUM",
    });
    expect(validation.usage?.inputTokens).toBeGreaterThan(0);
    expect(validation.container?.runtime).toBe("runsc");
    expect(validation.transcript?.some((entry) => entry.role === "tool")).toBe(true);
  });

  it("repairs malformed validation JSON on the final allowed turn", async () => {
    const responses = [
      JSON.stringify({ action: "run_command", command: "grep -R marker src/main/java" }),
      '{"action":"final"',
      JSON.stringify({
        action: "final",
        result: {
          verdict: "true-positive",
          reproducible: true,
          interesting: true,
          reasoning: "repaired final validation verdict",
        },
      }),
    ];
    const events: ExploreProgressEvent[] = [];
    const client: ModelClient = {
      async complete() {
        return { text: responses.shift()!, raw: {} };
      },
    };
    const report: BugReport = {
      outcome: "bug",
      title: "Marker bug",
      severity: "MEDIUM",
      confidence: "high",
      vulnSlug: "marker-bug",
      lineNumbers: [1],
      description: "marker",
      recommendation: "remove marker",
      reproductionSteps: ["grep marker"],
      evidence: ["marker"],
    };

    const validation = await validateBugReport({
      client,
      model: "stub",
      report,
      transcript: [],
      maxTurns: 2,
      container: {
        containerId: "validation",
        runtime: "runsc",
        networkMode: "none",
        image: "fixture",
      },
      runner: {
        async exec(command: string) {
          return {
            command,
            exitCode: 0,
            durationMs: 1,
            stdout: "marker",
            stderr: "",
            timedOut: false,
            truncated: false,
          };
        },
      },
      onProgress: (event) => events.push(event),
    });

    expect(validation.verdict).toMatchObject({
      verdict: "true-positive",
      reasoning: "repaired final validation verdict",
    });
    expect(validation.turns).toBe(2);
    expect(events.filter((event) => event.type === "repair")).toHaveLength(1);
    expect(events.filter((event) => event.type === "model-response")).toHaveLength(3);
  });
});

describe("explore command sandboxing", () => {
  it("denies host paths, credentials, network tools, and traversal", () => {
    expect(() => assertSafeContainerCommand("./gradlew --offline test")).not.toThrow();
    expect(() => assertSafeContainerCommand("cat /Users/me/secret.txt")).toThrow(/host path/);
    expect(() => assertSafeContainerCommand("cat /workspace/home/.ssh/id_rsa")).toThrow(
      /credential/,
    );
    expect(() => assertSafeContainerCommand("echo $OPENROUTER_API_KEY")).toThrow(/credential/);
    expect(() => assertSafeContainerCommand("curl https://example.com")).toThrow(/network/);
    expect(() => assertSafeContainerCommand("cat ../secret")).toThrow(/traversal/);
  });

  it("sanitizes environment and caps command output", () => {
    const env = sanitizeExploreEnv();
    expect(env.OPENROUTER_API_KEY).toBeUndefined();
    expect(env.HOME).toBe("/workspace/home");
    const capped = truncateOutput("a".repeat(100), "b".repeat(100), 80);
    expect(capped.truncated).toBe(true);
    expect(capped.stdout.length).toBeLessThanOrEqual(40);
  });

  it("redacts common secret values from command output artifacts", () => {
    const redacted = redactSensitiveText(
      [
        "OPENROUTER_API_KEY=sk-or-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyzABCDEF123456",
        "aws=AKIA1234567890ABCDEF",
      ].join("\n"),
    );

    expect(redacted.redacted).toBe(true);
    expect(redacted.text).toContain("OPENROUTER_API_KEY=[REDACTED:secret-assignment]");
    expect(redacted.text).toContain("[REDACTED:bearer-token]");
    expect(redacted.text).toContain("[REDACTED:aws-access-key]");
    expect(redacted.text).not.toContain("sk-or-v1-aaaaaaaa");
    expect(redacted.text).not.toContain("AKIA1234567890ABCDEF");

    const execution = redactCommandExecution({
      command: "echo sk-or-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      exitCode: 0,
      durationMs: 1,
      stdout: "ok",
      stderr: "",
      timedOut: false,
      truncated: false,
    });
    expect(execution.redacted).toBe(true);
    expect(execution.command).toBe("echo [REDACTED:openrouter-api-key]");
  });
});

describe("explore model contracts", () => {
  it("prompts focused agents to use canonical action JSON instead of live-model aliases", () => {
    const contract = [
      exploreSystemPrompt(),
      finalExploreTurnPrompt(),
      exploreRepairPrompt("action must be a non-empty string."),
    ].join("\n\n");

    expect(contract).toContain('"action": "run_command"');
    expect(contract).toContain('"action": "final"');
    expect(contract).toContain('"outcome": "no-bug"');
    expect(contract).toContain('"outcome": "bug"');
    expect(contract).toContain('{"result":"no_bug_found"}');
    expect(contract).toContain('The top-level "action" field is required.');
  });

  it("prompts validators to use canonical verdict JSON instead of verdict aliases", () => {
    const report: BugReport = {
      outcome: "bug",
      title: "Marker bug",
      severity: "MEDIUM",
      confidence: "high",
      vulnSlug: "marker-bug",
      lineNumbers: [1],
      description: "marker",
      recommendation: "remove marker",
      reproductionSteps: ["grep marker"],
      evidence: ["marker"],
    };
    const contract = [
      validationPrompt(report, "local evidence"),
      finalValidationTurnPrompt(),
      validationRepairPrompt("verdict must be a non-empty string."),
    ].join("\n\n");

    expect(contract).toContain('"action": "run_command"');
    expect(contract).toContain('"action": "final"');
    expect(contract).toContain('"verdict": "true-positive"');
    expect(contract).toContain("Allowed verdict values: true-positive, false-positive, uncertain.");
    expect(contract).toContain('{"result":"true_positive"}');
    expect(contract).toContain('The top-level "action" field is required.');
  });
});

describe("explore stubbed agent loop", () => {
  it("runs ranking-style focused command flow and returns a structured final report", async () => {
    const responses = [
      JSON.stringify({ action: "run_command", command: "sed -n '1,20p' src/Main.java" }),
      JSON.stringify({
        action: "final",
        result: {
          outcome: "bug",
          title: "Unchecked parser accepts unsafe sentinel",
          severity: "MEDIUM",
          confidence: "medium",
          vulnSlug: "unchecked-parser-sentinel",
          lineNumbers: [7],
          description: "The parser accepts a sentinel that bypasses validation.",
          recommendation: "Reject the sentinel before parsing.",
          reproductionSteps: ["Run the local parser test."],
          evidence: ["The local command printed the unsafe path."],
        },
      }),
    ];
    const client: ModelClient = {
      async complete() {
        return { text: responses.shift()!, raw: {} };
      },
    };
    const runner: ContainerRunner = {
      async exec(command: string) {
        return {
          command,
          exitCode: 0,
          durationMs: 10,
          stdout: "unsafe path",
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      },
    };
    const focus: RankedFile = {
      filePath: "src/Main.java",
      score: 5,
      reason: "parser",
    };
    const attempt = await runAgenticExploreLoop({
      projectId: "fixture",
      runId: "run",
      focus,
      topFiles: [focus],
      model: "stub",
      maxTurns: 4,
      client,
      runner,
      container: {
        containerId: "abc",
        runtime: "runsc",
        networkMode: "none",
        image: "fixture",
      },
    });
    expect(attempt.report.outcome).toBe("bug");
    expect(attempt.transcript.some((entry) => entry.role === "tool")).toBe(true);
  });

  it("emits bounded progress events without command output bodies", async () => {
    const responses = [
      JSON.stringify({ action: "run_command", command: "sed -n '1,20p' src/Main.java" }),
      JSON.stringify({
        action: "final",
        result: { outcome: "no-bug", summary: "checked", evidence: ["local command ran"] },
      }),
    ];
    const events: ExploreProgressEvent[] = [];
    const client: ModelClient = {
      async complete() {
        return { text: responses.shift()!, raw: {} };
      },
    };
    const runner: ContainerRunner = {
      async exec(command: string) {
        return {
          command,
          exitCode: 0,
          durationMs: 10,
          stdout: "sensitive local output",
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      },
    };
    const focus: RankedFile = { filePath: "src/Main.java", score: 5, reason: "parser" };

    await runAgenticExploreLoop({
      projectId: "fixture",
      runId: "run",
      focus,
      topFiles: [focus],
      model: "stub",
      maxTurns: 4,
      client,
      runner,
      container: {
        containerId: "abc",
        runtime: "runsc",
        networkMode: "none",
        image: "fixture",
      },
      onProgress: (event) => events.push(event),
    });

    expect(events.map((event) => event.type)).toEqual([
      "model-request",
      "model-response",
      "action",
      "command-result",
      "model-request",
      "model-response",
      "final",
    ]);
    const commandResult = events.find((event) => event.type === "command-result");
    expect(commandResult).toMatchObject({
      type: "command-result",
      stdoutBytes: "sensitive local output".length,
      stderrBytes: 0,
    });
    expect(commandResult).not.toHaveProperty("stdout");
    expect(commandResult).not.toHaveProperty("stderr");
  });

  it("redacts command output before persistence and model observation", async () => {
    const rawSecret = "sk-or-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const responses = [
      JSON.stringify({ action: "run_command", command: `echo ${rawSecret}` }),
      JSON.stringify({
        action: "final",
        result: { outcome: "no-bug", summary: "checked", evidence: ["local command ran"] },
      }),
    ];
    const events: ExploreProgressEvent[] = [];
    const client: ModelClient = {
      async complete(params) {
        if (responses.length === 1) {
          const observation = params.messages.at(-1)?.content ?? "";
          expect(observation).not.toContain(rawSecret);
          expect(observation).toContain("echo [REDACTED:openrouter-api-key]");
          expect(observation).toContain("OPENROUTER_API_KEY=[REDACTED:secret-assignment]");
        }
        return { text: responses.shift()!, raw: {} };
      },
    };
    const runner: ContainerRunner = {
      async exec(command: string) {
        return {
          command,
          exitCode: 0,
          durationMs: 10,
          stdout: `OPENROUTER_API_KEY=${rawSecret}`,
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      },
    };
    const focus: RankedFile = { filePath: "src/Main.java", score: 5, reason: "parser" };

    const attempt = await runAgenticExploreLoop({
      projectId: "fixture",
      runId: "run",
      focus,
      topFiles: [focus],
      model: "stub",
      maxTurns: 4,
      client,
      runner,
      container: {
        containerId: "abc",
        runtime: "runsc",
        networkMode: "none",
        image: "fixture",
      },
      onProgress: (event) => events.push(event),
    });

    const toolEntry = attempt.transcript.find((entry) => entry.role === "tool");
    expect(JSON.stringify(toolEntry)).not.toContain(rawSecret);
    expect(JSON.stringify(events)).not.toContain(rawSecret);
    expect(JSON.stringify(toolEntry)).toContain("OPENROUTER_API_KEY=[REDACTED:secret-assignment]");
    expect(events.find((event) => event.type === "action")).toMatchObject({
      command: "echo [REDACTED:openrouter-api-key]",
      redacted: true,
    });
    expect(events.find((event) => event.type === "command-result")).toMatchObject({
      command: "echo [REDACTED:openrouter-api-key]",
      redacted: true,
    });
  });

  it("sums model usage across focused agent turns and emits per-response usage", async () => {
    const responses = [
      JSON.stringify({ action: "run_command", command: "sed -n '1,20p' src/Main.java" }),
      JSON.stringify({
        action: "final",
        result: { outcome: "no-bug", summary: "checked", evidence: ["local command ran"] },
      }),
    ];
    const usages = [
      { inputTokens: 10, outputTokens: 4, costUsd: 0.001 },
      { inputTokens: 20, outputTokens: 8, costUsd: 0.002 },
    ];
    const events: ExploreProgressEvent[] = [];
    const client: ModelClient = {
      async complete() {
        return { text: responses.shift()!, raw: {}, usage: usages.shift()! };
      },
    };
    const runner: ContainerRunner = {
      async exec(command: string) {
        return {
          command,
          exitCode: 0,
          durationMs: 10,
          stdout: "ok",
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      },
    };
    const focus: RankedFile = { filePath: "src/Main.java", score: 5, reason: "parser" };

    const attempt = await runAgenticExploreLoop({
      projectId: "fixture",
      runId: "run",
      focus,
      topFiles: [focus],
      model: "stub",
      maxTurns: 4,
      client,
      runner,
      container: {
        containerId: "abc",
        runtime: "runsc",
        networkMode: "none",
        image: "fixture",
      },
      onProgress: (event) => events.push(event),
    });

    expect(attempt.usage?.inputTokens).toBe(30);
    expect(attempt.usage?.outputTokens).toBe(12);
    expect(attempt.usage?.costUsd).toBeCloseTo(0.003);
    const modelResponses = events.filter((event) => event.type === "model-response");
    expect(modelResponses).toHaveLength(2);
    expect(modelResponses[0]).toMatchObject({
      type: "model-response",
      usage: { inputTokens: 10, outputTokens: 4, costUsd: 0.001 },
    });
  });

  it("asks for a final report on the last allowed turn", async () => {
    const responses = [
      JSON.stringify({ action: "run_command", command: "sed -n '1,20p' src/Main.java" }),
      JSON.stringify({
        action: "final",
        result: { outcome: "no-bug", summary: "finalized", evidence: ["checked locally"] },
      }),
    ];
    const client: ModelClient = {
      async complete(params) {
        if (responses.length === 1) {
          expect(params.messages.at(-1)?.content).toContain("final allowed model turn");
          expect(params.messages.at(-1)?.content).toContain("Do not request another command");
        }
        return { text: responses.shift()!, raw: {} };
      },
    };
    const runner: ContainerRunner = {
      async exec(command: string) {
        return {
          command,
          exitCode: 0,
          durationMs: 1,
          stdout: "ok",
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      },
    };
    const focus: RankedFile = { filePath: "src/Main.java", score: 5, reason: "parser" };

    const attempt = await runAgenticExploreLoop({
      projectId: "fixture",
      runId: "run",
      focus,
      topFiles: [focus],
      model: "stub",
      maxTurns: 2,
      client,
      runner,
      container: {
        containerId: "abc",
        runtime: "runsc",
        networkMode: "none",
        image: "fixture",
      },
    });

    expect(attempt.report).toMatchObject({ outcome: "no-bug", summary: "finalized" });
    expect(attempt.turns).toBe(2);
  });

  it("repairs malformed explore JSON on the final allowed turn", async () => {
    const responses = [
      JSON.stringify({ action: "run_command", command: "sed -n '1,20p' src/Main.java" }),
      '{"action":"final"',
      JSON.stringify({
        action: "final",
        result: { outcome: "no-bug", summary: "repaired final", evidence: ["checked locally"] },
      }),
    ];
    const events: ExploreProgressEvent[] = [];
    const client: ModelClient = {
      async complete(params) {
        if (responses.length <= 1) {
          expect(params.messages.at(-1)?.content).toContain("Return exactly one valid JSON");
        }
        return { text: responses.shift()!, raw: {} };
      },
    };
    const runner: ContainerRunner = {
      async exec(command: string) {
        return {
          command,
          exitCode: 0,
          durationMs: 1,
          stdout: "ok",
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      },
    };
    const focus: RankedFile = { filePath: "src/Main.java", score: 5, reason: "parser" };

    const attempt = await runAgenticExploreLoop({
      projectId: "fixture",
      runId: "run",
      focus,
      topFiles: [focus],
      model: "stub",
      maxTurns: 2,
      client,
      runner,
      container: {
        containerId: "abc",
        runtime: "runsc",
        networkMode: "none",
        image: "fixture",
      },
      onProgress: (event) => events.push(event),
    });

    expect(attempt.report).toMatchObject({ outcome: "no-bug", summary: "repaired final" });
    expect(attempt.turns).toBe(2);
    expect(events.filter((event) => event.type === "repair")).toHaveLength(1);
    expect(events.filter((event) => event.type === "model-response")).toHaveLength(3);
  });

  it("does not execute a command requested on the final allowed turn", async () => {
    const responses = [
      JSON.stringify({ action: "run_command", command: "sed -n '1,20p' src/Main.java" }),
      JSON.stringify({ action: "run_command", command: "echo should-not-run" }),
    ];
    let execCalls = 0;
    const client: ModelClient = {
      async complete() {
        return { text: responses.shift()!, raw: {} };
      },
    };
    const runner: ContainerRunner = {
      async exec(command: string) {
        execCalls++;
        return {
          command,
          exitCode: 0,
          durationMs: 1,
          stdout: "ok",
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      },
    };
    const focus: RankedFile = { filePath: "src/Main.java", score: 5, reason: "parser" };

    const attempt = await runAgenticExploreLoop({
      projectId: "fixture",
      runId: "run",
      focus,
      topFiles: [focus],
      model: "stub",
      maxTurns: 2,
      client,
      runner,
      container: {
        containerId: "abc",
        runtime: "runsc",
        networkMode: "none",
        image: "fixture",
      },
    });

    expect(execCalls).toBe(1);
    expect(attempt.report).toMatchObject({
      outcome: "no-bug",
      summary: expect.stringContaining("requested another command"),
    });
  });

  it("uses a repair turn when the model emits incomplete JSON", async () => {
    const responses = [
      '{"action":"run_command","command":"sed -n ',
      JSON.stringify({
        action: "final",
        result: { outcome: "no-bug", summary: "repaired", evidence: ["valid JSON after repair"] },
      }),
    ];
    const client: ModelClient = {
      async complete(params) {
        if (params.messages.at(-1)?.content.includes("not one complete valid JSON")) {
          expect(params.messages.at(-1)?.content).toContain("Return exactly one valid JSON");
        }
        return { text: responses.shift()!, raw: {} };
      },
    };
    const runner: ContainerRunner = {
      async exec() {
        throw new Error("no command should run");
      },
    };
    const focus: RankedFile = { filePath: "src/Main.java", score: 5, reason: "parser" };
    const attempt = await runAgenticExploreLoop({
      projectId: "fixture",
      runId: "run",
      focus,
      topFiles: [focus],
      model: "stub",
      maxTurns: 4,
      client,
      runner,
      container: {
        containerId: "abc",
        runtime: "runsc",
        networkMode: "none",
        image: "fixture",
      },
    });
    expect(attempt.report).toEqual({
      outcome: "no-bug",
      summary: "repaired",
      evidence: ["valid JSON after repair"],
    });
  });

  it("rejects malformed agent actions", () => {
    expect(() =>
      parseExploreAction('{"action":"run_command","command":"curl https://x"}'),
    ).not.toThrow();
    expect(
      parseExploreAction(
        '{"action":"finish","result":{"outcome":"no-bug","summary":"checked","evidence":[]}}',
      ),
    ).toEqual({
      action: "final",
      result: { outcome: "no-bug", summary: "checked", evidence: [] },
    });
    expect(() => parseExploreAction('{"action":"final","result":{"outcome":"maybe"}}')).toThrow(
      /Unsupported/,
    );
  });

  it("accepts common no-bug final report shapes returned by live models", () => {
    expect(
      parseExploreAction(
        JSON.stringify({
          result: "no_bug_found",
          evidence: {
            summary: "Reviewed the file and found no confirmed defect.",
            observations: ["Suspicious branch was inspected."],
            conclusion: "No local reproduction evidence.",
          },
        }),
      ),
    ).toEqual({
      action: "final",
      result: {
        outcome: "no-bug",
        summary: "Reviewed the file and found no confirmed defect.",
        evidence: [
          "Reviewed the file and found no confirmed defect.",
          "Suspicious branch was inspected.",
          "No local reproduction evidence.",
        ],
      },
    });

    expect(
      parseExploreAction(
        JSON.stringify({
          action: "final",
          result: "no_bug_found",
          evidence: "No definitive local reproduction evidence available.",
        }),
      ),
    ).toEqual({
      action: "final",
      result: {
        outcome: "no-bug",
        summary: "No definitive local reproduction evidence available.",
        evidence: ["No definitive local reproduction evidence available."],
      },
    });
  });

  it("accepts common validation verdict spellings returned by live models", () => {
    expect(
      parseValidationAction(
        JSON.stringify({
          result: "false_positive",
          reproducible: false,
          interesting: false,
          reasoning: "Could not reproduce the report.",
        }),
      ),
    ).toEqual({
      action: "final",
      verdict: {
        verdict: "false-positive",
        reproducible: false,
        interesting: false,
        reasoning: "Could not reproduce the report.",
        adjustedSeverity: undefined,
      },
    });

    expect(
      parseValidationAction(
        JSON.stringify({
          action: "final",
          result: "true_positive",
          reproducible: true,
          interesting: true,
          reasoning: "Reproduced in the isolated container.",
        }),
      ),
    ).toMatchObject({
      action: "final",
      verdict: {
        verdict: "true-positive",
        reproducible: true,
        interesting: true,
      },
    });
  });
});

describe("explore report merge", () => {
  it("records no-bug attempts as analyzed files with zero findings", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-data-"));
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-root-"));
    tempRoots.push(dataRoot, root);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    fs.mkdirSync(path.join(root, "src/main/java"), { recursive: true });
    fs.writeFileSync(path.join(root, "src/main/java/Parser.java"), "class Parser {}\n");

    const accepted = mergeAcceptedExploreAttempt({
      projectId: "fixture",
      root,
      runId: "20260605010101-abcdef",
      model: "stub-model",
      attempt: {
        projectId: "fixture",
        runId: "20260605010101-abcdef",
        focusFile: "src/main/java/Parser.java",
        model: "stub-model",
        startedAt: "2026-06-05T01:01:01.000Z",
        completedAt: "2026-06-05T01:01:02.000Z",
        turns: 2,
        container: {
          containerId: "abc",
          runtime: "runsc",
          networkMode: "none",
          image: "deepsec-explore-java11-gradle:local",
        },
        transcript: [],
        report: { outcome: "no-bug", summary: "checked", evidence: ["no repro"] },
        usage: { inputTokens: 100, outputTokens: 25, costUsd: 0.01 },
      },
    });

    expect(accepted).toBe(false);
    const record = readFileRecord("fixture", "src/main/java/Parser.java");
    expect(record?.status).toBe("analyzed");
    expect(record?.findings).toEqual([]);
    expect(record?.analysisHistory[0]?.findingCount).toBe(0);
    expect(record?.analysisHistory[0]?.modelConfig.outcome).toBe("no-bug");
    expect(record?.analysisHistory[0]?.usage).toEqual({
      inputTokens: 100,
      outputTokens: 25,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
    });
    expect(record?.analysisHistory[0]?.costUsd).toBe(0.01);
  });

  it("merges accepted validation into normal file records", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-data-"));
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-root-"));
    tempRoots.push(dataRoot, root);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    fs.mkdirSync(path.join(root, "src/main/java"), { recursive: true });
    fs.writeFileSync(path.join(root, "src/main/java/Parser.java"), "class Parser {}\n");

    const merged = mergeAcceptedExploreAttempt({
      projectId: "fixture",
      root,
      runId: "20260605010101-abcdef",
      model: "stub-model",
      attempt: {
        projectId: "fixture",
        runId: "20260605010101-abcdef",
        focusFile: "src/main/java/Parser.java",
        model: "stub-model",
        startedAt: "2026-06-05T01:01:01.000Z",
        completedAt: "2026-06-05T01:01:02.000Z",
        turns: 2,
        container: {
          containerId: "abc",
          runtime: "runsc",
          networkMode: "none",
          image: "deepsec-explore-java11-gradle:local",
        },
        transcript: [],
        report: {
          outcome: "bug",
          title: "Parser accepts invalid field",
          severity: "HIGH",
          confidence: "high",
          vulnSlug: "parser-invalid-field",
          lineNumbers: [1],
          description: "Invalid field bypasses validation.",
          recommendation: "Validate before accepting the field.",
          reproductionSteps: ["Run a local parser repro."],
          evidence: ["Local repro exits 0 with invalid field."],
        },
        validation: {
          verdict: "true-positive",
          reproducible: true,
          interesting: true,
          reasoning: "Local repro confirms it.",
        },
      },
    });

    expect(merged).toBe(true);
    const record = readFileRecord("fixture", "src/main/java/Parser.java");
    expect(record?.status).toBe("analyzed");
    expect(record?.findings[0]?.revalidation?.verdict).toBe("true-positive");
    expect(record?.analysisHistory[0]?.modelConfig.mode).toBe("explore");

    const mergedAgain = mergeAcceptedExploreAttempt({
      projectId: "fixture",
      root,
      runId: "20260605010101-abcdef",
      model: "stub-model",
      attempt: {
        projectId: "fixture",
        runId: "20260605010101-abcdef",
        focusFile: "src/main/java/Parser.java",
        model: "stub-model",
        startedAt: "2026-06-05T01:01:03.000Z",
        completedAt: "2026-06-05T01:01:04.000Z",
        turns: 3,
        container: {
          containerId: "def",
          runtime: "runsc",
          networkMode: "none",
          image: "deepsec-explore-java11-gradle:local",
        },
        transcript: [],
        report: {
          outcome: "bug",
          title: "Parser accepts invalid field",
          severity: "HIGH",
          confidence: "high",
          vulnSlug: "parser-invalid-field",
          lineNumbers: [1],
          description: "Invalid field bypasses validation.",
          recommendation: "Validate before accepting the field.",
          reproductionSteps: ["Run a local parser repro."],
          evidence: ["Local repro exits 0 with invalid field."],
        },
        validation: {
          verdict: "true-positive",
          reproducible: true,
          interesting: true,
          reasoning: "Local repro still confirms it.",
        },
      },
    });

    expect(mergedAgain).toBe(true);
    const afterRetry = readFileRecord("fixture", "src/main/java/Parser.java");
    expect(afterRetry?.findings).toHaveLength(1);
    expect(
      afterRetry?.analysisHistory.filter((entry) => entry.runId === "20260605010101-abcdef"),
    ).toHaveLength(1);
    expect(afterRetry?.analysisHistory[0]?.numTurns).toBe(3);
  });

  it("removes stale findings from the same explore run when a retry is not accepted", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-data-"));
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-root-"));
    tempRoots.push(dataRoot, root);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    fs.mkdirSync(path.join(root, "src/main/java"), { recursive: true });
    fs.writeFileSync(path.join(root, "src/main/java/Parser.java"), "class Parser {}\n");

    const runId = "20260605010101-abcdef";
    const accepted = mergeAcceptedExploreAttempt({
      projectId: "fixture",
      root,
      runId,
      model: "stub-model",
      attempt: {
        projectId: "fixture",
        runId,
        focusFile: "src/main/java/Parser.java",
        model: "stub-model",
        startedAt: "2026-06-05T01:01:01.000Z",
        completedAt: "2026-06-05T01:01:02.000Z",
        turns: 2,
        container: {
          containerId: "abc",
          runtime: "runsc",
          networkMode: "none",
          image: "deepsec-explore-java11-gradle:local",
        },
        transcript: [],
        report: {
          outcome: "bug",
          title: "Parser accepts invalid field",
          severity: "HIGH",
          confidence: "high",
          vulnSlug: "parser-invalid-field",
          lineNumbers: [1],
          description: "Invalid field bypasses validation.",
          recommendation: "Validate before accepting the field.",
          reproductionSteps: ["Run a local parser repro."],
          evidence: ["Local repro exits 0 with invalid field."],
        },
        validation: {
          verdict: "true-positive",
          reproducible: true,
          interesting: true,
          reasoning: "Local repro confirms it.",
        },
      },
    });
    expect(accepted).toBe(true);
    expect(readFileRecord("fixture", "src/main/java/Parser.java")?.findings).toHaveLength(1);

    const acceptedAfterRetry = mergeAcceptedExploreAttempt({
      projectId: "fixture",
      root,
      runId,
      model: "stub-model",
      attempt: {
        projectId: "fixture",
        runId,
        focusFile: "src/main/java/Parser.java",
        model: "stub-model",
        startedAt: "2026-06-05T01:01:03.000Z",
        completedAt: "2026-06-05T01:01:04.000Z",
        turns: 3,
        container: {
          containerId: "def",
          runtime: "runsc",
          networkMode: "none",
          image: "deepsec-explore-java11-gradle:local",
        },
        transcript: [],
        report: { outcome: "no-bug", summary: "Retry did not reproduce a bug." },
      },
    });

    expect(acceptedAfterRetry).toBe(false);
    const afterRetry = readFileRecord("fixture", "src/main/java/Parser.java");
    expect(afterRetry?.findings).toEqual([]);
    expect(afterRetry?.analysisHistory).toHaveLength(1);
    expect(afterRetry?.analysisHistory[0]).toMatchObject({
      runId,
      findingCount: 0,
      numTurns: 3,
      modelConfig: { outcome: "no-bug" },
    });
  });
});

describe("explore run status", () => {
  function hardenedContainer() {
    return {
      containerId: "abc",
      runtime: "runsc",
      networkMode: "none",
      image: "image",
      readOnlyRootfs: true,
      noNewPrivileges: true,
      capDropAll: true,
      privileged: false,
      pidsLimit: 512,
      memoryBytes: 4_294_967_296,
      nanoCpus: 2_000_000_000,
      copyExcludedCount: 3,
      copyExcludedPaths: [".env", ".ssh", "service.credentials.json"],
      mountDestinations: [
        "/workspace/gradle-cache",
        "/workspace/home",
        "/workspace/out",
        "/workspace/target",
      ],
    };
  }

  function emptyWorkspaceChanges() {
    return {
      generatedAt: "now",
      containerTarget: "/workspace/target",
      totalChanges: 0,
      capturedChanges: 0,
      omittedChanges: 0,
      changes: [],
    };
  }

  function writeWorkspaceChanges(
    runDir: string,
    value: ReturnType<typeof emptyWorkspaceChanges> = emptyWorkspaceChanges(),
  ) {
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "workspace-changes.json"),
      JSON.stringify(value),
    );
  }

  it("summarizes a healthy explore run with sandbox evidence", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        usage: { inputTokens: 5, outputTokens: 2, costUsd: 0.0001 },
        rankings: [{ filePath: "src/Main.java", score: 5, reason: "parser" }],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({
        attempts: 1,
        completedAttempts: 1,
        failedAttempts: 0,
        bugsReported: 0,
        acceptedFindings: 0,
        rankingUsage: { inputTokens: 5, outputTokens: 2, costUsd: 0.0001 },
        attemptUsage: { inputTokens: 50, outputTokens: 10, costUsd: 0.002 },
        usage: { inputTokens: 55, outputTokens: 12, costUsd: 0.0021 },
      }),
    );
    writeWorkspaceChanges(runDir);
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/Main.java",
        model: "stub",
        startedAt: "start",
        completedAt: "end",
        turns: 2,
        container: hardenedContainer(),
        transcript: [{ role: "tool", content: { command: "echo ok" } }],
        report: { outcome: "no-bug", summary: "checked" },
        usage: { inputTokens: 50, outputTokens: 10, costUsd: 0.002 },
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n${JSON.stringify({ type: "final", turn: 2 })}\n`,
    );

    const status = summarizeExploreRun("fixture", "run-1");

    expect(status.ok).toBe(true);
    expect(status.rankingsCount).toBe(1);
    expect(status.rankingScoreMin).toBe(5);
    expect(status.rankingScoreMax).toBe(5);
    expect(status.summary?.usage).toEqual({
      inputTokens: 55,
      outputTokens: 12,
      costUsd: 0.0021,
    });
    expect(status.attempts[0]).toMatchObject({
      focusFile: "src/Main.java",
      outcome: "no-bug",
      runtime: "runsc",
      networkMode: "none",
      readOnlyRootfs: true,
      noNewPrivileges: true,
      capDropAll: true,
      privileged: false,
      copyExcludedCount: 3,
      copyExcludedPaths: [".env", ".ssh", "service.credentials.json"],
      eventCount: 2,
      toolEvents: 1,
      inputTokens: 50,
      outputTokens: 10,
      costUsd: 0.002,
      usage: { inputTokens: 50, outputTokens: 10, costUsd: 0.002 },
      workspaceChanges: 0,
      workspaceChangesCaptured: 0,
      problems: [],
    });
  });

  it("flags inconsistent provider usage totals", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        usage: { inputTokens: 5, outputTokens: 2, costUsd: 0.0001 },
        rankings: [{ filePath: "src/Main.java", score: 5, reason: "parser" }],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({
        attempts: 1,
        completedAttempts: 1,
        failedAttempts: 0,
        bugsReported: 0,
        acceptedFindings: 0,
        rankingUsage: { inputTokens: 4, outputTokens: 2, costUsd: 0.0001 },
        attemptUsage: { inputTokens: 51, outputTokens: 10, costUsd: 0.002 },
        usage: { inputTokens: 55, outputTokens: 11, costUsd: 0.0021 },
      }),
    );
    writeWorkspaceChanges(runDir);
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/Main.java",
        model: "stub",
        startedAt: "start",
        completedAt: "end",
        turns: 2,
        container: hardenedContainer(),
        transcript: [{ role: "tool", content: { command: "echo ok" } }],
        report: { outcome: "no-bug", summary: "checked" },
        usage: { inputTokens: 50, outputTokens: 10, costUsd: 0.002 },
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
    );

    const status = summarizeExploreRun("fixture", "run-1");

    expect(status.ok).toBe(false);
    expect(status.problems).toEqual([
      "summary.rankingUsage does not match rankings.usage",
      "summary.attemptUsage does not match attempt usage totals",
      "summary.usage does not match ranking+attempt usage totals",
    ]);
  });

  it("summarizes captured workspace changes for attempts", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        rankings: [{ filePath: "src/Main.java", score: 5, reason: "parser" }],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({ attempts: 1, completedAttempts: 1, failedAttempts: 0 }),
    );
    const workspaceChanges = {
      generatedAt: "now",
      containerTarget: "/workspace/target",
      totalChanges: 2,
      capturedChanges: 2,
      omittedChanges: 0,
      changes: [
        { path: "src/Repro.java", status: "added", afterSha256: "a", afterBytes: 10 },
        { path: "src/Main.java", status: "modified", beforeSha256: "b", afterSha256: "c" },
      ],
    };
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "workspace-changes.json"),
      JSON.stringify(workspaceChanges),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/Main.java",
        model: "stub",
        startedAt: "start",
        completedAt: "end",
        turns: 2,
        container: hardenedContainer(),
        transcript: [{ role: "tool", content: { command: "echo ok" } }],
        report: { outcome: "no-bug", summary: "checked" },
        workspaceChanges,
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
    );

    const status = summarizeExploreRun("fixture", "run-1");

    expect(status.ok).toBe(true);
    expect(status.attempts[0]).toMatchObject({
      workspaceChanges: 2,
      workspaceChangesCaptured: 2,
      problems: [],
    });
  });

  it("prints a machine-readable explore artifact index", async () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        rankings: [{ filePath: "src/Main.java", score: 5, reason: "parser" }],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({
        attempts: 1,
        completedAttempts: 1,
        failedAttempts: 0,
        bugsReported: 0,
        acceptedFindings: 0,
      }),
    );
    writeWorkspaceChanges(runDir);
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/Main.java",
        model: "stub",
        startedAt: "start",
        completedAt: "end",
        turns: 2,
        container: hardenedContainer(),
        transcript: [{ role: "tool", content: { command: "echo ok" } }],
        report: { outcome: "no-bug", summary: "checked" },
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
    );
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((value?: unknown) => {
      logs.push(String(value ?? ""));
    });

    await exploreArtifactsCommand({ projectId: "fixture", runId: "run-1", json: true });

    const index = JSON.parse(logs.join("\n"));
    expect(index).toMatchObject({
      version: 1,
      projectId: "fixture",
      runId: "run-1",
      statusOk: true,
      problems: [],
      exploreDir: runDir,
    });
    expect(index.runArtifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "summary",
          path: path.join(runDir, "summary.json"),
          exists: true,
          bytes: expect.any(Number),
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
      ]),
    );
    expect(index.attempts[0]).toMatchObject({
      dirName: "01",
      focusFile: "src/Main.java",
      dir: path.join(runDir, "attempts", "01"),
    });
    expect(index.attempts[0].artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "attempt",
          exists: true,
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
        expect.objectContaining({
          kind: "workspace-changes",
          exists: true,
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
        expect.objectContaining({
          kind: "validation-events",
          exists: false,
        }),
      ]),
    );
    expect(index.reportArtifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "report-json",
          exists: false,
        }),
      ]),
    );
    expect(index.ciArtifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "ci-summary",
          path: path.join(dataRoot, "fixture", "ci", "run-1", "ci-summary.json"),
          exists: false,
        }),
      ]),
    );
  });

  it("inspects one explore attempt as machine-readable JSON", async () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        rankings: [{ filePath: "src/Main.java", score: 5, reason: "parser" }],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({
        attempts: 1,
        completedAttempts: 1,
        failedAttempts: 0,
        bugsReported: 1,
        acceptedFindings: 1,
      }),
    );
    writeWorkspaceChanges(runDir);
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/Main.java",
        model: "stub",
        startedAt: "start",
        completedAt: "end",
        turns: 2,
        container: hardenedContainer(),
        transcript: [{ role: "tool", content: { command: "echo bug" } }],
        report: {
          outcome: "bug",
          title: "Bug",
          severity: "MEDIUM",
          confidence: "high",
          vulnSlug: "bug",
          lineNumbers: [7],
          description: "desc",
          recommendation: "fix",
          reproductionSteps: ["run local repro"],
          evidence: ["evidence"],
        },
        validation: {
          verdict: "true-positive",
          reproducible: true,
          interesting: true,
          reasoning: "confirmed",
        },
        validationContainer: hardenedContainer(),
        validationTranscript: [{ role: "tool", content: { command: "grep marker" } }],
        validationTurns: 1,
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "validation-events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
    );
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((value?: unknown) => {
      logs.push(String(value ?? ""));
    });

    await exploreAttemptCommand({
      projectId: "fixture",
      runId: "run-1",
      attempt: "1",
      json: true,
    });

    const inspection = JSON.parse(logs.join("\n"));
    expect(inspection).toMatchObject({
      version: 1,
      projectId: "fixture",
      runId: "run-1",
      attempt: "01",
      attemptDir: path.join(runDir, "attempts", "01"),
      problems: [],
      status: {
        focusFile: "src/Main.java",
        outcome: "bug",
        acceptedFinding: true,
      },
      report: {
        outcome: "bug",
        title: "Bug",
        severity: "MEDIUM",
        lineNumbers: [7],
      },
      validation: {
        verdict: "true-positive",
        reproducible: true,
        interesting: true,
      },
      workspaceChanges: {
        totalChanges: 0,
        capturedChanges: 0,
      },
    });
    expect(inspection.transcript).toBeUndefined();
    expect(inspection.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "attempt",
          exists: true,
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
        expect.objectContaining({
          kind: "validation-events",
          exists: true,
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
      ]),
    );
  });

  it("lists accepted explore findings and can include non-accepted reports", async () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    for (const dirName of ["01", "02"]) {
      fs.mkdirSync(path.join(runDir, "attempts", dirName), { recursive: true });
      fs.writeFileSync(
        path.join(runDir, "attempts", dirName, "workspace-changes.json"),
        JSON.stringify(emptyWorkspaceChanges()),
      );
      fs.writeFileSync(
        path.join(runDir, "attempts", dirName, "events.jsonl"),
        `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
      );
      fs.writeFileSync(
        path.join(runDir, "attempts", dirName, "validation-events.jsonl"),
        `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
      );
    }
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        rankings: [
          { filePath: "src/Low.java", score: 5, reason: "parser" },
          { filePath: "src/High.java", score: 5, reason: "parser" },
        ],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({
        attempts: 2,
        completedAttempts: 2,
        failedAttempts: 0,
        bugsReported: 2,
        acceptedFindings: 1,
      }),
    );
    const baseAttempt = {
      projectId: "fixture",
      runId: "run-1",
      model: "stub",
      startedAt: "start",
      completedAt: "end",
      turns: 2,
      container: hardenedContainer(),
      transcript: [{ role: "tool", content: { command: "echo bug" } }],
      validationContainer: hardenedContainer(),
      validationTranscript: [{ role: "tool", content: { command: "grep marker" } }],
      validationTurns: 1,
    };
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        ...baseAttempt,
        focusFile: "src/Low.java",
        report: {
          outcome: "bug",
          title: "Low accepted",
          severity: "LOW",
          confidence: "high",
          vulnSlug: "low-bug",
          lineNumbers: [1],
          description: "desc",
          recommendation: "fix",
          reproductionSteps: ["repro"],
          evidence: ["evidence"],
        },
        validation: {
          verdict: "true-positive",
          reproducible: true,
          interesting: true,
          reasoning: "confirmed",
        },
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "02", "attempt.json"),
      JSON.stringify({
        ...baseAttempt,
        focusFile: "src/High.java",
        report: {
          outcome: "bug",
          title: "High rejected",
          severity: "HIGH",
          confidence: "medium",
          vulnSlug: "high-bug",
          lineNumbers: [9],
          description: "desc",
          recommendation: "fix",
          reproductionSteps: ["repro"],
          evidence: ["evidence"],
        },
        validation: {
          verdict: "false-positive",
          reproducible: false,
          interesting: false,
          reasoning: "not real",
        },
      }),
    );
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((value?: unknown) => {
      logs.push(String(value ?? ""));
    });

    await exploreFindingsCommand({ projectId: "fixture", runId: "run-1", json: true });
    const acceptedOnly = JSON.parse(logs.splice(0).join("\n"));

    expect(acceptedOnly).toMatchObject({
      projectId: "fixture",
      runId: "run-1",
      acceptedOnly: true,
      counts: { findings: 1, accepted: 1 },
    });
    expect(acceptedOnly.findings).toEqual([
      expect.objectContaining({
        attempt: "01",
        focusFile: "src/Low.java",
        accepted: true,
        title: "Low accepted",
        severity: "LOW",
        thresholdMatched: true,
      }),
    ]);

    await exploreFindingsCommand({
      projectId: "fixture",
      runId: "run-1",
      json: true,
      all: true,
      minSeverity: "HIGH",
    });
    const allHigh = JSON.parse(logs.join("\n"));

    expect(allHigh).toMatchObject({
      acceptedOnly: false,
      minSeverity: "HIGH",
      counts: { findings: 1, accepted: 0, atOrAboveMinSeverity: 1 },
    });
    expect(allHigh.findings).toEqual([
      expect.objectContaining({
        attempt: "02",
        focusFile: "src/High.java",
        accepted: false,
        title: "High rejected",
        severity: "HIGH",
        validationVerdict: "false-positive",
        thresholdMatched: true,
      }),
    ]);
  });

  it("lists explore runs newest first as machine-readable JSON", async () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    for (const runId of ["run-1", "run-2"]) {
      const runDir = path.join(dataRoot, "fixture", "explore", runId);
      fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
      fs.writeFileSync(
        path.join(runDir, "metadata.json"),
        JSON.stringify({
          projectId: "fixture",
          runId,
          startedAt: runId === "run-1" ? "2026-06-01T00:00:00.000Z" : "2026-06-02T00:00:00.000Z",
        }),
      );
      fs.writeFileSync(
        path.join(runDir, "ranking-container.json"),
        JSON.stringify(hardenedContainer()),
      );
      fs.writeFileSync(
        path.join(runDir, "rankings.json"),
        JSON.stringify({
          projectId: "fixture",
          runId,
          generatedAt: "now",
          model: "stub",
          usage: { inputTokens: 3, outputTokens: 1, costUsd: 0.0002 },
          rankings: [{ filePath: "src/Main.java", score: 5, reason: "parser" }],
        }),
      );
      fs.writeFileSync(
        path.join(runDir, "summary.json"),
        JSON.stringify({
          attempts: 1,
          completedAttempts: 1,
          failedAttempts: 0,
          bugsReported: 0,
          acceptedFindings: 0,
          completedAt: runId === "run-1" ? "2026-06-01T00:01:00.000Z" : "2026-06-02T00:01:00.000Z",
          rankingUsage: { inputTokens: 3, outputTokens: 1, costUsd: 0.0002 },
          attemptUsage: { inputTokens: 7, outputTokens: 1, costUsd: 0.0008 },
          usage: { inputTokens: 10, outputTokens: 2, costUsd: 0.001 },
        }),
      );
      writeWorkspaceChanges(runDir);
      fs.writeFileSync(
        path.join(runDir, "attempts", "01", "attempt.json"),
        JSON.stringify({
          projectId: "fixture",
          runId,
          focusFile: "src/Main.java",
          model: "stub",
          startedAt: "start",
          completedAt: "end",
          turns: 2,
          container: hardenedContainer(),
          transcript: [{ role: "tool", content: { command: "echo ok" } }],
          report: { outcome: "no-bug", summary: "checked" },
          usage: { inputTokens: 7, outputTokens: 1, costUsd: 0.0008 },
        }),
      );
      fs.writeFileSync(
        path.join(runDir, "attempts", "01", "events.jsonl"),
        `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
      );
    }
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((value?: unknown) => {
      logs.push(String(value ?? ""));
    });

    await exploreListCommand({ projectId: "fixture", json: true, limit: 1 });

    const list = JSON.parse(logs.join("\n"));
    expect(list).toMatchObject({
      version: 1,
      projectId: "fixture",
      exploreRoot: path.join(dataRoot, "fixture", "explore"),
    });
    expect(list.runs).toHaveLength(1);
    expect(list.runs[0]).toMatchObject({
      projectId: "fixture",
      runId: "run-2",
      ok: true,
      rankingsCount: 1,
      attempts: 1,
      completedAttempts: 1,
      failedAttempts: 0,
      bugsReported: 0,
      acceptedFindings: 0,
      inputTokens: 10,
      outputTokens: 2,
      costUsd: 0.001,
      startedAt: "2026-06-02T00:00:00.000Z",
      completedAt: "2026-06-02T00:01:00.000Z",
    });
  });

  it("verifies integrity manifests and detects artifact tampering", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    const eventsPath = path.join(runDir, "attempts", "01", "events.jsonl");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1", integrityManifest: true }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        rankings: [{ filePath: "src/Main.java", score: 5, reason: "parser" }],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({ attempts: 1, completedAttempts: 1, failedAttempts: 0 }),
    );
    writeWorkspaceChanges(runDir);
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/Main.java",
        model: "stub",
        startedAt: "start",
        completedAt: "end",
        turns: 2,
        container: hardenedContainer(),
        transcript: [{ role: "tool", content: { command: "echo ok" } }],
        report: { outcome: "no-bug", summary: "checked" },
      }),
    );
    fs.writeFileSync(eventsPath, `${JSON.stringify({ type: "model-request", turn: 1 })}\n`);
    writeExploreIntegrityManifest(runDir);

    const before = summarizeExploreRun("fixture", "run-1");
    expect(before.ok).toBe(true);
    expect(before.integrity).toMatchObject({ present: true, files: expect.any(Number) });
    expect(before.integrity?.files).toBeGreaterThan(0);

    fs.appendFileSync(eventsPath, `${JSON.stringify({ type: "tampered" })}\n`);

    const after = summarizeExploreRun("fixture", "run-1");
    expect(after.ok).toBe(false);
    expect(after.problems).toContain("integrity mismatch for attempts/01/events.jsonl");
  });

  it("summarizes validation container evidence for bug attempts", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        rankings: [{ filePath: "src/Main.java", score: 5, reason: "parser" }],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({
        attempts: 1,
        completedAttempts: 1,
        failedAttempts: 0,
        bugsReported: 1,
        acceptedFindings: 1,
      }),
    );
    writeWorkspaceChanges(runDir);
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/Main.java",
        model: "stub",
        startedAt: "start",
        completedAt: "end",
        turns: 2,
        container: hardenedContainer(),
        transcript: [{ role: "tool", content: { command: "echo bug" } }],
        report: {
          outcome: "bug",
          title: "Bug",
          severity: "MEDIUM",
          confidence: "high",
          vulnSlug: "bug",
          lineNumbers: [1],
          description: "desc",
          recommendation: "fix",
          reproductionSteps: ["run local repro"],
          evidence: ["evidence"],
        },
        validation: {
          verdict: "true-positive",
          reproducible: true,
          interesting: true,
          reasoning: "confirmed in fresh container",
        },
        validationContainer: hardenedContainer(),
        validationTranscript: [{ role: "tool", content: { command: "grep marker" } }],
        validationTurns: 2,
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "validation-events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n${JSON.stringify({ type: "final", turn: 2 })}\n`,
    );

    const status = summarizeExploreRun("fixture", "run-1");

    expect(status.ok).toBe(true);
    expect(exploreStatusExitCode(status)).toBeUndefined();
    expect(exploreStatusExitCode(status, { failOnAcceptedFindings: true })).toBe(2);
    expect(
      exploreStatusExitCode(status, {
        failOnAcceptedFindings: true,
        minSeverity: "MEDIUM",
      }),
    ).toBe(2);
    expect(
      exploreStatusExitCode(status, {
        failOnAcceptedFindings: true,
        minSeverity: "HIGH",
      }),
    ).toBeUndefined();
    expect(status.attempts[0]).toMatchObject({
      outcome: "bug",
      bugTitle: "Bug",
      bugSeverity: "MEDIUM",
      bugConfidence: "high",
      vulnSlug: "bug",
      lineNumbers: [1],
      acceptedFinding: true,
      validationVerdict: "true-positive",
      validationRuntime: "runsc",
      validationNetworkMode: "none",
      validationTurns: 2,
      validationToolEvents: 1,
      validationEventCount: 2,
      problems: [],
    });
  });

  it("audits completed explore runs as a named automation checklist", async () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-audit-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        usage: { inputTokens: 5, outputTokens: 2, costUsd: 0.0001 },
        rankings: [{ filePath: "src/Main.java", score: 5, reason: "parser" }],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({
        attempts: 1,
        completedAttempts: 1,
        failedAttempts: 0,
        bugsReported: 1,
        acceptedFindings: 1,
        rankingUsage: { inputTokens: 5, outputTokens: 2, costUsd: 0.0001 },
        attemptUsage: { inputTokens: 50, outputTokens: 10, costUsd: 0.002 },
        usage: { inputTokens: 55, outputTokens: 12, costUsd: 0.0021 },
      }),
    );
    writeWorkspaceChanges(runDir);
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/Main.java",
        model: "stub",
        startedAt: "start",
        completedAt: "end",
        turns: 2,
        container: hardenedContainer(),
        transcript: [{ role: "tool", content: { command: "echo bug" } }],
        report: {
          outcome: "bug",
          title: "Low finding",
          severity: "LOW",
          confidence: "high",
          vulnSlug: "low-bug",
          lineNumbers: [12],
          description: "desc",
          recommendation: "fix",
          reproductionSteps: ["run local repro"],
          evidence: ["evidence"],
        },
        validation: {
          verdict: "true-positive",
          reproducible: true,
          interesting: true,
          reasoning: "confirmed",
        },
        validationContainer: hardenedContainer(),
        validationTranscript: [{ role: "tool", content: { command: "grep marker" } }],
        validationTurns: 1,
        usage: { inputTokens: 50, outputTokens: 10, costUsd: 0.002 },
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "validation-events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
    );
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((value?: unknown) => {
      logs.push(String(value ?? ""));
    });

    process.exitCode = undefined;
    await exploreAuditCommand({
      projectId: "fixture",
      runId: "run-1",
      json: true,
      failOnAcceptedFindings: true,
      minSeverity: "MEDIUM",
    });
    const passingAudit = JSON.parse(logs.splice(0).join("\n"));

    expect(process.exitCode).toBeUndefined();
    expect(passingAudit).toMatchObject({
      version: 1,
      projectId: "fixture",
      runId: "run-1",
      ok: true,
      exitCode: 0,
      gate: {
        failOnAcceptedFindings: true,
        minSeverity: "MEDIUM",
        acceptedFindingsAtOrAboveMinSeverity: 0,
        totalAcceptedFindings: 1,
      },
      run: {
        rankingsCount: 1,
        attempts: 1,
        completedAttempts: 1,
        failedAttempts: 0,
        bugsReported: 1,
        acceptedFindings: 1,
      },
    });
    expect(passingAudit.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "artifact-status", status: "pass" }),
        expect.objectContaining({ id: "gvisor-isolation", status: "pass" }),
        expect.objectContaining({ id: "validation", status: "pass" }),
        expect.objectContaining({ id: "usage-accounting", status: "pass" }),
        expect.objectContaining({ id: "accepted-finding-gate", status: "pass" }),
        expect.objectContaining({ id: "report-artifacts", status: "warn" }),
        expect.objectContaining({ id: "ci-artifacts", status: "warn" }),
      ]),
    );
    expect(passingAudit.warnings).toEqual(
      expect.arrayContaining([
        expect.stringContaining("report-artifacts:"),
        expect.stringContaining("ci-artifacts:"),
      ]),
    );

    process.exitCode = undefined;
    await exploreAuditCommand({
      projectId: "fixture",
      runId: "run-1",
      json: true,
      failOnAcceptedFindings: true,
      minSeverity: "LOW",
    });
    const failingAudit = JSON.parse(logs.splice(0).join("\n"));

    expect(process.exitCode).toBe(2);
    expect(failingAudit).toMatchObject({
      ok: false,
      exitCode: 2,
      gate: {
        acceptedFindingsAtOrAboveMinSeverity: 1,
        totalAcceptedFindings: 1,
      },
    });
    expect(failingAudit.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "accepted-finding-gate", status: "fail" }),
      ]),
    );

    const manifestOut = path.join(dataRoot, "manifest.json");
    process.exitCode = undefined;
    await exploreManifestCommand({
      projectId: "fixture",
      runId: "run-1",
      out: manifestOut,
      failOnAcceptedFindings: true,
      minSeverity: "MEDIUM",
    });

    expect(process.exitCode).toBeUndefined();
    expect(fs.existsSync(manifestOut)).toBe(true);
    expect(logs.join("\n")).toContain("DeepSec explore manifest");
    const manifest = JSON.parse(fs.readFileSync(manifestOut, "utf-8"));
    expect(manifest).toMatchObject({
      version: 1,
      projectId: "fixture",
      runId: "run-1",
      statusOk: true,
      outputs: { manifestJson: manifestOut },
      audit: {
        exitCode: 0,
        gate: {
          minSeverity: "MEDIUM",
          acceptedFindingsAtOrAboveMinSeverity: 0,
          totalAcceptedFindings: 1,
        },
      },
      findings: {
        counts: { findings: 1, accepted: 1 },
        findings: [
          expect.objectContaining({
            attempt: "01",
            focusFile: "src/Main.java",
            title: "Low finding",
            severity: "LOW",
            accepted: true,
          }),
        ],
      },
      artifacts: {
        statusOk: true,
        exploreDir: runDir,
      },
    });
    expect(manifest.nextCommands).toEqual(
      expect.arrayContaining([
        "deepsec explore status --project-id fixture --run-id run-1",
        "deepsec explore ci --project-id fixture --run-id run-1 --min-severity MEDIUM",
      ]),
    );

    logs.splice(0);
    process.exitCode = undefined;
    await exploreVerifyManifestCommand({
      manifest: manifestOut,
      json: true,
    });
    const cleanVerification = JSON.parse(logs.splice(0).join("\n"));
    expect(process.exitCode).toBeUndefined();
    expect(cleanVerification).toMatchObject({
      version: 1,
      manifestPath: manifestOut,
      projectId: "fixture",
      runId: "run-1",
      ok: true,
      problems: [],
    });
    expect(cleanVerification.checkedArtifacts).toBeGreaterThan(0);
    expect(cleanVerification.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "events",
          status: "ok",
          actualExists: true,
          actualSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
      ]),
    );

    const evidenceOut = path.join(dataRoot, "evidence.md");
    process.exitCode = undefined;
    await exploreEvidenceCommand({
      manifest: manifestOut,
      out: evidenceOut,
    });
    expect(process.exitCode).toBeUndefined();
    expect(fs.readFileSync(evidenceOut, "utf-8")).toContain("# DeepSec Explore Evidence");
    expect(fs.readFileSync(evidenceOut, "utf-8")).toContain("Low finding");
    expect(fs.readFileSync(evidenceOut, "utf-8")).toContain("Manifest verification: ok");

    logs.splice(0);
    process.exitCode = undefined;
    await exploreEvidenceCommand({
      manifest: manifestOut,
      json: true,
    });
    const evidenceJson = JSON.parse(logs.splice(0).join("\n"));
    expect(process.exitCode).toBeUndefined();
    expect(evidenceJson).toMatchObject({
      version: 1,
      projectId: "fixture",
      runId: "run-1",
      verificationOk: true,
      counts: {
        findings: 1,
        accepted: 1,
        artifactProblems: 0,
      },
      findings: [
        expect.objectContaining({
          title: "Low finding",
          accepted: true,
        }),
      ],
    });

    const bundleDir = path.join(dataRoot, "bundle");
    logs.splice(0);
    process.exitCode = undefined;
    await exploreBundleCommand({
      manifest: manifestOut,
      outDir: bundleDir,
      includeAttempts: true,
      json: true,
    });
    const bundle = JSON.parse(logs.splice(0).join("\n"));
    expect(process.exitCode).toBeUndefined();
    expect(bundle).toMatchObject({
      version: 1,
      projectId: "fixture",
      runId: "run-1",
      bundleDir,
      includeAttempts: true,
      verification: {
        ok: true,
        problems: [],
      },
      files: {
        manifest: "manifest.json",
        evidenceMarkdown: "evidence.md",
        evidenceJson: "evidence.json",
        provenance: "provenance.json",
        checksums: "checksums.sha256",
      },
    });
    expect(fs.existsSync(path.join(bundleDir, "manifest.json"))).toBe(true);
    expect(fs.existsSync(path.join(bundleDir, "evidence.md"))).toBe(true);
    expect(fs.existsSync(path.join(bundleDir, "evidence.json"))).toBe(true);
    expect(fs.existsSync(path.join(bundleDir, "provenance.json"))).toBe(true);
    expect(fs.existsSync(path.join(bundleDir, "bundle-index.json"))).toBe(true);
    expect(fs.existsSync(path.join(bundleDir, "checksums.sha256"))).toBe(true);
    const provenance = JSON.parse(
      fs.readFileSync(path.join(bundleDir, "provenance.json"), "utf-8"),
    );
    expect(provenance).toMatchObject({
      version: 1,
      tool: {
        name: "deepsec",
        version: expect.any(String),
        node: process.version,
        platform: process.platform,
        arch: process.arch,
      },
      source: {
        manifestPath: manifestOut,
        projectId: "fixture",
        runId: "run-1",
      },
      bundle: {
        includeAttempts: true,
        verificationOk: true,
      },
    });
    expect(provenance.source.manifestSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(provenance.source.manifestBytes).toBeGreaterThan(0);
    expect(provenance.bundle.checkedArtifacts).toBeGreaterThan(0);
    expect(bundle.copiedArtifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "events",
          bundlePath: expect.stringContaining("events-events.jsonl"),
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
      ]),
    );
    expect(bundle.skippedArtifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "report-json",
          reason: "artifact was not present when manifest was generated",
        }),
      ]),
    );
    expect(bundle.coreFiles).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "manifest",
          bundlePath: "manifest.json",
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
        expect.objectContaining({
          kind: "evidence-markdown",
          bundlePath: "evidence.md",
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
        expect.objectContaining({
          kind: "provenance",
          bundlePath: "provenance.json",
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
      ]),
    );

    logs.splice(0);
    process.exitCode = undefined;
    await exploreVerifyBundleCommand({
      bundleDir,
      json: true,
    });
    const cleanBundleVerification = JSON.parse(logs.splice(0).join("\n"));
    expect(process.exitCode).toBeUndefined();
    expect(cleanBundleVerification).toMatchObject({
      version: 1,
      bundleDir,
      projectId: "fixture",
      runId: "run-1",
      ok: true,
      problems: [],
    });
    expect(cleanBundleVerification.checkedFiles).toBeGreaterThan(0);

    const bundledEvidenceMarkdown = fs.readFileSync(path.join(bundleDir, "evidence.md"), "utf-8");
    fs.appendFileSync(path.join(bundleDir, "evidence.md"), "tampered\n");
    process.exitCode = undefined;
    await exploreVerifyBundleCommand({
      bundleDir,
      json: true,
    });
    const tamperedCoreBundleVerification = JSON.parse(logs.splice(0).join("\n"));
    expect(process.exitCode).toBe(1);
    expect(tamperedCoreBundleVerification.ok).toBe(false);
    expect(tamperedCoreBundleVerification.problems).toEqual(
      expect.arrayContaining([
        expect.stringContaining("evidence-markdown changed at evidence.md"),
        expect.stringContaining("checksums mismatch for evidence.md"),
      ]),
    );
    fs.writeFileSync(path.join(bundleDir, "evidence.md"), bundledEvidenceMarkdown);
    process.exitCode = undefined;

    const bundledProvenance = fs.readFileSync(path.join(bundleDir, "provenance.json"), "utf-8");
    fs.appendFileSync(path.join(bundleDir, "provenance.json"), "tampered\n");
    process.exitCode = undefined;
    await exploreVerifyBundleCommand({
      bundleDir,
      json: true,
    });
    const tamperedProvenanceVerification = JSON.parse(logs.splice(0).join("\n"));
    expect(process.exitCode).toBe(1);
    expect(tamperedProvenanceVerification.ok).toBe(false);
    expect(tamperedProvenanceVerification.problems).toEqual(
      expect.arrayContaining([
        expect.stringContaining("provenance changed at provenance.json"),
        expect.stringContaining("checksums mismatch for provenance.json"),
      ]),
    );
    fs.writeFileSync(path.join(bundleDir, "provenance.json"), bundledProvenance);
    process.exitCode = undefined;

    const copiedEvents = bundle.copiedArtifacts.find(
      (artifact: { kind: string }) => artifact.kind === "events",
    );
    expect(copiedEvents?.bundlePath).toBeTruthy();
    fs.appendFileSync(path.join(bundleDir, copiedEvents.bundlePath), "tampered\n");
    process.exitCode = undefined;
    await exploreVerifyBundleCommand({
      bundleDir,
      json: true,
    });
    const tamperedBundleVerification = JSON.parse(logs.splice(0).join("\n"));
    expect(process.exitCode).toBe(1);
    expect(tamperedBundleVerification.ok).toBe(false);
    expect(tamperedBundleVerification.problems).toEqual(
      expect.arrayContaining([
        expect.stringContaining("events changed at"),
        expect.stringContaining("checksums mismatch for"),
      ]),
    );

    fs.appendFileSync(
      path.join(runDir, "attempts", "01", "events.jsonl"),
      `${JSON.stringify({ type: "tampered" })}\n`,
    );
    process.exitCode = undefined;
    await exploreVerifyManifestCommand({
      manifest: manifestOut,
      json: true,
    });
    const tamperedVerification = JSON.parse(logs.splice(0).join("\n"));
    expect(process.exitCode).toBe(1);
    expect(tamperedVerification.ok).toBe(false);
    expect(tamperedVerification.problems).toEqual([expect.stringContaining("events changed at")]);
    expect(tamperedVerification.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "events",
          status: "mismatch",
        }),
      ]),
    );
  });

  it("flags inconsistent explore metadata and contradictory attempt artifacts", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "wrong-project",
        runId: "wrong-run",
        generatedAt: "now",
        model: "stub",
        rankings: [{ filePath: "src/Main.java", score: 5, reason: "parser" }],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({
        attempts: 1,
        completedAttempts: 1,
        failedAttempts: 0,
        bugsReported: 1,
        acceptedFindings: 1,
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/Main.java",
        model: "stub",
        startedAt: "start",
        completedAt: "end",
        turns: 1,
        container: hardenedContainer(),
        transcript: [],
        report: { outcome: "no-bug", summary: "checked" },
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt-error.json"),
      JSON.stringify({
        projectId: "wrong-project",
        runId: "wrong-run",
        focusFile: "src/Main.java",
        model: "stub",
        failedAt: "now",
        error: "stale failure from a previous attempt",
        container: hardenedContainer(),
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
    );

    const status = summarizeExploreRun("fixture", "run-1");

    expect(status.ok).toBe(false);
    expect(status.problems).toEqual(
      expect.arrayContaining([
        "rankings.projectId does not match",
        "rankings.runId does not match",
        "summary.bugsReported=1 but found 0 bug attempts",
        "summary.acceptedFindings=1 but found 0 accepted findings",
        "attempt 01: attempt.json and attempt-error.json are both present",
        "attempt 01: attempt-error.projectId does not match",
        "attempt 01: attempt-error.runId does not match",
        "attempt 01: workspace-changes.json is missing or invalid",
      ]),
    );
  });

  it("runs CI wrapper exports and applies min-severity gate", async () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-ci-"));
    const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-ci-root-"));
    tempRoots.push(dataRoot, projectRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    ensureProject("fixture", projectRoot);
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        rankings: [{ filePath: "src/Main.java", score: 5, reason: "parser" }],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({
        attempts: 1,
        completedAttempts: 1,
        failedAttempts: 0,
        bugsReported: 1,
        acceptedFindings: 1,
      }),
    );
    writeWorkspaceChanges(runDir);
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/Main.java",
        model: "stub",
        startedAt: "start",
        completedAt: "end",
        turns: 2,
        container: hardenedContainer(),
        transcript: [{ role: "tool", content: { command: "echo bug" } }],
        report: {
          outcome: "bug",
          title: "Low finding",
          severity: "LOW",
          confidence: "high",
          vulnSlug: "low-bug",
          lineNumbers: [12],
          description: "desc",
          recommendation: "fix",
          reproductionSteps: ["run local repro"],
          evidence: ["evidence"],
        },
        validation: {
          verdict: "true-positive",
          reproducible: true,
          interesting: true,
          reasoning: "confirmed in fresh container",
        },
        validationContainer: hardenedContainer(),
        validationTranscript: [{ role: "tool", content: { command: "grep marker" } }],
        validationTurns: 2,
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "validation-events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n${JSON.stringify({ type: "final", turn: 2 })}\n`,
    );
    writeFileRecord({
      projectId: "fixture",
      filePath: "src/Main.java",
      candidates: [],
      lastScannedAt: new Date().toISOString(),
      lastScannedRunId: "run-1",
      fileHash: "hash",
      findings: [
        {
          severity: "LOW",
          vulnSlug: "low-bug",
          title: "Low finding",
          description: "desc",
          lineNumbers: [12],
          recommendation: "fix",
          confidence: "high",
          producedByRunId: "run-1",
          revalidation: {
            verdict: "true-positive",
            reasoning: "confirmed",
            revalidatedAt: new Date().toISOString(),
            runId: "run-1",
            model: "stub",
          },
        },
      ],
      analysisHistory: [
        {
          runId: "run-1",
          investigatedAt: new Date().toISOString(),
          durationMs: 10,
          agentType: "openrouter-explore",
          model: "stub",
          modelConfig: { mode: "explore" },
          findingCount: 1,
          phase: "process",
        },
      ],
      status: "analyzed",
    });
    vi.spyOn(console, "log").mockImplementation(() => {});
    const outDir = path.join(dataRoot, "ci-out");

    process.exitCode = undefined;
    await exploreCiCommand({
      projectId: "fixture",
      runId: "run-1",
      minSeverity: "MEDIUM",
      outDir,
    });

    expect(process.exitCode).toBeUndefined();
    expect(fs.existsSync(reportJsonPath("fixture", "run-1"))).toBe(true);
    expect(JSON.parse(fs.readFileSync(path.join(outDir, "findings.json"), "utf-8"))).toHaveLength(
      1,
    );
    const sarif = JSON.parse(fs.readFileSync(path.join(outDir, "findings.sarif"), "utf-8"));
    expect(sarif.runs[0].results).toHaveLength(1);
    const passingJunit = fs.readFileSync(path.join(outDir, "junit.xml"), "utf-8");
    expect(passingJunit).toContain('<testsuites tests="2" failures="0" skipped="0">');
    expect(passingJunit).toContain('name="accepted finding gate"');
    const passingSummary = JSON.parse(
      fs.readFileSync(path.join(outDir, "ci-summary.json"), "utf-8"),
    );
    expect(passingSummary).toMatchObject({
      version: 1,
      projectId: "fixture",
      runId: "run-1",
      statusOk: true,
      exitCode: 0,
      gate: {
        failOnAcceptedFindings: true,
        minSeverity: "MEDIUM",
        acceptedFindingsAtOrAboveMinSeverity: 0,
        totalAcceptedFindings: 1,
      },
      outputs: {
        outDir,
        summaryJson: path.join(outDir, "ci-summary.json"),
        findingsJson: path.join(outDir, "findings.json"),
        findingsSarif: path.join(outDir, "findings.sarif"),
        junitXml: path.join(outDir, "junit.xml"),
      },
    });
    expect(passingSummary.findings.accepted).toEqual([
      expect.objectContaining({
        attemptDir: "01",
        focusFile: "src/Main.java",
        title: "Low finding",
        severity: "LOW",
        confidence: "high",
        vulnSlug: "low-bug",
        lineNumbers: [12],
        validationVerdict: "true-positive",
        thresholdMatched: false,
      }),
    ]);
    expect(passingSummary.findings.acceptedAtOrAboveMinSeverity).toEqual([]);
    expect(passingSummary.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "report-json",
          exists: true,
          bytes: expect.any(Number),
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
        expect.objectContaining({
          kind: "report-markdown",
          exists: true,
          bytes: expect.any(Number),
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
        expect.objectContaining({
          kind: "findings-json",
          exists: true,
          bytes: expect.any(Number),
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
        expect.objectContaining({
          kind: "findings-sarif",
          exists: true,
          bytes: expect.any(Number),
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
        expect.objectContaining({
          kind: "junit-xml",
          exists: true,
          bytes: expect.any(Number),
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
      ]),
    );
    expect(fs.existsSync(path.join(runDir, "ci-out"))).toBe(false);

    process.exitCode = undefined;
    await exploreCiCommand({
      projectId: "fixture",
      runId: "run-1",
      minSeverity: "LOW",
      outDir,
      report: false,
      exportJson: false,
      exportSarif: false,
    });

    expect(process.exitCode).toBe(2);
    const failingJunit = fs.readFileSync(path.join(outDir, "junit.xml"), "utf-8");
    expect(failingJunit).toContain('<testsuites tests="2" failures="1" skipped="0">');
    expect(failingJunit).toContain("accepted findings at or above LOW");
    const failingSummary = JSON.parse(
      fs.readFileSync(path.join(outDir, "ci-summary.json"), "utf-8"),
    );
    expect(failingSummary).toMatchObject({
      statusOk: true,
      exitCode: 2,
      gate: {
        minSeverity: "LOW",
        acceptedFindingsAtOrAboveMinSeverity: 1,
        totalAcceptedFindings: 1,
      },
    });
    expect(failingSummary.findings.acceptedAtOrAboveMinSeverity).toEqual([
      expect.objectContaining({
        title: "Low finding",
        severity: "LOW",
        thresholdMatched: true,
      }),
    ]);
    expect(failingSummary.artifacts).toEqual([
      expect.objectContaining({
        kind: "junit-xml",
        exists: true,
        bytes: expect.any(Number),
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      }),
    ]);
    expect(failingSummary.outputs.findingsJson).toBeUndefined();
    expect(failingSummary.outputs.findingsSarif).toBeUndefined();
    expect(failingSummary.outputs.junitXml).toBe(path.join(outDir, "junit.xml"));
  });

  it("summarizes failed attempts from attempt-error metadata", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify(hardenedContainer()),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        rankings: [{ filePath: "src/DeniedParser.java", score: 5, reason: "parser" }],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "summary.json"),
      JSON.stringify({
        attempts: 1,
        completedAttempts: 0,
        failedAttempts: 1,
        bugsReported: 0,
        acceptedFindings: 0,
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt-error.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/DeniedParser.java",
        model: "stub",
        failedAt: "now",
        error: "Denied container command: network tools.",
        container: hardenedContainer(),
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "events.jsonl"),
      `${JSON.stringify({ type: "model-request", turn: 1 })}\n`,
    );

    const status = summarizeExploreRun("fixture", "run-1");

    expect(status.ok).toBe(false);
    expect(status.summary?.failedAttempts).toBe(1);
    expect(status.attempts[0]).toMatchObject({
      failed: true,
      focusFile: "src/DeniedParser.java",
      error: "Denied container command: network tools.",
      runtime: "runsc",
      networkMode: "none",
    });
    expect(status.attempts[0]?.problems).toEqual([
      "attempt-error.json present: Denied container command: network tools.",
    ]);
  });

  it("flags broken explore sandbox artifacts", async () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-status-"));
    tempRoots.push(dataRoot);
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    const runDir = path.join(dataRoot, "fixture", "explore", "run-1");
    fs.mkdirSync(path.join(runDir, "attempts", "01"), { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "metadata.json"),
      JSON.stringify({ projectId: "fixture", runId: "run-1" }),
    );
    fs.writeFileSync(
      path.join(runDir, "ranking-container.json"),
      JSON.stringify({
        ...hardenedContainer(),
        runtime: "runc",
        networkMode: "bridge",
        readOnlyRootfs: false,
        noNewPrivileges: false,
        capDropAll: false,
        privileged: true,
        pidsLimit: 0,
        memoryBytes: 0,
        nanoCpus: 0,
        mountDestinations: ["/var/run/docker.sock"],
      }),
    );
    fs.writeFileSync(
      path.join(runDir, "rankings.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        generatedAt: "now",
        model: "stub",
        rankings: [{ filePath: "src/Main.java", score: 9, reason: "bad" }],
      }),
    );
    fs.writeFileSync(path.join(runDir, "summary.json"), JSON.stringify({ attempts: 2 }));
    fs.writeFileSync(
      path.join(runDir, "attempts", "01", "attempt.json"),
      JSON.stringify({
        projectId: "fixture",
        runId: "run-1",
        focusFile: "src/Main.java",
        model: "stub",
        startedAt: "start",
        completedAt: "end",
        turns: 1,
        container: {
          ...hardenedContainer(),
          runtime: "runc",
          networkMode: "bridge",
          readOnlyRootfs: false,
          noNewPrivileges: false,
          capDropAll: false,
          privileged: true,
          pidsLimit: 0,
          memoryBytes: 0,
          nanoCpus: 0,
          mountDestinations: ["/run/docker.sock"],
        },
        transcript: [],
        report: { outcome: "no-bug", summary: "checked" },
      }),
    );

    const status = summarizeExploreRun("fixture", "run-1");

    expect(status.ok).toBe(false);
    expect(exploreStatusExitCode(status, { failOnAcceptedFindings: true })).toBe(1);
    expect(status.problems).toEqual(
      expect.arrayContaining([
        "ranking container runtime is runc",
        "ranking container network is bridge",
        "ranking container rootfs is not read-only",
        "ranking container no-new-privileges is not enabled",
        "ranking container did not drop all capabilities",
        "ranking container privileged flag is true",
        "ranking container pids limit is 0",
        "ranking container memory limit is 0",
        "ranking container cpu limit is 0",
        "ranking container mounted a Docker socket",
        "rankings.json contains scores outside 1-5",
        "summary.attempts=2 but found 1 attempt dirs",
        "attempt 01: events.jsonl is missing or empty",
        "attempt 01: workspace-changes.json is missing or invalid",
        "attempt 01: container runtime is runc",
        "attempt 01: container network is bridge",
        "attempt 01: container rootfs is not read-only",
        "attempt 01: container no-new-privileges is not enabled",
        "attempt 01: container did not drop all capabilities",
        "attempt 01: container privileged flag is true",
        "attempt 01: container pids limit is 0",
        "attempt 01: container memory limit is 0",
        "attempt 01: container cpu limit is 0",
        "attempt 01: container mounted a Docker socket",
      ]),
    );

    vi.spyOn(console, "log").mockImplementation(() => {});
    const outDir = path.join(dataRoot, "ci-broken");
    process.exitCode = undefined;
    await exploreCiCommand({
      projectId: "fixture",
      runId: "run-1",
      outDir,
    });

    expect(process.exitCode).toBe(1);
    const brokenJunit = fs.readFileSync(path.join(outDir, "junit.xml"), "utf-8");
    expect(brokenJunit).toContain('<testsuites tests="2" failures="1" skipped="1">');
    expect(brokenJunit).toContain("explore artifact validation failed");
    const ciSummary = JSON.parse(fs.readFileSync(path.join(outDir, "ci-summary.json"), "utf-8"));
    expect(ciSummary).toMatchObject({
      statusOk: false,
      exitCode: 1,
      outputs: {
        outDir,
        summaryJson: path.join(outDir, "ci-summary.json"),
      },
    });
    expect(ciSummary.problems).toEqual(
      expect.arrayContaining(["ranking container runtime is runc"]),
    );
    expect(ciSummary.artifacts).toEqual([
      expect.objectContaining({
        kind: "junit-xml",
        exists: true,
        bytes: expect.any(Number),
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      }),
    ]);
    expect(ciSummary.outputs.findingsJson).toBeUndefined();
    expect(ciSummary.outputs.findingsSarif).toBeUndefined();
    expect(ciSummary.outputs.junitXml).toBe(path.join(outDir, "junit.xml"));
  });
});
