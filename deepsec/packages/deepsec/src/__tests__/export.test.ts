import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensureProject, writeFileRecord } from "@deepsec/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { exportCommand } from "../commands/export.js";

let cleanup: (() => void) | null = null;
const originalDataRoot = process.env.DEEPSEC_DATA_ROOT;

afterEach(() => {
  cleanup?.();
  cleanup = null;
  if (originalDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
  else process.env.DEEPSEC_DATA_ROOT = originalDataRoot;
  vi.restoreAllMocks();
});

function setupProject(): { projectId: string; runId: string; out: string } {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-export-"));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-export-root-"));
  process.env.DEEPSEC_DATA_ROOT = dataRoot;
  cleanup = () => {
    fs.rmSync(dataRoot, { recursive: true, force: true });
    fs.rmSync(root, { recursive: true, force: true });
  };
  const projectId = `export-${Date.now().toString(36)}`;
  const runId = "20260612190428-873fbf0d15d1ce0b";
  ensureProject(projectId, root);
  return { projectId, runId, out: path.join(dataRoot, "deepsec.sarif") };
}

describe("exportCommand()", () => {
  it("exports SARIF for filtered findings", async () => {
    const { projectId, runId, out } = setupProject();
    vi.spyOn(console, "log").mockImplementation(() => {});

    writeFileRecord({
      projectId,
      filePath: "src/main/java/Parser.java",
      candidates: [],
      lastScannedAt: new Date().toISOString(),
      lastScannedRunId: runId,
      fileHash: "hash",
      findings: [
        {
          severity: "HIGH",
          vulnSlug: "parser-boundary-bypass",
          title: "Parser boundary bypass",
          description: "A parser accepts input past the intended boundary.",
          lineNumbers: [42, 43],
          recommendation: "Reject data past the boundary.",
          confidence: "high",
          producedByRunId: runId,
          revalidation: {
            verdict: "true-positive",
            reasoning: "Reproduced locally.",
            revalidatedAt: new Date().toISOString(),
            runId,
            model: "anthropic/claude-opus-4.8",
          },
        },
      ],
      analysisHistory: [
        {
          runId,
          investigatedAt: "2026-06-12T19:10:18.817Z",
          durationMs: 100,
          agentType: "openrouter-explore",
          model: "anthropic/claude-opus-4.8",
          modelConfig: { mode: "explore" },
          findingCount: 1,
          phase: "process",
        },
      ],
      status: "analyzed",
    });

    writeFileRecord({
      projectId,
      filePath: "src/main/java/OldParser.java",
      candidates: [],
      lastScannedAt: new Date().toISOString(),
      lastScannedRunId: "old-run",
      fileHash: "old-hash",
      findings: [
        {
          severity: "CRITICAL",
          vulnSlug: "old-parser-bug",
          title: "Old parser bug",
          description: "This older finding must not appear in a run-scoped export.",
          lineNumbers: [7],
          recommendation: "Fix the old parser.",
          confidence: "high",
          producedByRunId: "old-run",
          revalidation: {
            verdict: "true-positive",
            reasoning: "Older local repro.",
            revalidatedAt: new Date().toISOString(),
            runId: "old-run",
            model: "anthropic/claude-opus-4.8",
          },
        },
      ],
      analysisHistory: [
        {
          runId: "old-run",
          investigatedAt: "2026-06-11T19:10:18.817Z",
          durationMs: 100,
          agentType: "openrouter-explore",
          model: "anthropic/claude-opus-4.8",
          modelConfig: { mode: "explore" },
          findingCount: 1,
          phase: "process",
        },
      ],
      status: "analyzed",
    });

    await exportCommand({ projectId, format: "sarif", out, onlyTruePositive: true, runId });

    const sarif = JSON.parse(fs.readFileSync(out, "utf-8"));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.name).toBe("DeepSec");
    expect(sarif.runs[0].tool.driver.rules[0]).toMatchObject({
      id: "parser-boundary-bypass",
      properties: {
        precision: "high",
        "security-severity": "8.0",
      },
    });
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0]).toMatchObject({
      ruleId: "parser-boundary-bypass",
      level: "error",
      message: { text: "[HIGH] Parser boundary bypass" },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: "src/main/java/Parser.java",
              uriBaseId: "PROJECTROOT",
            },
            region: {
              startLine: 42,
              endLine: 43,
            },
          },
        },
      ],
      properties: {
        projectId,
        severity: "HIGH",
        confidence: "high",
        runId,
        revalidation: {
          verdict: "true-positive",
          reasoning: "Reproduced locally.",
        },
      },
    });
  });
});
