import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensureProject, reportJsonPath, reportMdPath, writeFileRecord } from "@deepsec/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { reportCommand } from "../commands/report.js";

let cleanup: (() => void) | null = null;
const originalDataRoot = process.env.DEEPSEC_DATA_ROOT;

afterEach(() => {
  cleanup?.();
  cleanup = null;
  if (originalDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
  else process.env.DEEPSEC_DATA_ROOT = originalDataRoot;
  vi.restoreAllMocks();
});

function setupProject(): { projectId: string; runId: string } {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-report-"));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-report-root-"));
  process.env.DEEPSEC_DATA_ROOT = dataRoot;
  cleanup = () => {
    fs.rmSync(dataRoot, { recursive: true, force: true });
    fs.rmSync(root, { recursive: true, force: true });
  };
  const projectId = `report-${Date.now().toString(36)}`;
  const runId = "20260612190428-873fbf0d15d1ce0b";
  ensureProject(projectId, root);
  return { projectId, runId };
}

describe("reportCommand()", () => {
  it("includes low-severity findings in run-scoped report totals and markdown", async () => {
    const { projectId, runId } = setupProject();
    vi.spyOn(console, "log").mockImplementation(() => {});

    writeFileRecord({
      projectId,
      filePath: "src/parser.java",
      candidates: [],
      lastScannedAt: new Date().toISOString(),
      lastScannedRunId: runId,
      fileHash: "hash",
      findings: [
        {
          severity: "CRITICAL",
          vulnSlug: "old-parser-bug",
          title: "Older parser finding",
          description: "This finding came from an older run.",
          lineNumbers: [99],
          recommendation: "Fix the older parser issue.",
          confidence: "high",
          producedByRunId: "old-run",
          revalidation: {
            verdict: "true-positive",
            reasoning: "Validated by older local evidence.",
            revalidatedAt: new Date().toISOString(),
            runId: "old-run",
            model: "anthropic/claude-opus-4.8",
          },
        },
        {
          severity: "LOW",
          vulnSlug: "low-parser-integrity",
          title: "Low severity parser finding",
          description: "A low severity finding should still be visible in reports.",
          lineNumbers: [12],
          recommendation: "Fix the parser boundary condition.",
          confidence: "high",
          producedByRunId: runId,
          revalidation: {
            verdict: "true-positive",
            reasoning: "Validated by local evidence.",
            revalidatedAt: new Date().toISOString(),
            runId,
            model: "anthropic/claude-opus-4.8",
          },
        },
      ],
      analysisHistory: [
        {
          runId: "old-run",
          investigatedAt: new Date().toISOString(),
          durationMs: 100,
          agentType: "openrouter-explore",
          model: "anthropic/claude-opus-4.8",
          modelConfig: { mode: "explore" },
          findingCount: 1,
          phase: "process",
        },
        {
          runId,
          investigatedAt: new Date().toISOString(),
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

    await reportCommand({ projectId, runId });

    const reportJson = JSON.parse(fs.readFileSync(reportJsonPath(projectId, runId), "utf-8"));
    expect(reportJson.summary.totalFindings).toBe(1);
    expect(reportJson.summary.critical).toBe(0);
    expect(reportJson.summary.low).toBe(1);
    expect(reportJson.files[0].findings).toHaveLength(1);
    expect(reportJson.files[0].findings[0].title).toBe("Low severity parser finding");
    expect(reportJson.files[0].analysisHistory).toHaveLength(1);
    expect(reportJson.files[0].analysisHistory[0].runId).toBe(runId);

    const markdown = fs.readFileSync(reportMdPath(projectId, runId), "utf-8");
    expect(markdown).toContain("| LOW | 1 |");
    expect(markdown).toContain("| CRITICAL | 0 |");
    expect(markdown).toContain("## LOW (1)");
    expect(markdown).toContain("Low severity parser finding");
    expect(markdown).not.toContain("Older parser finding");
  });
});
