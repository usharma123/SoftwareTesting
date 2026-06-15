import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  type AnalysisEntry,
  type FileRecord,
  type Finding,
  readFileRecord,
  writeFileRecord,
} from "@deepsec/core";
import type { BugReport, ExploreAttempt, ValidationVerdict } from "./types.js";

export function mergeAcceptedExploreAttempt(args: {
  projectId: string;
  root: string;
  runId: string;
  model: string;
  attempt: ExploreAttempt;
}): boolean {
  const filePath = args.attempt.focusFile;
  const now = new Date().toISOString();
  const record =
    readFileRecord(args.projectId, filePath) ??
    createExploreFileRecord({
      projectId: args.projectId,
      root: args.root,
      filePath,
      runId: args.runId,
      now,
    });

  record.findings = record.findings.filter((finding) => finding.producedByRunId !== args.runId);

  const accepted = args.attempt.report.outcome === "bug" && isAccepted(args.attempt.validation);
  if (accepted && args.attempt.report.outcome === "bug") {
    const finding = findingFromBugReport(
      args.attempt.report,
      args.runId,
      args.model,
      args.attempt.validation!,
      now,
    );
    const signature = findingSignature(finding);
    if (!record.findings.some((existing) => findingSignature(existing) === signature)) {
      record.findings.push(finding);
    }
  }
  const historyEntry: AnalysisEntry = {
    runId: args.runId,
    investigatedAt: now,
    durationMs: Math.max(
      0,
      Date.parse(args.attempt.completedAt) - Date.parse(args.attempt.startedAt),
    ),
    agentType: "openrouter-explore",
    model: args.model,
    modelConfig: {
      mode: "explore",
      profile: "java11-gradle",
      runtime: args.attempt.container.runtime,
      networkMode: args.attempt.container.networkMode,
      outcome: args.attempt.report.outcome,
      validation: args.attempt.validation,
    },
    findingCount: accepted ? 1 : 0,
    numTurns: args.attempt.turns,
    phase: "process",
  };
  if (args.attempt.usage) {
    if (args.attempt.usage.costUsd !== undefined) historyEntry.costUsd = args.attempt.usage.costUsd;
    historyEntry.usage = {
      inputTokens: args.attempt.usage.inputTokens,
      outputTokens: args.attempt.usage.outputTokens,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
    };
  }
  record.analysisHistory = record.analysisHistory.filter((entry) => entry.runId !== args.runId);
  record.analysisHistory.push(historyEntry);
  record.status = "analyzed";
  delete record.lockedAt;
  delete record.lockedByRunId;
  writeFileRecord(record);
  return accepted;
}

export function isAccepted(validation: ValidationVerdict | undefined): boolean {
  return (
    validation?.verdict === "true-positive" && validation.reproducible && validation.interesting
  );
}

function createExploreFileRecord(args: {
  projectId: string;
  root: string;
  filePath: string;
  runId: string;
  now: string;
}): FileRecord {
  const full = path.join(args.root, args.filePath);
  let content = "";
  try {
    content = fs.readFileSync(full, "utf-8");
  } catch {}
  return {
    projectId: args.projectId,
    filePath: args.filePath,
    candidates: [
      {
        vulnSlug: "explore-focus",
        lineNumbers: [1],
        snippet: "AI-ranked local gVisor exploration target.",
        matchedPattern: "deepsec explore",
      },
    ],
    lastScannedAt: args.now,
    lastScannedRunId: args.runId,
    fileHash: crypto.createHash("sha256").update(content).digest("hex"),
    findings: [],
    analysisHistory: [],
    status: "pending",
  };
}

function findingFromBugReport(
  report: BugReport,
  runId: string,
  model: string,
  validation: ValidationVerdict,
  now: string,
): Finding {
  return {
    severity: validation.adjustedSeverity ?? report.severity,
    vulnSlug: report.vulnSlug,
    title: report.title,
    description: [
      report.description,
      "",
      "Local reproduction steps:",
      ...report.reproductionSteps.map((step) => `- ${step}`),
      "",
      "Evidence:",
      ...report.evidence.map((item) => `- ${item}`),
    ].join("\n"),
    lineNumbers: report.lineNumbers.length > 0 ? report.lineNumbers : [1],
    recommendation: report.recommendation,
    confidence: report.confidence,
    producedByRunId: runId,
    revalidation: {
      verdict: validation.verdict,
      reasoning: validation.reasoning,
      adjustedSeverity: validation.adjustedSeverity,
      revalidatedAt: now,
      runId,
      model,
    },
  };
}

function findingSignature(finding: Finding): string {
  return `${finding.vulnSlug}\0${finding.title}\0${finding.lineNumbers.join(",")}`;
}
