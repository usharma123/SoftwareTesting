import fs from "node:fs";
import path from "node:path";
import { assertSafeSegment, type Confidence, dataDir, type Severity } from "@deepsec/core";
import { type ExploreIntegrityStatus, verifyExploreIntegrityManifest } from "./integrity.js";
import {
  type ContainerMetadata,
  EXPLORE_RUNTIME,
  type ExploreAttempt,
  type ExploreAttemptFailure,
  type ModelUsage,
  type StoredRankings,
} from "./types.js";
import { sumModelUsages } from "./usage.js";

export interface ExploreAttemptStatus {
  index: number;
  dirName: string;
  focusFile?: string;
  outcome?: string;
  runtime?: string;
  networkMode?: string;
  readOnlyRootfs?: boolean;
  noNewPrivileges?: boolean;
  capDropAll?: boolean;
  privileged?: boolean;
  pidsLimit?: number;
  memoryBytes?: number;
  nanoCpus?: number;
  copyExcludedCount?: number;
  copyExcludedPaths?: string[];
  turns?: number;
  toolEvents: number;
  eventCount: number;
  bugTitle?: string;
  bugSeverity?: Severity;
  bugConfidence?: Confidence;
  vulnSlug?: string;
  lineNumbers?: number[];
  acceptedFinding?: boolean;
  validationVerdict?: string;
  usage?: ModelUsage;
  inputTokens?: number;
  outputTokens?: number;
  costUsd?: number;
  validationRuntime?: string;
  validationNetworkMode?: string;
  validationTurns?: number;
  validationToolEvents: number;
  validationEventCount: number;
  workspaceChanges?: number;
  workspaceChangesCaptured?: number;
  failed: boolean;
  error?: string;
  problems: string[];
}

export interface ExploreRunSummaryStatus {
  attempts?: number;
  completedAttempts?: number;
  failedAttempts?: number;
  bugsReported?: number;
  acceptedFindings?: number;
  completedAt?: string;
  rankingUsage?: ModelUsage;
  attemptUsage?: ModelUsage;
  usage?: ModelUsage;
}

export interface ExploreRunStatus {
  projectId: string;
  runId: string;
  exploreDir: string;
  ok: boolean;
  problems: string[];
  rankingsCount: number;
  rankingScoreMin?: number;
  rankingScoreMax?: number;
  topRankedFiles: Array<{ filePath: string; score: number; reason: string }>;
  attempts: ExploreAttemptStatus[];
  summary?: ExploreRunSummaryStatus;
  integrity?: ExploreIntegrityStatus;
}

export function latestExploreRunId(projectId: string): string {
  const exploreRoot = path.join(dataDir(projectId), "explore");
  if (!fs.existsSync(exploreRoot)) {
    throw new Error(`No explore runs found for project ${projectId}.`);
  }
  const runIds = fs
    .readdirSync(exploreRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  const latest = runIds.at(-1);
  if (!latest) throw new Error(`No explore runs found for project ${projectId}.`);
  assertSafeSegment(latest, "runId");
  return latest;
}

export function summarizeExploreRun(projectId: string, runId: string): ExploreRunStatus {
  assertSafeSegment(runId, "runId");
  const exploreDir = path.join(dataDir(projectId), "explore", runId);
  if (!fs.existsSync(exploreDir)) {
    throw new Error(`Explore run ${runId} does not exist for project ${projectId}.`);
  }

  const problems: string[] = [];
  const metadata = readJson<Record<string, unknown>>(path.join(exploreDir, "metadata.json"));
  if (!metadata) {
    problems.push("metadata.json is missing or invalid");
  } else {
    if (metadata.projectId !== projectId) problems.push("metadata.projectId does not match");
    if (metadata.runId !== runId) problems.push("metadata.runId does not match");
  }

  const rankingContainer = readJson<Record<string, unknown>>(
    path.join(exploreDir, "ranking-container.json"),
  );
  if (!rankingContainer) {
    problems.push("ranking-container.json is missing or invalid");
  } else {
    problems.push(...containerIsolationProblems("ranking container", rankingContainer));
  }

  const rankings = readJson<StoredRankings>(path.join(exploreDir, "rankings.json"));
  const rankedFiles = Array.isArray(rankings?.rankings) ? rankings.rankings : [];
  if (rankedFiles.length === 0) problems.push("rankings.json contains no rankings");
  if (rankings) {
    if (rankings.projectId !== projectId) problems.push("rankings.projectId does not match");
    if (rankings.runId !== runId) problems.push("rankings.runId does not match");
  }
  const scores = rankedFiles.map((r) => r.score).filter((score) => Number.isInteger(score));
  if (scores.some((score) => score < 1 || score > 5) || scores.length !== rankedFiles.length) {
    problems.push("rankings.json contains scores outside 1-5");
  }

  const summary = readJson<ExploreRunStatus["summary"]>(path.join(exploreDir, "summary.json"));
  if (!summary) problems.push("summary.json is missing or invalid");

  const integrity = verifyExploreIntegrityManifest(exploreDir);
  const requiresIntegrity = metadata?.integrityManifest === true;
  if (requiresIntegrity && !integrity.present) {
    problems.push("integrity-manifest.json is missing");
  }
  for (const problem of integrity.problems) {
    problems.push(problem);
  }

  const attempts = summarizeAttempts(path.join(exploreDir, "attempts"), projectId, runId);
  for (const attempt of attempts) {
    for (const problem of attempt.problems) {
      problems.push(`attempt ${attempt.dirName}: ${problem}`);
    }
  }
  if (summary?.attempts !== undefined && summary.attempts !== attempts.length) {
    problems.push(`summary.attempts=${summary.attempts} but found ${attempts.length} attempt dirs`);
  }
  const completedAttempts = attempts.filter((attempt) => !attempt.failed).length;
  const failedAttempts = attempts.filter((attempt) => attempt.failed).length;
  if (summary?.completedAttempts !== undefined && summary.completedAttempts !== completedAttempts) {
    problems.push(
      `summary.completedAttempts=${summary.completedAttempts} but found ${completedAttempts} completed attempts`,
    );
  }
  if (summary?.failedAttempts !== undefined && summary.failedAttempts !== failedAttempts) {
    problems.push(
      `summary.failedAttempts=${summary.failedAttempts} but found ${failedAttempts} failed attempts`,
    );
  }
  const bugsReported = attempts.filter((attempt) => attempt.outcome === "bug").length;
  if (summary?.bugsReported !== undefined && summary.bugsReported !== bugsReported) {
    problems.push(
      `summary.bugsReported=${summary.bugsReported} but found ${bugsReported} bug attempts`,
    );
  }
  const acceptedFindings = attempts.filter((attempt) => attempt.acceptedFinding).length;
  if (summary?.acceptedFindings !== undefined && summary.acceptedFindings !== acceptedFindings) {
    problems.push(
      `summary.acceptedFindings=${summary.acceptedFindings} but found ${acceptedFindings} accepted findings`,
    );
  }
  const attemptUsage = sumModelUsages(attempts.map((attempt) => attempt.usage));
  if (!sameUsage(summary?.rankingUsage, rankings?.usage)) {
    problems.push("summary.rankingUsage does not match rankings.usage");
  }
  if (!sameUsage(summary?.attemptUsage, attemptUsage)) {
    problems.push("summary.attemptUsage does not match attempt usage totals");
  }
  if (!sameUsage(summary?.usage, sumModelUsages([rankings?.usage, attemptUsage]))) {
    problems.push("summary.usage does not match ranking+attempt usage totals");
  }

  return {
    projectId,
    runId,
    exploreDir,
    ok: problems.length === 0,
    problems,
    rankingsCount: rankedFiles.length,
    rankingScoreMin: scores.length > 0 ? Math.min(...scores) : undefined,
    rankingScoreMax: scores.length > 0 ? Math.max(...scores) : undefined,
    topRankedFiles: rankedFiles.slice(0, 5).map((r) => ({
      filePath: r.filePath,
      score: r.score,
      reason: r.reason,
    })),
    attempts,
    summary: summary ?? undefined,
    integrity,
  };
}

function summarizeAttempts(
  attemptsDir: string,
  projectId: string,
  runId: string,
): ExploreAttemptStatus[] {
  if (!fs.existsSync(attemptsDir)) return [];
  return fs
    .readdirSync(attemptsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
    .map((dirName, index) =>
      summarizeAttempt(path.join(attemptsDir, dirName), dirName, index + 1, projectId, runId),
    );
}

function summarizeAttempt(
  attemptDir: string,
  dirName: string,
  index: number,
  projectId: string,
  runId: string,
): ExploreAttemptStatus {
  const problems: string[] = [];
  const attempt = readJson<ExploreAttempt>(path.join(attemptDir, "attempt.json"));
  const error = readJson<ExploreAttemptFailure>(path.join(attemptDir, "attempt-error.json"));
  const workspaceChanges = readJson<ExploreAttempt["workspaceChanges"]>(
    path.join(attemptDir, "workspace-changes.json"),
  );
  if (!attempt) {
    problems.push(
      error ? `attempt-error.json present: ${String(error.error)}` : "attempt.json is missing",
    );
  }
  if (attempt && error) {
    problems.push("attempt.json and attempt-error.json are both present");
  }
  if (attempt) {
    if (attempt.projectId !== projectId) problems.push("attempt.projectId does not match");
    if (attempt.runId !== runId) problems.push("attempt.runId does not match");
  }
  if (error) {
    if (error.projectId !== projectId) problems.push("attempt-error.projectId does not match");
    if (error.runId !== runId) problems.push("attempt-error.runId does not match");
  }
  if (attempt && !workspaceChanges) {
    problems.push("workspace-changes.json is missing or invalid");
  }
  if (attempt?.workspaceChanges && workspaceChanges) {
    if (attempt.workspaceChanges.totalChanges !== workspaceChanges.totalChanges) {
      problems.push("workspace-changes.json does not match attempt workspaceChanges summary");
    }
  }

  const eventsPath = path.join(attemptDir, "events.jsonl");
  const eventCount = fs.existsSync(eventsPath)
    ? fs.readFileSync(eventsPath, "utf-8").split(/\r?\n/).filter(Boolean).length
    : 0;
  if (eventCount === 0) problems.push("events.jsonl is missing or empty");

  const container = attempt?.container ?? error?.container;
  problems.push(...containerIsolationProblems("container", container));
  const validationEventsPath = path.join(attemptDir, "validation-events.jsonl");
  const validationEventCount = fs.existsSync(validationEventsPath)
    ? fs.readFileSync(validationEventsPath, "utf-8").split(/\r?\n/).filter(Boolean).length
    : 0;
  if (attempt?.report.outcome === "bug") {
    if (!attempt.validation) problems.push("bug report is missing validation verdict");
    if (!attempt.validationContainer) {
      problems.push("bug report is missing validation container metadata");
    } else {
      problems.push(
        ...containerIsolationProblems("validation container", attempt.validationContainer),
      );
    }
    if (validationEventCount === 0) problems.push("validation-events.jsonl is missing or empty");
  }

  return {
    index,
    dirName,
    focusFile: attempt?.focusFile ?? error?.focusFile,
    failed: !attempt,
    error: error?.error,
    outcome: attempt?.report.outcome,
    runtime: container?.runtime,
    networkMode: container?.networkMode,
    readOnlyRootfs: container?.readOnlyRootfs,
    noNewPrivileges: container?.noNewPrivileges,
    capDropAll: container?.capDropAll,
    privileged: container?.privileged,
    pidsLimit: container?.pidsLimit,
    memoryBytes: container?.memoryBytes,
    nanoCpus: container?.nanoCpus,
    copyExcludedCount: container?.copyExcludedCount,
    copyExcludedPaths: container?.copyExcludedPaths,
    turns: attempt?.turns,
    toolEvents: attempt?.transcript.filter((entry) => entry.role === "tool").length ?? 0,
    eventCount,
    bugTitle: attempt?.report.outcome === "bug" ? attempt.report.title : undefined,
    bugSeverity: attempt?.report.outcome === "bug" ? attempt.report.severity : undefined,
    bugConfidence: attempt?.report.outcome === "bug" ? attempt.report.confidence : undefined,
    vulnSlug: attempt?.report.outcome === "bug" ? attempt.report.vulnSlug : undefined,
    lineNumbers: attempt?.report.outcome === "bug" ? attempt.report.lineNumbers : undefined,
    acceptedFinding:
      attempt?.report.outcome === "bug"
        ? attempt.validation?.verdict === "true-positive" &&
          attempt.validation.reproducible &&
          attempt.validation.interesting
        : undefined,
    validationVerdict: attempt?.validation?.verdict,
    usage: attempt?.usage,
    inputTokens: attempt?.usage?.inputTokens,
    outputTokens: attempt?.usage?.outputTokens,
    costUsd: attempt?.usage?.costUsd,
    validationRuntime: attempt?.validationContainer?.runtime,
    validationNetworkMode: attempt?.validationContainer?.networkMode,
    validationTurns: attempt?.validationTurns,
    validationToolEvents:
      attempt?.validationTranscript?.filter((entry) => entry.role === "tool").length ?? 0,
    validationEventCount,
    workspaceChanges: workspaceChanges?.totalChanges ?? attempt?.workspaceChanges?.totalChanges,
    workspaceChangesCaptured:
      workspaceChanges?.capturedChanges ?? attempt?.workspaceChanges?.capturedChanges,
    problems,
  };
}

function containerIsolationProblems(
  label: string,
  container: Partial<ContainerMetadata> | Record<string, unknown> | undefined,
): string[] {
  const problems: string[] = [];
  if (!container) {
    problems.push(`${label} metadata is missing`);
    return problems;
  }
  if (container.runtime !== EXPLORE_RUNTIME) {
    problems.push(`${label} runtime is ${String(container.runtime)}`);
  }
  if (container.networkMode !== "none") {
    problems.push(`${label} network is ${String(container.networkMode)}`);
  }
  if (container.readOnlyRootfs !== true) {
    problems.push(`${label} rootfs is not read-only`);
  }
  if (container.noNewPrivileges !== true) {
    problems.push(`${label} no-new-privileges is not enabled`);
  }
  if (container.capDropAll !== true) {
    problems.push(`${label} did not drop all capabilities`);
  }
  if (container.privileged !== false) {
    problems.push(`${label} privileged flag is ${String(container.privileged)}`);
  }
  if (
    typeof container.pidsLimit !== "number" ||
    container.pidsLimit <= 0 ||
    container.pidsLimit > 512
  ) {
    problems.push(`${label} pids limit is ${String(container.pidsLimit)}`);
  }
  if (typeof container.memoryBytes !== "number" || container.memoryBytes <= 0) {
    problems.push(`${label} memory limit is ${String(container.memoryBytes)}`);
  }
  if (typeof container.nanoCpus !== "number" || container.nanoCpus <= 0) {
    problems.push(`${label} cpu limit is ${String(container.nanoCpus)}`);
  }
  const mountDestinations = Array.isArray(container.mountDestinations)
    ? container.mountDestinations
    : [];
  if (
    mountDestinations.some((dst) => dst === "/var/run/docker.sock" || dst === "/run/docker.sock")
  ) {
    problems.push(`${label} mounted a Docker socket`);
  }
  for (const required of [
    "/workspace/target",
    "/workspace/out",
    "/workspace/home",
    "/workspace/gradle-cache",
  ]) {
    if (!mountDestinations.includes(required)) {
      problems.push(`${label} missing mount ${required}`);
    }
  }
  return problems;
}

function sameUsage(a: ModelUsage | undefined, b: ModelUsage | undefined): boolean {
  if (a === undefined && b === undefined) return true;
  if (a === undefined || b === undefined) return false;
  if (a.inputTokens !== b.inputTokens || a.outputTokens !== b.outputTokens) return false;
  if (a.costUsd === undefined && b.costUsd === undefined) return true;
  if (a.costUsd === undefined || b.costUsd === undefined) return false;
  return Math.abs(a.costUsd - b.costUsd) <= 0.000_000_001;
}

function readJson<T>(file: string): T | null {
  try {
    return JSON.parse(fs.readFileSync(file, "utf-8")) as T;
  } catch {
    return null;
  }
}
