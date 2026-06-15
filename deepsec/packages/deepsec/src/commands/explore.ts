import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Severity } from "@deepsec/core";
import {
  assertSafeSegment,
  dataDir,
  ensureProject,
  generateRunId,
  parseSeverity,
  reportJsonPath,
  reportMdPath,
  severityAtOrAbove,
} from "@deepsec/core";
import { runAgenticExploreLoop, validateBugReport } from "../explore/agent-loop.js";
import { maybeBudgetModelClient } from "../explore/budget.js";
import {
  assertExploreImageExists,
  assertGradleCacheAvailable,
  assertRunscRegistered,
  createGvisorContainer,
} from "../explore/docker.js";
import { writeExploreIntegrityManifest } from "../explore/integrity.js";
import { checkOpenRouterModelReachability } from "../explore/model-check.js";
import { OpenRouterResponsesClient } from "../explore/openrouter.js";
import { rankingPrompt } from "../explore/prompts.js";
import {
  collectProductionFileSummariesFromRunner,
  normalizeRankings,
  parseRankingsFromText,
  selectTopRankedFiles,
} from "../explore/ranking.js";
import { isAccepted, mergeAcceptedExploreAttempt } from "../explore/records.js";
import { RANKING_RESPONSE_FORMAT } from "../explore/response-formats.js";
import { assertExploreProfile, setupExploreProfile } from "../explore/setup.js";
import {
  type ExploreRunStatus,
  latestExploreRunId,
  summarizeExploreRun,
} from "../explore/status.js";
import { StubExploreModelClient } from "../explore/stub-model.js";
import {
  EXPLORE_IMAGE,
  EXPLORE_RUNTIME,
  type ExploreAttempt,
  type ExploreAttemptFailure,
  type ExploreOptions,
  type ExploreProgressEvent,
  type ExploreSetupOptions,
  type ModelClient,
  type ModelUsage,
  OPENROUTER_DEFAULT_MODEL,
  type RankedFile,
  type SourceFileSummary,
  type StoredRankings,
  type ValidationResult,
} from "../explore/types.js";
import { addModelUsage, formatModelUsage, sumModelUsages } from "../explore/usage.js";
import { collectWorkspaceChanges } from "../explore/workspace-changes.js";
import { BOLD, GREEN, RESET, YELLOW } from "../formatters.js";
import { resolveProjectId, resolveProjectIdForDirect } from "../resolve-project-id.js";
import { getDeepsecVersion } from "../version.js";
import { exportCommand } from "./export.js";
import { reportCommand } from "./report.js";

export interface ExploreStatusOptions {
  projectId?: string;
  runId?: string;
  json?: boolean;
  failOnAcceptedFindings?: boolean;
  minSeverity?: string;
}

export interface ExploreCiOptions extends ExploreStatusOptions {
  outDir?: string;
  report?: boolean;
  exportJson?: boolean;
  exportSarif?: boolean;
  junit?: boolean;
}

export interface ExploreArtifactsOptions {
  projectId?: string;
  runId?: string;
  json?: boolean;
  hashes?: boolean;
}

export interface ExploreAuditOptions extends ExploreStatusOptions {
  requireReport?: boolean;
  requireCi?: boolean;
  failOnWarnings?: boolean;
}

export interface ExploreManifestOptions extends ExploreAuditOptions {
  out?: string;
}

export interface ExploreVerifyManifestOptions {
  manifest?: string;
  json?: boolean;
}

export interface ExploreEvidenceOptions {
  manifest?: string;
  out?: string;
  json?: boolean;
}

export interface ExploreBundleOptions {
  manifest?: string;
  outDir?: string;
  includeAttempts?: boolean;
  force?: boolean;
  json?: boolean;
}

export interface ExploreVerifyBundleOptions {
  bundleDir?: string;
  json?: boolean;
}

export interface ExploreListOptions {
  projectId?: string;
  json?: boolean;
  limit?: number;
}

export interface ExploreAttemptInspectOptions {
  projectId?: string;
  runId?: string;
  attempt?: string;
  json?: boolean;
  transcript?: boolean;
}

export interface ExploreFindingsOptions {
  projectId?: string;
  runId?: string;
  json?: boolean;
  minSeverity?: string;
  all?: boolean;
}

export interface ExploreRetryOptions extends ExploreOptions {
  runId?: string;
  all?: boolean;
}

type FocusedAttemptResult =
  | { ok: true; attempt: ExploreAttempt }
  | { ok: false; failure: ExploreAttemptFailure };

interface ExploreSummary {
  projectId: string;
  runId: string;
  completedAt: string;
  attempts: number;
  completedAttempts: number;
  failedAttempts: number;
  bugsReported: number;
  acceptedFindings: number;
  rankingUsage?: ModelUsage;
  attemptUsage?: ModelUsage;
  usage?: ModelUsage;
}

interface ExploreCiOutputs {
  outDir: string;
  summaryJson: string;
  reportJson?: string;
  reportMarkdown?: string;
  findingsJson?: string;
  findingsSarif?: string;
  junitXml?: string;
}

interface ExploreCiSummary {
  version: 1;
  generatedAt: string;
  projectId: string;
  runId: string;
  statusOk: boolean;
  exitCode: number;
  gate: {
    failOnAcceptedFindings: boolean;
    minSeverity: Severity;
    acceptedFindingsAtOrAboveMinSeverity: number;
    totalAcceptedFindings: number;
  };
  run: {
    rankingsCount: number;
    attempts: number;
    completedAttempts?: number;
    failedAttempts?: number;
    bugsReported?: number;
    acceptedFindings?: number;
    usage?: ModelUsage;
  };
  problems: string[];
  findings: {
    accepted: ExploreCiFindingSummary[];
    acceptedAtOrAboveMinSeverity: ExploreCiFindingSummary[];
  };
  artifacts: ExploreCiArtifactSummary[];
  outputs: ExploreCiOutputs;
}

const EXPLORE_CI_SUMMARY_FILE = "ci-summary.json";

interface ExploreCiFindingSummary {
  attemptDir: string;
  focusFile?: string;
  title?: string;
  severity?: Severity;
  confidence?: string;
  vulnSlug?: string;
  lineNumbers?: number[];
  validationVerdict?: string;
  thresholdMatched: boolean;
}

interface ExploreCiArtifactSummary {
  kind: "report-json" | "report-markdown" | "findings-json" | "findings-sarif" | "junit-xml";
  path: string;
  exists: boolean;
  bytes?: number;
  sha256?: string;
}

interface ExploreArtifactEntry {
  kind: string;
  path: string;
  exists: boolean;
  bytes?: number;
  sha256?: string;
}

interface ExploreAttemptArtifactIndex {
  dirName: string;
  focusFile?: string;
  dir: string;
  artifacts: ExploreArtifactEntry[];
}

interface ExploreArtifactIndex {
  version: 1;
  generatedAt: string;
  projectId: string;
  runId: string;
  statusOk: boolean;
  problems: string[];
  exploreDir: string;
  runArtifacts: ExploreArtifactEntry[];
  attempts: ExploreAttemptArtifactIndex[];
  reportArtifacts: ExploreArtifactEntry[];
  ciArtifacts: ExploreArtifactEntry[];
}

interface ExploreRunListEntry {
  projectId: string;
  runId: string;
  exploreDir: string;
  ok: boolean;
  problems: string[];
  rankingsCount: number;
  attempts: number;
  completedAttempts?: number;
  failedAttempts?: number;
  bugsReported?: number;
  acceptedFindings?: number;
  inputTokens?: number;
  outputTokens?: number;
  costUsd?: number;
  startedAt?: string;
  completedAt?: string;
}

interface ExploreRunList {
  version: 1;
  generatedAt: string;
  projectId: string;
  exploreRoot: string;
  runs: ExploreRunListEntry[];
}

interface ExploreAttemptInspection {
  version: 1;
  generatedAt: string;
  projectId: string;
  runId: string;
  attempt: string;
  attemptDir: string;
  status?: ExploreRunStatus["attempts"][number];
  artifacts: ExploreArtifactEntry[];
  report?: ExploreAttempt["report"];
  validation?: ExploreAttempt["validation"];
  workspaceChanges?: ExploreAttempt["workspaceChanges"];
  failure?: ExploreAttemptFailure;
  transcript?: ExploreAttempt["transcript"];
  validationTranscript?: ExploreAttempt["validationTranscript"];
  problems: string[];
}

interface ExploreFindingEntry {
  attempt: string;
  focusFile?: string;
  accepted: boolean;
  title?: string;
  severity?: Severity;
  confidence?: string;
  vulnSlug?: string;
  lineNumbers?: number[];
  validationVerdict?: string;
  thresholdMatched: boolean;
}

interface ExploreFindingsSummary {
  version: 1;
  generatedAt: string;
  projectId: string;
  runId: string;
  statusOk: boolean;
  minSeverity?: Severity;
  acceptedOnly: boolean;
  problems: string[];
  counts: {
    findings: number;
    accepted: number;
    atOrAboveMinSeverity: number;
  };
  findings: ExploreFindingEntry[];
}

type ExploreAuditCheckStatus = "pass" | "warn" | "fail";

interface ExploreAuditCheck {
  id: string;
  label: string;
  status: ExploreAuditCheckStatus;
  detail: string;
  problems: string[];
}

interface ExploreAuditSummary {
  version: 1;
  generatedAt: string;
  projectId: string;
  runId: string;
  ok: boolean;
  exitCode: number;
  gate: {
    failOnAcceptedFindings: boolean;
    minSeverity?: Severity;
    failOnWarnings: boolean;
    requireReport: boolean;
    requireCi: boolean;
    acceptedFindingsAtOrAboveMinSeverity: number;
    totalAcceptedFindings: number;
  };
  run: {
    rankingsCount: number;
    attempts: number;
    completedAttempts?: number;
    failedAttempts?: number;
    bugsReported?: number;
    acceptedFindings?: number;
    usage?: ModelUsage;
  };
  checks: ExploreAuditCheck[];
  problems: string[];
  warnings: string[];
}

interface ExploreRunManifest {
  version: 1;
  generatedAt: string;
  projectId: string;
  runId: string;
  projectDataDir: string;
  exploreDir: string;
  statusOk: boolean;
  summary?: ExploreRunStatus["summary"];
  audit: ExploreAuditSummary;
  findings: ExploreFindingsSummary;
  artifacts: ExploreArtifactIndex;
  outputs: {
    manifestJson?: string;
  };
  nextCommands: string[];
}

type ExploreManifestArtifactVerificationStatus =
  | "ok"
  | "missing"
  | "unexpected-present"
  | "mismatch"
  | "invalid";

interface ExploreManifestArtifactVerification {
  kind: string;
  path: string;
  expectedExists: boolean;
  actualExists: boolean;
  expectedBytes?: number;
  actualBytes?: number;
  expectedSha256?: string;
  actualSha256?: string;
  status: ExploreManifestArtifactVerificationStatus;
  problem?: string;
}

interface ExploreManifestVerification {
  version: 1;
  generatedAt: string;
  manifestPath: string;
  manifestBytes: number;
  manifestSha256: string;
  projectId?: string;
  runId?: string;
  ok: boolean;
  checkedArtifacts: number;
  problems: string[];
  artifacts: ExploreManifestArtifactVerification[];
}

interface ExploreEvidenceSummary {
  version: 1;
  generatedAt: string;
  manifestPath: string;
  projectId?: string;
  runId?: string;
  verificationOk: boolean;
  auditExitCode?: number;
  auditProblems: string[];
  auditWarnings: string[];
  counts: {
    findings: number;
    accepted: number;
    artifactsChecked: number;
    artifactProblems: number;
  };
  findings: ExploreFindingEntry[];
  artifactProblems: string[];
  reportArtifacts: ExploreArtifactEntry[];
  ciArtifacts: ExploreArtifactEntry[];
  nextCommands: string[];
}

interface ExploreBundleCopiedArtifact {
  kind: string;
  sourcePath: string;
  bundlePath: string;
  bytes: number;
  sha256: string;
}

interface ExploreBundleFileRecord {
  kind: string;
  bundlePath: string;
  bytes: number;
  sha256: string;
}

interface ExploreBundleIndex {
  version: 1;
  generatedAt: string;
  projectId?: string;
  runId?: string;
  bundleDir: string;
  manifestPath: string;
  includeAttempts: boolean;
  verification: {
    ok: boolean;
    checkedArtifacts: number;
    problems: string[];
  };
  files: {
    manifest: string;
    evidenceMarkdown: string;
    evidenceJson: string;
    provenance?: string;
    checksums?: string;
  };
  coreFiles?: ExploreBundleFileRecord[];
  copiedArtifacts: ExploreBundleCopiedArtifact[];
  skippedArtifacts: Array<{ kind: string; path: string; reason: string }>;
}

type ExploreBundleFileVerificationStatus = "ok" | "missing" | "mismatch" | "invalid";

interface ExploreBundleFileVerification {
  kind: string;
  bundlePath: string;
  expectedBytes?: number;
  actualBytes?: number;
  expectedSha256?: string;
  actualSha256?: string;
  status: ExploreBundleFileVerificationStatus;
  problem?: string;
}

interface ExploreBundleVerification {
  version: 1;
  generatedAt: string;
  bundleDir: string;
  indexPath: string;
  projectId?: string;
  runId?: string;
  ok: boolean;
  checkedFiles: number;
  problems: string[];
  files: ExploreBundleFileVerification[];
}

interface ExploreBundleProvenance {
  version: 1;
  generatedAt: string;
  tool: {
    name: "deepsec";
    version: string;
    node: string;
    platform: string;
    arch: string;
    hostname: string;
  };
  source: {
    manifestPath: string;
    manifestBytes: number;
    manifestSha256: string;
    projectId?: string;
    runId?: string;
    projectDataDir?: string;
    exploreDir?: string;
  };
  bundle: {
    includeAttempts: boolean;
    verificationOk: boolean;
    checkedArtifacts: number;
  };
}

export async function exploreSetupCommand(rawOpts: ExploreSetupOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  await setupExploreProfile(opts.profile);
}

export async function exploreDoctorCommand(rawOpts: ExploreOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  const profile = assertExploreProfile(opts.profile);
  const runtime = opts.runtime ?? EXPLORE_RUNTIME;
  if (runtime !== EXPLORE_RUNTIME) {
    throw new Error(`deepsec explore doctor requires --runtime ${EXPLORE_RUNTIME}.`);
  }

  console.log("DeepSec explore doctor");
  console.log(`  profile: ${profile}`);
  console.log(`  runtime: ${runtime}`);

  await check("Docker runtime registered", () => assertRunscRegistered(runtime));
  await check("Explore image exists", () => assertExploreImageExists(EXPLORE_IMAGE));
  await check("Gradle offline cache exists", () => assertGradleCacheAvailable());
  if (opts.stubModel) {
    console.log(`  ${GREEN}ok${RESET} Stub model selected; OpenRouter is not required`);
  } else {
    await check("OpenRouter API key configured", () => {
      if (!process.env.OPENROUTER_API_KEY) {
        throw new Error("OPENROUTER_API_KEY is not set.");
      }
    });
    if (opts.liveModelCheck) {
      const model = opts.model ?? OPENROUTER_DEFAULT_MODEL;
      const rankModel = opts.rankModel ?? model;
      const models = [...new Set([rankModel, model])];
      const client = new OpenRouterResponsesClient(
        process.env.OPENROUTER_API_KEY,
        process.env.OPENROUTER_BASE_URL,
        Number(process.env.OPENROUTER_TIMEOUT_MS ?? 240_000),
        256,
      );
      for (const modelName of models) {
        const usage = await check(`OpenRouter live model check (${modelName})`, () =>
          checkOpenRouterModelReachability({ client, model: modelName }),
        );
        const formatted = formatModelUsage(usage);
        if (formatted) console.log(`    usage: ${formatted}`);
      }
    } else {
      console.log(
        "  OpenRouter live model check: skipped (pass --live-model-check to spend tokens)",
      );
    }
  }

  if (opts.root || opts.projectId) {
    const resolved = resolveProjectIdForDirect(opts.projectId, opts.root);
    const root = path.resolve(resolved.rootPath);
    let files: SourceFileSummary[] = [];
    await check("Throwaway gVisor container preflight", async () => {
      const container = await createGvisorContainer({
        root,
        runId: `doctor-${generateRunId()}`,
        focusFile: "doctor",
        runtime,
        image: EXPLORE_IMAGE,
      });
      try {
        console.log(`    container runtime: ${container.metadata.runtime}`);
        console.log(`    container network: ${container.metadata.networkMode}`);
        files = await collectProductionFileSummariesFromRunner(container);
        if (files.length === 0) {
          throw new Error(`No production-relevant files found under ${root}.`);
        }
      } finally {
        await container.cleanup();
      }
    });
    console.log(`  root: ${root}`);
    console.log(`  candidate files: ${files.length}`);
  } else {
    console.log("  root: not checked (pass --root to verify copied-source/container preflight)");
  }

  console.log(`${GREEN}Explore doctor passed${RESET}`);
}

export async function exploreStatusCommand(rawOpts: ExploreStatusOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  const projectId = resolveProjectId(opts.projectId);
  const runId = opts.runId ?? latestExploreRunId(projectId);
  const status = summarizeExploreRun(projectId, runId);
  const minSeverity = opts.minSeverity
    ? parseSeverity(opts.minSeverity, "--min-severity")
    : undefined;
  const exitCode = exploreStatusExitCode(status, {
    failOnAcceptedFindings: opts.failOnAcceptedFindings,
    minSeverity,
  });
  if (opts.json) {
    console.log(JSON.stringify(status, null, 2));
    if (exitCode !== undefined) process.exitCode = exitCode;
    return;
  }

  console.log("DeepSec explore status");
  console.log(`  project:  ${status.projectId}`);
  console.log(`  runId:    ${status.runId}`);
  console.log(`  result:   ${status.ok ? `${GREEN}ok${RESET}` : `${YELLOW}problems${RESET}`}`);
  console.log(`  rankings: ${status.rankingsCount}`);
  if (status.rankingScoreMin !== undefined && status.rankingScoreMax !== undefined) {
    console.log(`  scores:   ${status.rankingScoreMin}-${status.rankingScoreMax}`);
  }
  if (status.summary) {
    const usage = formatModelUsage(status.summary.usage);
    console.log(
      `  summary:  attempts=${status.summary.attempts ?? "?"} completed=${status.summary.completedAttempts ?? "?"} failed=${status.summary.failedAttempts ?? "?"} bugs=${status.summary.bugsReported ?? "?"} accepted=${status.summary.acceptedFindings ?? "?"}${usage ? ` ${usage}` : ""}`,
    );
  }
  if (status.integrity?.present) {
    console.log(`  integrity: sha256 manifest (${status.integrity.files} files)`);
  }
  console.log();
  console.log("  Top ranked files");
  for (const ranked of status.topRankedFiles) {
    console.log(`    [${ranked.score}] ${ranked.filePath}`);
  }
  console.log();
  console.log("  Attempts");
  for (const attempt of status.attempts) {
    const marker = attempt.problems.length === 0 ? `${GREEN}ok${RESET}` : `${YELLOW}fail${RESET}`;
    const hardening = [
      attempt.readOnlyRootfs ? "ro-root" : "rw-root",
      attempt.noNewPrivileges ? "nnp" : "privs",
      attempt.capDropAll ? "capdrop" : "caps",
    ].join(",");
    console.log(
      `    ${marker} ${attempt.dirName} ${attempt.focusFile ?? "(missing)"} outcome=${attempt.outcome ?? (attempt.failed ? "error" : "?")} turns=${attempt.turns ?? "?"} events=${attempt.eventCount} tools=${attempt.toolEvents} runtime=${attempt.runtime ?? "?"} network=${attempt.networkMode ?? "?"}`,
    );
    if (attempt.error) {
      console.log(`      error=${shorten(attempt.error, 180)}`);
    }
    const usage = formatModelUsage(attempt.usage);
    console.log(
      `      hardening=${hardening} pids=${attempt.pidsLimit ?? "?"} memory=${attempt.memoryBytes ?? "?"} nanoCpus=${attempt.nanoCpus ?? "?"} copyExcluded=${attempt.copyExcludedCount ?? "?"}${usage ? ` ${usage}` : ""}`,
    );
    if (attempt.workspaceChanges !== undefined) {
      console.log(
        `      workspaceChanges=${attempt.workspaceChanges} captured=${attempt.workspaceChangesCaptured ?? "?"}`,
      );
    }
    if (attempt.bugTitle) {
      const accepted =
        attempt.acceptedFinding === undefined
          ? ""
          : ` accepted=${attempt.acceptedFinding ? "yes" : "no"}`;
      const lines =
        attempt.lineNumbers && attempt.lineNumbers.length > 0
          ? ` lines=${attempt.lineNumbers.join(",")}`
          : "";
      console.log(
        `      finding=${attempt.bugSeverity ?? "?"}/${attempt.bugConfidence ?? "?"} slug=${attempt.vulnSlug ?? "?"}${lines}${accepted}: ${shorten(attempt.bugTitle, 140)}`,
      );
    }
    if (
      attempt.validationVerdict ||
      attempt.validationRuntime ||
      attempt.validationEventCount > 0
    ) {
      console.log(
        `      validation=${attempt.validationVerdict ?? "?"} turns=${attempt.validationTurns ?? "?"} events=${attempt.validationEventCount} tools=${attempt.validationToolEvents} runtime=${attempt.validationRuntime ?? "?"} network=${attempt.validationNetworkMode ?? "?"}`,
      );
    }
  }
  if (status.problems.length > 0) {
    console.log();
    console.log("  Problems");
    for (const problem of status.problems) {
      console.log(`    - ${problem}`);
    }
  }
  const acceptedFindings = countAcceptedExploreFindings(status, minSeverity);
  if (opts.failOnAcceptedFindings && acceptedFindings > 0 && status.ok) {
    console.log();
    const threshold = minSeverity ? ` at or above ${minSeverity}` : "";
    console.log(
      `${YELLOW}Accepted findings${threshold} present: ${acceptedFindings}; failing due to --fail-on-accepted-findings.${RESET}`,
    );
  }
  if (exitCode !== undefined) process.exitCode = exitCode;
}

export async function exploreArtifactsCommand(rawOpts: ExploreArtifactsOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  const projectId = resolveProjectId(opts.projectId);
  const runId = opts.runId ?? latestExploreRunId(projectId);
  const status = summarizeExploreRun(projectId, runId);
  const index = buildExploreArtifactIndex(status, { hashes: opts.hashes !== false });

  if (opts.json) {
    console.log(JSON.stringify(index, null, 2));
    return;
  }

  console.log("DeepSec explore artifacts");
  console.log(`  project: ${index.projectId}`);
  console.log(`  runId:   ${index.runId}`);
  console.log(`  status:  ${index.statusOk ? `${GREEN}ok${RESET}` : `${YELLOW}problems${RESET}`}`);
  console.log(`  dir:     ${index.exploreDir}`);
  console.log();
  printArtifactGroup("Run artifacts", index.runArtifacts);
  for (const attempt of index.attempts) {
    console.log();
    console.log(`  Attempt ${attempt.dirName}${attempt.focusFile ? ` ${attempt.focusFile}` : ""}`);
    printArtifactEntries(attempt.artifacts, "    ");
  }
  console.log();
  printArtifactGroup("Report artifacts", index.reportArtifacts);
  console.log();
  printArtifactGroup("CI artifacts", index.ciArtifacts);
  if (index.problems.length > 0) {
    console.log();
    console.log("  Problems");
    for (const problem of index.problems) {
      console.log(`    - ${problem}`);
    }
  }
}

export async function exploreAuditCommand(rawOpts: ExploreAuditOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  const projectId = resolveProjectId(opts.projectId);
  const runId = opts.runId ?? latestExploreRunId(projectId);
  const status = summarizeExploreRun(projectId, runId);
  const minSeverity = opts.minSeverity
    ? parseSeverity(opts.minSeverity, "--min-severity")
    : undefined;
  const audit = buildExploreAuditSummary(status, {
    failOnAcceptedFindings: opts.failOnAcceptedFindings === true,
    minSeverity,
    requireReport: opts.requireReport === true,
    requireCi: opts.requireCi === true,
    failOnWarnings: opts.failOnWarnings === true,
  });

  if (opts.json) {
    console.log(JSON.stringify(audit, null, 2));
    if (audit.exitCode !== 0) process.exitCode = audit.exitCode;
    return;
  }

  console.log("DeepSec explore audit");
  console.log(`  project: ${audit.projectId}`);
  console.log(`  runId:   ${audit.runId}`);
  console.log(`  result:  ${audit.ok ? `${GREEN}ok${RESET}` : `${YELLOW}attention${RESET}`}`);
  console.log(`  exit:    ${audit.exitCode}`);
  console.log(
    `  gate:    accepted>=${audit.gate.minSeverity ?? "any"} fail=${audit.gate.failOnAcceptedFindings} warnings-fail=${audit.gate.failOnWarnings}`,
  );
  console.log();
  for (const check of audit.checks) {
    const marker =
      check.status === "pass"
        ? `${GREEN}pass${RESET}`
        : check.status === "warn"
          ? `${YELLOW}warn${RESET}`
          : `${YELLOW}fail${RESET}`;
    console.log(`  ${marker} ${check.id}: ${check.detail}`);
    for (const problem of check.problems.slice(0, 5)) {
      console.log(`    - ${problem}`);
    }
    if (check.problems.length > 5) {
      console.log(`    - ... ${check.problems.length - 5} more`);
    }
  }
  if (audit.exitCode !== 0) process.exitCode = audit.exitCode;
}

export async function exploreManifestCommand(rawOpts: ExploreManifestOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  const projectId = resolveProjectId(opts.projectId);
  const runId = opts.runId ?? latestExploreRunId(projectId);
  const status = summarizeExploreRun(projectId, runId);
  const minSeverity = opts.minSeverity
    ? parseSeverity(opts.minSeverity, "--min-severity")
    : undefined;
  const out = opts.out ? path.resolve(opts.out) : undefined;
  const manifest = buildExploreRunManifest(status, {
    failOnAcceptedFindings: opts.failOnAcceptedFindings === true,
    minSeverity,
    requireReport: opts.requireReport === true,
    requireCi: opts.requireCi === true,
    failOnWarnings: opts.failOnWarnings === true,
    out,
  });

  if (out) {
    writeJson(out, manifest);
  }
  if (opts.json || !out) {
    console.log(JSON.stringify(manifest, null, 2));
  } else {
    console.log("DeepSec explore manifest");
    console.log(`  project: ${manifest.projectId}`);
    console.log(`  runId:   ${manifest.runId}`);
    console.log(
      `  status:  ${manifest.statusOk ? `${GREEN}ok${RESET}` : `${YELLOW}problems${RESET}`}`,
    );
    console.log(`  audit:   exit=${manifest.audit.exitCode}`);
    console.log(`  out:     ${out}`);
  }
  if (manifest.audit.exitCode !== 0) process.exitCode = manifest.audit.exitCode;
}

export async function exploreVerifyManifestCommand(
  rawOpts: ExploreVerifyManifestOptions,
): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  if (!opts.manifest) throw new Error("deepsec explore verify-manifest requires a manifest path.");
  const verification = verifyExploreRunManifest(path.resolve(opts.manifest));

  if (opts.json) {
    console.log(JSON.stringify(verification, null, 2));
  } else {
    console.log("DeepSec explore verify-manifest");
    console.log(`  manifest: ${verification.manifestPath}`);
    console.log(
      `  result:   ${verification.ok ? `${GREEN}ok${RESET}` : `${YELLOW}problems${RESET}`}`,
    );
    console.log(`  project:  ${verification.projectId ?? "?"}`);
    console.log(`  runId:    ${verification.runId ?? "?"}`);
    console.log(`  artifacts checked: ${verification.checkedArtifacts}`);
    console.log(`  manifest sha256:   ${verification.manifestSha256}`);
    if (verification.problems.length > 0) {
      console.log();
      console.log("  Problems");
      for (const problem of verification.problems) {
        console.log(`    - ${problem}`);
      }
    }
  }
  if (!verification.ok) process.exitCode = 1;
}

export async function exploreEvidenceCommand(rawOpts: ExploreEvidenceOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  if (!opts.manifest) throw new Error("deepsec explore evidence requires a manifest path.");
  const manifestPath = path.resolve(opts.manifest);
  const evidence = buildExploreEvidenceSummary(manifestPath);
  const out = opts.out ? path.resolve(opts.out) : undefined;

  if (opts.json) {
    const payload = JSON.stringify(evidence, null, 2);
    if (out) fs.writeFileSync(out, payload + "\n");
    console.log(payload);
  } else {
    const markdown = renderExploreEvidenceMarkdown(evidence);
    if (out) {
      fs.mkdirSync(path.dirname(out), { recursive: true });
      fs.writeFileSync(out, markdown);
      console.log("DeepSec explore evidence");
      console.log(`  project: ${evidence.projectId ?? "?"}`);
      console.log(`  runId:   ${evidence.runId ?? "?"}`);
      console.log(
        `  verify:  ${evidence.verificationOk ? `${GREEN}ok${RESET}` : `${YELLOW}problems${RESET}`}`,
      );
      console.log(`  out:     ${out}`);
    } else {
      console.log(markdown.trimEnd());
    }
  }
  if (!evidence.verificationOk) process.exitCode = 1;
}

export async function exploreBundleCommand(rawOpts: ExploreBundleOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  if (!opts.manifest) throw new Error("deepsec explore bundle requires a manifest path.");
  if (!opts.outDir) throw new Error("deepsec explore bundle requires --out-dir.");
  const index = buildExploreBundle({
    manifestPath: path.resolve(opts.manifest),
    outDir: path.resolve(opts.outDir),
    includeAttempts: opts.includeAttempts === true,
    force: opts.force === true,
  });

  if (opts.json) {
    console.log(JSON.stringify(index, null, 2));
  } else {
    console.log("DeepSec explore bundle");
    console.log(`  project: ${index.projectId ?? "?"}`);
    console.log(`  runId:   ${index.runId ?? "?"}`);
    console.log(`  out:     ${index.bundleDir}`);
    console.log(`  copied:  ${index.copiedArtifacts.length}`);
    console.log(`  skipped: ${index.skippedArtifacts.length}`);
    console.log(`  index:   ${path.join(index.bundleDir, "bundle-index.json")}`);
  }
}

export async function exploreVerifyBundleCommand(
  rawOpts: ExploreVerifyBundleOptions,
): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  if (!opts.bundleDir) throw new Error("deepsec explore verify-bundle requires a bundle dir.");
  const verification = verifyExploreBundle(path.resolve(opts.bundleDir));

  if (opts.json) {
    console.log(JSON.stringify(verification, null, 2));
  } else {
    console.log("DeepSec explore verify-bundle");
    console.log(`  bundle: ${verification.bundleDir}`);
    console.log(
      `  result: ${verification.ok ? `${GREEN}ok${RESET}` : `${YELLOW}problems${RESET}`}`,
    );
    console.log(`  project: ${verification.projectId ?? "?"}`);
    console.log(`  runId:   ${verification.runId ?? "?"}`);
    console.log(`  files checked: ${verification.checkedFiles}`);
    if (verification.problems.length > 0) {
      console.log();
      console.log("  Problems");
      for (const problem of verification.problems) console.log(`    - ${problem}`);
    }
  }
  if (!verification.ok) process.exitCode = 1;
}

export async function exploreListCommand(rawOpts: ExploreListOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  const projectId = resolveProjectId(opts.projectId);
  const limit = parsePositiveInt(opts.limit, 20, "--limit");
  const list = buildExploreRunList(projectId, limit);

  if (opts.json) {
    console.log(JSON.stringify(list, null, 2));
    return;
  }

  console.log("DeepSec explore runs");
  console.log(`  project: ${list.projectId}`);
  console.log(`  root:    ${list.exploreRoot}`);
  console.log(`  runs:    ${list.runs.length}`);
  console.log();
  for (const run of list.runs) {
    const marker = run.ok ? `${GREEN}ok${RESET}` : `${YELLOW}problems${RESET}`;
    const usage =
      run.inputTokens !== undefined || run.outputTokens !== undefined || run.costUsd !== undefined
        ? ` tokens=${run.inputTokens ?? "?"}/${run.outputTokens ?? "?"}${
            run.costUsd !== undefined ? ` cost=$${run.costUsd.toFixed(6)}` : ""
          }`
        : "";
    console.log(
      `  ${marker} ${run.runId} attempts=${run.attempts} completed=${run.completedAttempts ?? "?"} failed=${run.failedAttempts ?? "?"} bugs=${run.bugsReported ?? "?"} accepted=${run.acceptedFindings ?? "?"}${usage}`,
    );
    if (run.problems.length > 0) {
      for (const problem of run.problems.slice(0, 3)) {
        console.log(`    - ${problem}`);
      }
      if (run.problems.length > 3) {
        console.log(`    - ... ${run.problems.length - 3} more`);
      }
    }
  }
}

export async function exploreAttemptCommand(rawOpts: ExploreAttemptInspectOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  if (!opts.attempt) throw new Error("deepsec explore attempt requires an attempt id.");
  const projectId = resolveProjectId(opts.projectId);
  const runId = opts.runId ?? latestExploreRunId(projectId);
  const status = summarizeExploreRun(projectId, runId);
  const inspection = buildExploreAttemptInspection(status, opts.attempt, {
    includeTranscript: opts.transcript === true,
  });

  if (opts.json) {
    console.log(JSON.stringify(inspection, null, 2));
    return;
  }

  console.log("DeepSec explore attempt");
  console.log(`  project: ${inspection.projectId}`);
  console.log(`  runId:   ${inspection.runId}`);
  console.log(`  attempt: ${inspection.attempt}`);
  console.log(`  dir:     ${inspection.attemptDir}`);
  if (inspection.status) {
    console.log(`  focus:   ${inspection.status.focusFile ?? "(missing)"}`);
    console.log(
      `  result:  ${inspection.status.failed ? "failed" : (inspection.status.outcome ?? "?")} runtime=${inspection.status.runtime ?? "?"} network=${inspection.status.networkMode ?? "?"}`,
    );
    console.log(
      `  events:  attempt=${inspection.status.eventCount} tools=${inspection.status.toolEvents} validation=${inspection.status.validationEventCount}`,
    );
  }
  if (inspection.failure) {
    console.log();
    console.log(`${YELLOW}Failure${RESET}`);
    console.log(`  ${inspection.failure.error}`);
  }
  if (inspection.report) {
    console.log();
    console.log("Report");
    printExploreReport(inspection.report, "  ");
  }
  if (inspection.validation) {
    console.log();
    console.log("Validation");
    console.log(`  verdict:      ${inspection.validation.verdict}`);
    console.log(`  reproducible: ${inspection.validation.reproducible}`);
    console.log(`  interesting:  ${inspection.validation.interesting}`);
    if (inspection.validation.adjustedSeverity) {
      console.log(`  severity:     ${inspection.validation.adjustedSeverity}`);
    }
    console.log(`  reasoning:    ${shorten(inspection.validation.reasoning, 220)}`);
  }
  if (inspection.workspaceChanges) {
    console.log();
    console.log("Workspace changes");
    console.log(
      `  total=${inspection.workspaceChanges.totalChanges} captured=${inspection.workspaceChanges.capturedChanges} omitted=${inspection.workspaceChanges.omittedChanges}`,
    );
    for (const change of inspection.workspaceChanges.changes.slice(0, 10)) {
      console.log(`  - ${change.status} ${change.path}`);
    }
    if (inspection.workspaceChanges.changes.length > 10) {
      console.log(`  - ... ${inspection.workspaceChanges.changes.length - 10} more`);
    }
  }
  console.log();
  printArtifactGroup("Artifacts", inspection.artifacts);
  if (inspection.problems.length > 0) {
    console.log();
    console.log("Problems");
    for (const problem of inspection.problems) console.log(`  - ${problem}`);
  }
}

export async function exploreFindingsCommand(rawOpts: ExploreFindingsOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  const projectId = resolveProjectId(opts.projectId);
  const runId = opts.runId ?? latestExploreRunId(projectId);
  const status = summarizeExploreRun(projectId, runId);
  const minSeverity = opts.minSeverity
    ? parseSeverity(opts.minSeverity, "--min-severity")
    : undefined;
  const summary = buildExploreFindingsSummary(status, {
    minSeverity,
    acceptedOnly: opts.all !== true,
  });

  if (opts.json) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }

  console.log("DeepSec explore findings");
  console.log(`  project:      ${summary.projectId}`);
  console.log(`  runId:        ${summary.runId}`);
  console.log(
    `  status:       ${summary.statusOk ? `${GREEN}ok${RESET}` : `${YELLOW}problems${RESET}`}`,
  );
  console.log(`  acceptedOnly: ${summary.acceptedOnly}`);
  console.log(`  minSeverity:  ${summary.minSeverity ?? "(none)"}`);
  console.log(`  findings:     ${summary.counts.findings}`);
  console.log(`  accepted:     ${summary.counts.accepted}`);
  if (summary.minSeverity) {
    console.log(`  >= threshold: ${summary.counts.atOrAboveMinSeverity}`);
  }
  console.log();
  for (const finding of summary.findings) {
    const marker = finding.accepted ? `${GREEN}accepted${RESET}` : `${YELLOW}reported${RESET}`;
    const lines =
      finding.lineNumbers && finding.lineNumbers.length > 0
        ? `:${finding.lineNumbers.join(",")}`
        : "";
    console.log(
      `  ${marker} ${finding.severity ?? "?"} ${finding.title ?? "(untitled)"} [${finding.attempt}]`,
    );
    console.log(`    ${finding.focusFile ?? "(missing)"}${lines}`);
    console.log(
      `    slug=${finding.vulnSlug ?? "?"} confidence=${finding.confidence ?? "?"} validation=${finding.validationVerdict ?? "?"}`,
    );
  }
  if (summary.problems.length > 0) {
    console.log();
    console.log("Problems");
    for (const problem of summary.problems) console.log(`  - ${problem}`);
  }
}

export async function exploreCiCommand(rawOpts: ExploreCiOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  const projectId = resolveProjectId(opts.projectId);
  const runId = opts.runId ?? latestExploreRunId(projectId);
  const status = summarizeExploreRun(projectId, runId);
  const minSeverity = parseSeverity(opts.minSeverity ?? "LOW", "--min-severity");
  const failOnAcceptedFindings = opts.failOnAcceptedFindings !== false;
  const outDir = path.resolve(opts.outDir ?? path.join(dataDir(projectId), "ci", runId));
  fs.mkdirSync(outDir, { recursive: true });
  const exitCode = exploreStatusExitCode(status, {
    failOnAcceptedFindings,
    minSeverity,
  });
  const shouldReport = status.ok && opts.report !== false;
  const shouldExportJson = status.ok && opts.exportJson !== false;
  const shouldExportSarif = status.ok && opts.exportSarif !== false;
  const shouldWriteJunit = opts.junit !== false;
  const outputs: ExploreCiOutputs = {
    outDir,
    summaryJson: path.join(outDir, EXPLORE_CI_SUMMARY_FILE),
    reportJson: shouldReport ? reportJsonPath(projectId, runId) : undefined,
    reportMarkdown: shouldReport ? reportMdPath(projectId, runId) : undefined,
    findingsJson: shouldExportJson ? path.join(outDir, "findings.json") : undefined,
    findingsSarif: shouldExportSarif ? path.join(outDir, "findings.sarif") : undefined,
    junitXml: shouldWriteJunit ? path.join(outDir, "junit.xml") : undefined,
  };

  console.log("DeepSec explore CI");
  console.log(`  project:      ${projectId}`);
  console.log(`  runId:        ${runId}`);
  console.log(`  status:       ${status.ok ? `${GREEN}ok${RESET}` : `${YELLOW}problems${RESET}`}`);
  console.log(`  min severity: ${minSeverity}`);
  console.log(
    `  gate:         ${failOnAcceptedFindings ? "fail on accepted findings" : "artifact status only"}`,
  );

  if (!status.ok) {
    console.log();
    console.log("  Problems");
    for (const problem of status.problems) {
      console.log(`    - ${problem}`);
    }
    if (shouldWriteJunit) {
      writeExploreCiJunit({
        status,
        minSeverity,
        failOnAcceptedFindings,
        exitCode: 1,
        outputs,
      });
    }
    writeExploreCiSummary({
      status,
      minSeverity,
      failOnAcceptedFindings,
      exitCode: 1,
      outputs,
    });
    console.log();
    console.log(`  summary: ${outputs.summaryJson}`);
    process.exitCode = 1;
    return;
  }

  if (shouldReport) {
    console.log();
    console.log(`${BOLD}Generating run-scoped report${RESET}`);
    await reportCommand({ projectId, runId });
  }

  if (shouldExportJson) {
    console.log();
    console.log(`${BOLD}Exporting run-scoped JSON findings${RESET}`);
    await exportCommand({
      projectId,
      runId,
      format: "json",
      out: outputs.findingsJson,
    });
  }

  if (shouldExportSarif) {
    console.log();
    console.log(`${BOLD}Exporting run-scoped SARIF findings${RESET}`);
    await exportCommand({
      projectId,
      runId,
      format: "sarif",
      out: outputs.findingsSarif,
    });
  }

  const acceptedFindings = countAcceptedExploreFindings(status, minSeverity);
  if (shouldWriteJunit) {
    writeExploreCiJunit({
      status,
      minSeverity,
      failOnAcceptedFindings,
      exitCode: exitCode ?? 0,
      outputs,
    });
  }
  writeExploreCiSummary({
    status,
    minSeverity,
    failOnAcceptedFindings,
    exitCode: exitCode ?? 0,
    outputs,
  });
  console.log();
  console.log(`${BOLD}CI summary${RESET}`);
  console.log(`  export dir:           ${outDir}`);
  console.log(`  summary:              ${outputs.summaryJson}`);
  console.log(`  accepted >= ${minSeverity}: ${acceptedFindings}`);

  if (exitCode !== undefined) {
    console.log(
      `${YELLOW}Accepted findings at or above ${minSeverity} present: ${acceptedFindings}; failing CI gate.${RESET}`,
    );
    process.exitCode = exitCode;
  }
}

function writeExploreCiSummary(args: {
  status: ExploreRunStatus;
  minSeverity: Severity;
  failOnAcceptedFindings: boolean;
  exitCode: number;
  outputs: ExploreCiOutputs;
}): ExploreCiSummary {
  const { status, minSeverity, failOnAcceptedFindings, exitCode, outputs } = args;
  const acceptedFindings = summarizeAcceptedExploreFindings(status, minSeverity);
  const summary: ExploreCiSummary = {
    version: 1,
    generatedAt: new Date().toISOString(),
    projectId: status.projectId,
    runId: status.runId,
    statusOk: status.ok,
    exitCode,
    gate: {
      failOnAcceptedFindings,
      minSeverity,
      acceptedFindingsAtOrAboveMinSeverity: countAcceptedExploreFindings(status, minSeverity),
      totalAcceptedFindings: countAcceptedExploreFindings(status),
    },
    run: {
      rankingsCount: status.rankingsCount,
      attempts: status.attempts.length,
      completedAttempts: status.summary?.completedAttempts,
      failedAttempts: status.summary?.failedAttempts,
      bugsReported: status.summary?.bugsReported,
      acceptedFindings: status.summary?.acceptedFindings,
      usage: status.summary?.usage,
    },
    problems: status.problems,
    findings: {
      accepted: acceptedFindings.all,
      acceptedAtOrAboveMinSeverity: acceptedFindings.atOrAboveMinSeverity,
    },
    artifacts: summarizeCiArtifacts(outputs),
    outputs,
  };
  writeJson(outputs.summaryJson, summary);
  return summary;
}

function summarizeAcceptedExploreFindings(
  status: ExploreRunStatus,
  minSeverity: Severity,
): { all: ExploreCiFindingSummary[]; atOrAboveMinSeverity: ExploreCiFindingSummary[] } {
  const all = status.attempts
    .filter((attempt) => attempt.acceptedFinding)
    .map((attempt) => {
      const thresholdMatched =
        attempt.bugSeverity !== undefined && severityAtOrAbove(attempt.bugSeverity, minSeverity);
      return {
        attemptDir: attempt.dirName,
        focusFile: attempt.focusFile,
        title: attempt.bugTitle,
        severity: attempt.bugSeverity,
        confidence: attempt.bugConfidence,
        vulnSlug: attempt.vulnSlug,
        lineNumbers: attempt.lineNumbers,
        validationVerdict: attempt.validationVerdict,
        thresholdMatched,
      };
    });
  return {
    all,
    atOrAboveMinSeverity: all.filter((finding) => finding.thresholdMatched),
  };
}

function summarizeCiArtifacts(outputs: ExploreCiOutputs): ExploreCiArtifactSummary[] {
  const candidates: Array<{ kind: ExploreCiArtifactSummary["kind"]; path?: string }> = [
    { kind: "report-json", path: outputs.reportJson },
    { kind: "report-markdown", path: outputs.reportMarkdown },
    { kind: "findings-json", path: outputs.findingsJson },
    { kind: "findings-sarif", path: outputs.findingsSarif },
    { kind: "junit-xml", path: outputs.junitXml },
  ];
  const artifacts: ExploreCiArtifactSummary[] = [];
  for (const { kind, path: artifactPath } of candidates) {
    if (!artifactPath) continue;
    const resolved = path.resolve(artifactPath);
    if (!fs.existsSync(resolved)) {
      artifacts.push({ kind, path: resolved, exists: false });
      continue;
    }
    const bytes = fs.readFileSync(resolved);
    artifacts.push({
      kind,
      path: resolved,
      exists: true,
      bytes: bytes.length,
      sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    });
  }
  return artifacts;
}

function buildExploreArtifactIndex(
  status: ExploreRunStatus,
  opts: { hashes: boolean },
): ExploreArtifactIndex {
  const exploreDir = status.exploreDir;
  const ciDir = path.join(dataDir(status.projectId), "ci", status.runId);
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    projectId: status.projectId,
    runId: status.runId,
    statusOk: status.ok,
    problems: status.problems,
    exploreDir,
    runArtifacts: [
      artifactEntry("metadata", path.join(exploreDir, "metadata.json"), opts),
      artifactEntry("ranking-container", path.join(exploreDir, "ranking-container.json"), opts),
      artifactEntry("rankings", path.join(exploreDir, "rankings.json"), opts),
      artifactEntry("summary", path.join(exploreDir, "summary.json"), opts),
      artifactEntry("integrity-manifest", path.join(exploreDir, "integrity-manifest.json"), opts),
    ],
    attempts: status.attempts.map((attempt) => {
      const attemptDir = path.join(exploreDir, "attempts", attempt.dirName);
      return {
        dirName: attempt.dirName,
        focusFile: attempt.focusFile,
        dir: attemptDir,
        artifacts: [
          artifactEntry("attempt", path.join(attemptDir, "attempt.json"), opts),
          artifactEntry("attempt-error", path.join(attemptDir, "attempt-error.json"), opts),
          artifactEntry("events", path.join(attemptDir, "events.jsonl"), opts),
          artifactEntry(
            "validation-events",
            path.join(attemptDir, "validation-events.jsonl"),
            opts,
          ),
          artifactEntry("workspace-changes", path.join(attemptDir, "workspace-changes.json"), opts),
        ],
      };
    }),
    reportArtifacts: [
      artifactEntry("report-json", reportJsonPath(status.projectId, status.runId), opts),
      artifactEntry("report-markdown", reportMdPath(status.projectId, status.runId), opts),
    ],
    ciArtifacts: [
      artifactEntry("ci-summary", path.join(ciDir, EXPLORE_CI_SUMMARY_FILE), opts),
      artifactEntry("findings-json", path.join(ciDir, "findings.json"), opts),
      artifactEntry("findings-sarif", path.join(ciDir, "findings.sarif"), opts),
      artifactEntry("junit-xml", path.join(ciDir, "junit.xml"), opts),
    ],
  };
}

function buildExploreRunList(projectId: string, limit: number): ExploreRunList {
  const exploreRoot = path.join(dataDir(projectId), "explore");
  const runIds = fs.existsSync(exploreRoot)
    ? fs
        .readdirSync(exploreRoot, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name)
        .sort()
        .reverse()
        .slice(0, limit)
    : [];
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    projectId,
    exploreRoot: path.resolve(exploreRoot),
    runs: runIds.map((runId) => summarizeExploreRunForList(projectId, exploreRoot, runId)),
  };
}

function summarizeExploreRunForList(
  projectId: string,
  exploreRoot: string,
  runId: string,
): ExploreRunListEntry {
  const exploreDir = path.join(exploreRoot, runId);
  try {
    assertSafeSegment(runId, "runId");
  } catch (err) {
    return {
      projectId,
      runId,
      exploreDir: path.resolve(exploreDir),
      ok: false,
      problems: [err instanceof Error ? err.message : String(err)],
      rankingsCount: 0,
      attempts: 0,
    };
  }

  try {
    const status = summarizeExploreRun(projectId, runId);
    const metadata = readJson<Record<string, unknown>>(path.join(exploreDir, "metadata.json"));
    return {
      projectId,
      runId,
      exploreDir: status.exploreDir,
      ok: status.ok,
      problems: status.problems,
      rankingsCount: status.rankingsCount,
      attempts: status.attempts.length,
      completedAttempts: status.summary?.completedAttempts,
      failedAttempts: status.summary?.failedAttempts,
      bugsReported: status.summary?.bugsReported,
      acceptedFindings: status.summary?.acceptedFindings,
      inputTokens: status.summary?.usage?.inputTokens,
      outputTokens: status.summary?.usage?.outputTokens,
      costUsd: status.summary?.usage?.costUsd,
      startedAt: typeof metadata?.startedAt === "string" ? metadata.startedAt : undefined,
      completedAt: status.summary?.completedAt,
    };
  } catch (err) {
    return {
      projectId,
      runId,
      exploreDir: path.resolve(exploreDir),
      ok: false,
      problems: [err instanceof Error ? err.message : String(err)],
      rankingsCount: 0,
      attempts: 0,
    };
  }
}

function buildExploreAttemptInspection(
  status: ExploreRunStatus,
  requestedAttempt: string,
  opts: { includeTranscript: boolean },
): ExploreAttemptInspection {
  const attemptDirName = normalizeAttemptDirName(requestedAttempt);
  const attemptStatus = status.attempts.find((attempt) => attempt.dirName === attemptDirName);
  if (!attemptStatus) {
    throw new Error(
      `Explore attempt ${JSON.stringify(requestedAttempt)} does not exist in run ${status.runId}.`,
    );
  }
  const attemptDir = path.join(status.exploreDir, "attempts", attemptStatus.dirName);
  const attempt = readJson<ExploreAttempt>(path.join(attemptDir, "attempt.json"));
  const failure = readJson<ExploreAttemptFailure>(path.join(attemptDir, "attempt-error.json"));
  const workspaceChanges = readJson<ExploreAttempt["workspaceChanges"]>(
    path.join(attemptDir, "workspace-changes.json"),
  );
  const inspection: ExploreAttemptInspection = {
    version: 1,
    generatedAt: new Date().toISOString(),
    projectId: status.projectId,
    runId: status.runId,
    attempt: attemptStatus.dirName,
    attemptDir,
    status: attemptStatus,
    artifacts: [
      artifactEntry("attempt", path.join(attemptDir, "attempt.json"), { hashes: true }),
      artifactEntry("attempt-error", path.join(attemptDir, "attempt-error.json"), {
        hashes: true,
      }),
      artifactEntry("events", path.join(attemptDir, "events.jsonl"), { hashes: true }),
      artifactEntry("validation-events", path.join(attemptDir, "validation-events.jsonl"), {
        hashes: true,
      }),
      artifactEntry("workspace-changes", path.join(attemptDir, "workspace-changes.json"), {
        hashes: true,
      }),
    ],
    report: attempt?.report,
    validation: attempt?.validation,
    workspaceChanges: workspaceChanges ?? attempt?.workspaceChanges,
    failure: failure ?? undefined,
    problems: attemptStatus.problems,
  };
  if (opts.includeTranscript && attempt) {
    inspection.transcript = attempt.transcript;
    inspection.validationTranscript = attempt.validationTranscript;
  }
  return inspection;
}

function normalizeAttemptDirName(value: string): string {
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) {
    return String(Number(trimmed)).padStart(2, "0");
  }
  assertSafeSegment(trimmed, "attempt");
  return trimmed;
}

function buildExploreFindingsSummary(
  status: ExploreRunStatus,
  opts: { minSeverity?: Severity; acceptedOnly: boolean },
): ExploreFindingsSummary {
  const findings = status.attempts
    .filter((attempt) => attempt.outcome === "bug")
    .map((attempt): ExploreFindingEntry => {
      const thresholdMatched =
        attempt.bugSeverity !== undefined && opts.minSeverity !== undefined
          ? severityAtOrAbove(attempt.bugSeverity, opts.minSeverity)
          : true;
      return {
        attempt: attempt.dirName,
        focusFile: attempt.focusFile,
        accepted: attempt.acceptedFinding === true,
        title: attempt.bugTitle,
        severity: attempt.bugSeverity,
        confidence: attempt.bugConfidence,
        vulnSlug: attempt.vulnSlug,
        lineNumbers: attempt.lineNumbers,
        validationVerdict: attempt.validationVerdict,
        thresholdMatched,
      };
    })
    .filter((finding) => !opts.acceptedOnly || finding.accepted)
    .filter((finding) => opts.minSeverity === undefined || finding.thresholdMatched)
    .sort(compareExploreFindings);
  const accepted = findings.filter((finding) => finding.accepted).length;
  const atOrAboveMinSeverity =
    opts.minSeverity === undefined
      ? findings.length
      : findings.filter((finding) => finding.thresholdMatched).length;
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    projectId: status.projectId,
    runId: status.runId,
    statusOk: status.ok,
    minSeverity: opts.minSeverity,
    acceptedOnly: opts.acceptedOnly,
    problems: status.problems,
    counts: {
      findings: findings.length,
      accepted,
      atOrAboveMinSeverity,
    },
    findings,
  };
}

function buildExploreAuditSummary(
  status: ExploreRunStatus,
  opts: {
    failOnAcceptedFindings: boolean;
    minSeverity?: Severity;
    requireReport: boolean;
    requireCi: boolean;
    failOnWarnings: boolean;
  },
): ExploreAuditSummary {
  const artifactIndex = buildExploreArtifactIndex(status, { hashes: true });
  const acceptedAtThreshold = countAcceptedExploreFindings(status, opts.minSeverity);
  const totalAcceptedFindings = countAcceptedExploreFindings(status);
  const rankingProblems = matchingProblems(status.problems, rankingProblem);
  const attemptProblems = matchingProblems(status.problems, attemptProblem);
  const isolationProblems = matchingProblems(status.problems, isolationProblem);
  const validationProblems = matchingProblems(status.problems, validationProblem);
  const usageProblems = matchingProblems(status.problems, usageProblem);
  const failedAttempts = status.attempts.filter((attempt) => attempt.failed);
  const checks: ExploreAuditCheck[] = [
    makeAuditCheck({
      id: "artifact-status",
      label: "Explore artifact status",
      failed: !status.ok,
      detail: status.ok ? "status checks passed" : `${status.problems.length} status problem(s)`,
      problems: status.problems,
    }),
    makeAuditCheck({
      id: "ranking",
      label: "File ranking",
      failed: status.rankingsCount === 0 || rankingProblems.length > 0,
      detail:
        status.rankingsCount > 0
          ? `${status.rankingsCount} ranked file(s), scores ${status.rankingScoreMin ?? "?"}-${
              status.rankingScoreMax ?? "?"
            }`
          : "no ranked files",
      problems: [
        ...(status.rankingsCount === 0 ? ["rankings.json contains no ranked files"] : []),
        ...rankingProblems,
      ],
    }),
    makeAuditCheck({
      id: "focused-attempts",
      label: "Focused attempts",
      failed:
        status.attempts.length === 0 || failedAttempts.length > 0 || attemptProblems.length > 0,
      detail: `${status.attempts.length} attempt(s), ${
        status.summary?.completedAttempts ?? "?"
      } completed, ${status.summary?.failedAttempts ?? "?"} failed`,
      problems: [
        ...(status.attempts.length === 0 ? ["no focused attempts were recorded"] : []),
        ...failedAttempts.map(
          (attempt) => `attempt ${attempt.dirName} failed: ${attempt.error ?? "unknown error"}`,
        ),
        ...attemptProblems,
      ],
    }),
    makeAuditCheck({
      id: "gvisor-isolation",
      label: "gVisor isolation",
      failed: isolationProblems.length > 0,
      detail: `${countRunscContainers(status)} runsc container metadata record(s), network=none required`,
      problems: isolationProblems,
    }),
    makeAuditCheck({
      id: "validation",
      label: "Bug validation",
      failed: validationProblems.length > 0,
      detail: `${status.attempts.filter((attempt) => attempt.outcome === "bug").length} bug report(s), ${totalAcceptedFindings} accepted`,
      problems: validationProblems,
    }),
    makeAuditCheck({
      id: "usage-accounting",
      label: "Provider usage accounting",
      failed: usageProblems.length > 0,
      warning: status.summary?.usage === undefined,
      detail: status.summary?.usage
        ? (formatModelUsage(status.summary.usage) ?? "usage recorded")
        : "no provider usage recorded",
      problems:
        status.summary?.usage === undefined
          ? ["provider did not report token/cost usage for this run"]
          : usageProblems,
    }),
    makeAuditCheck({
      id: "accepted-finding-gate",
      label: "Accepted finding gate",
      failed: opts.failOnAcceptedFindings && acceptedAtThreshold > 0,
      warning: !opts.failOnAcceptedFindings && totalAcceptedFindings > 0,
      detail: `${acceptedAtThreshold} accepted finding(s) at threshold, ${totalAcceptedFindings} total accepted`,
      problems:
        acceptedAtThreshold > 0
          ? [
              `${acceptedAtThreshold} accepted finding(s) matched ${
                opts.minSeverity ? `severity ${opts.minSeverity} or higher` : "the active threshold"
              }`,
            ]
          : [],
    }),
    artifactAuditCheck({
      id: "report-artifacts",
      label: "Report artifacts",
      required: opts.requireReport,
      artifacts: artifactIndex.reportArtifacts,
    }),
    artifactAuditCheck({
      id: "ci-artifacts",
      label: "CI artifacts",
      required: opts.requireCi,
      artifacts: artifactIndex.ciArtifacts,
    }),
  ];
  const failed = checks.filter((check) => check.status === "fail");
  const warnings = checks.filter((check) => check.status === "warn");
  const acceptedGateFailed = failed.some((check) => check.id === "accepted-finding-gate");
  const nonAcceptedFailures = failed.filter((check) => check.id !== "accepted-finding-gate");
  const exitCode =
    nonAcceptedFailures.length > 0 || (opts.failOnWarnings && warnings.length > 0)
      ? 1
      : acceptedGateFailed
        ? 2
        : 0;
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    projectId: status.projectId,
    runId: status.runId,
    ok: failed.length === 0 && (!opts.failOnWarnings || warnings.length === 0),
    exitCode,
    gate: {
      failOnAcceptedFindings: opts.failOnAcceptedFindings,
      minSeverity: opts.minSeverity,
      failOnWarnings: opts.failOnWarnings,
      requireReport: opts.requireReport,
      requireCi: opts.requireCi,
      acceptedFindingsAtOrAboveMinSeverity: acceptedAtThreshold,
      totalAcceptedFindings,
    },
    run: {
      rankingsCount: status.rankingsCount,
      attempts: status.attempts.length,
      completedAttempts: status.summary?.completedAttempts,
      failedAttempts: status.summary?.failedAttempts,
      bugsReported: status.summary?.bugsReported,
      acceptedFindings: status.summary?.acceptedFindings,
      usage: status.summary?.usage,
    },
    checks,
    problems: failed.flatMap((check) => check.problems.map((problem) => `${check.id}: ${problem}`)),
    warnings: warnings.flatMap((check) =>
      check.problems.map((problem) => `${check.id}: ${problem}`),
    ),
  };
}

function buildExploreRunManifest(
  status: ExploreRunStatus,
  opts: {
    failOnAcceptedFindings: boolean;
    minSeverity?: Severity;
    requireReport: boolean;
    requireCi: boolean;
    failOnWarnings: boolean;
    out?: string;
  },
): ExploreRunManifest {
  const audit = buildExploreAuditSummary(status, opts);
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    projectId: status.projectId,
    runId: status.runId,
    projectDataDir: path.resolve(dataDir(status.projectId)),
    exploreDir: status.exploreDir,
    statusOk: status.ok,
    summary: status.summary,
    audit,
    findings: buildExploreFindingsSummary(status, { acceptedOnly: false }),
    artifacts: buildExploreArtifactIndex(status, { hashes: true }),
    outputs: opts.out ? { manifestJson: opts.out } : {},
    nextCommands: exploreNextCommands(status.projectId, status.runId),
  };
}

function verifyExploreRunManifest(manifestPath: string): ExploreManifestVerification {
  const { manifest, manifestBytes, manifestSha256 } = readExploreRunManifest(manifestPath);
  const problems: string[] = [];
  if (manifest.version !== 1) problems.push("manifest.version is not 1");
  if (typeof manifest.projectId !== "string") problems.push("manifest.projectId is missing");
  if (typeof manifest.runId !== "string") problems.push("manifest.runId is missing");
  const entries = flattenManifestArtifactEntries(manifest);
  if (entries.length === 0) problems.push("manifest contains no artifact entries");
  const artifacts = entries.map(verifyManifestArtifactEntry);
  problems.push(...artifacts.flatMap((artifact) => (artifact.problem ? [artifact.problem] : [])));
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    manifestPath,
    manifestBytes: manifestBytes.length,
    manifestSha256,
    projectId: manifest.projectId,
    runId: manifest.runId,
    ok: problems.length === 0,
    checkedArtifacts: artifacts.length,
    problems,
    artifacts,
  };
}

function buildExploreEvidenceSummary(manifestPath: string): ExploreEvidenceSummary {
  const { manifest } = readExploreRunManifest(manifestPath);
  const verification = verifyExploreRunManifest(manifestPath);
  const findings = manifest.findings?.findings ?? [];
  const reportArtifacts = manifest.artifacts?.reportArtifacts ?? [];
  const ciArtifacts = manifest.artifacts?.ciArtifacts ?? [];
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    manifestPath,
    projectId: manifest.projectId,
    runId: manifest.runId,
    verificationOk: verification.ok,
    auditExitCode: manifest.audit?.exitCode,
    auditProblems: manifest.audit?.problems ?? [],
    auditWarnings: manifest.audit?.warnings ?? [],
    counts: {
      findings: manifest.findings?.counts.findings ?? findings.length,
      accepted:
        manifest.findings?.counts.accepted ?? findings.filter((finding) => finding.accepted).length,
      artifactsChecked: verification.checkedArtifacts,
      artifactProblems: verification.problems.length,
    },
    findings,
    artifactProblems: verification.problems,
    reportArtifacts,
    ciArtifacts,
    nextCommands: manifest.nextCommands ?? [],
  };
}

function buildExploreBundle(args: {
  manifestPath: string;
  outDir: string;
  includeAttempts: boolean;
  force: boolean;
}): ExploreBundleIndex {
  const { manifest, manifestBytes, manifestSha256 } = readExploreRunManifest(args.manifestPath);
  const verification = verifyExploreRunManifest(args.manifestPath);
  if (!verification.ok) {
    throw new Error(
      `Cannot bundle explore evidence because manifest verification failed: ${verification.problems.join("; ")}`,
    );
  }

  if (fs.existsSync(args.outDir)) {
    const existing = fs.readdirSync(args.outDir);
    if (existing.length > 0 && !args.force) {
      throw new Error(`Bundle output directory is not empty: ${args.outDir}`);
    }
    if (args.force) fs.rmSync(args.outDir, { recursive: true, force: true });
  }
  fs.mkdirSync(args.outDir, { recursive: true });

  const evidence = buildExploreEvidenceSummary(args.manifestPath);
  const manifestBundlePath = path.join(args.outDir, "manifest.json");
  const evidenceMarkdownPath = path.join(args.outDir, "evidence.md");
  const evidenceJsonPath = path.join(args.outDir, "evidence.json");
  const provenancePath = path.join(args.outDir, "provenance.json");
  fs.writeFileSync(manifestBundlePath, manifestBytes);
  fs.writeFileSync(evidenceMarkdownPath, renderExploreEvidenceMarkdown(evidence));
  fs.writeFileSync(evidenceJsonPath, JSON.stringify(evidence, null, 2) + "\n");
  writeJson(
    provenancePath,
    buildExploreBundleProvenance({
      manifest,
      manifestPath: args.manifestPath,
      manifestBytes: manifestBytes.length,
      manifestSha256,
      verification,
      includeAttempts: args.includeAttempts,
    }),
  );
  const coreFiles: ExploreBundleFileRecord[] = [
    bundleFileRecord(args.outDir, "manifest", manifestBundlePath),
    bundleFileRecord(args.outDir, "evidence-markdown", evidenceMarkdownPath),
    bundleFileRecord(args.outDir, "evidence-json", evidenceJsonPath),
    bundleFileRecord(args.outDir, "provenance", provenancePath),
  ];

  const copiedArtifacts: ExploreBundleCopiedArtifact[] = [];
  const skippedArtifacts: ExploreBundleIndex["skippedArtifacts"] = [];
  for (const entry of bundleArtifactEntries(manifest, args.includeAttempts)) {
    const artifact = entry.artifact;
    if (!artifact.exists) {
      skippedArtifacts.push({
        kind: artifact.kind,
        path: artifact.path,
        reason: "artifact was not present when manifest was generated",
      });
      continue;
    }
    if (!fs.existsSync(artifact.path) || !fs.statSync(artifact.path).isFile()) {
      skippedArtifacts.push({
        kind: artifact.kind,
        path: artifact.path,
        reason: "artifact is missing at bundle time",
      });
      continue;
    }
    const relativePath = bundleArtifactRelativePath(entry);
    const destination = path.join(args.outDir, relativePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(artifact.path, destination);
    const bytes = fs.readFileSync(destination);
    copiedArtifacts.push({
      kind: artifact.kind,
      sourcePath: path.resolve(artifact.path),
      bundlePath: relativePath,
      bytes: bytes.length,
      sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    });
  }

  const index: ExploreBundleIndex = {
    version: 1,
    generatedAt: new Date().toISOString(),
    projectId: manifest.projectId,
    runId: manifest.runId,
    bundleDir: args.outDir,
    manifestPath: args.manifestPath,
    includeAttempts: args.includeAttempts,
    verification: {
      ok: verification.ok,
      checkedArtifacts: verification.checkedArtifacts,
      problems: verification.problems,
    },
    files: {
      manifest: path.relative(args.outDir, manifestBundlePath),
      evidenceMarkdown: path.relative(args.outDir, evidenceMarkdownPath),
      evidenceJson: path.relative(args.outDir, evidenceJsonPath),
      provenance: path.relative(args.outDir, provenancePath),
      checksums: "checksums.sha256",
    },
    coreFiles,
    copiedArtifacts,
    skippedArtifacts,
  };
  const bundleIndexPath = path.join(args.outDir, "bundle-index.json");
  writeJson(bundleIndexPath, index);
  writeBundleChecksums(args.outDir, [
    ...coreFiles.map((file) => file.bundlePath),
    "bundle-index.json",
    ...copiedArtifacts.map((artifact) => artifact.bundlePath),
  ]);
  return index;
}

function buildExploreBundleProvenance(args: {
  manifest: Partial<ExploreRunManifest>;
  manifestPath: string;
  manifestBytes: number;
  manifestSha256: string;
  verification: ExploreManifestVerification;
  includeAttempts: boolean;
}): ExploreBundleProvenance {
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    tool: {
      name: "deepsec",
      version: getDeepsecVersion(),
      node: process.version,
      platform: os.platform(),
      arch: os.arch(),
      hostname: os.hostname(),
    },
    source: {
      manifestPath: args.manifestPath,
      manifestBytes: args.manifestBytes,
      manifestSha256: args.manifestSha256,
      projectId: args.manifest.projectId,
      runId: args.manifest.runId,
      projectDataDir: args.manifest.projectDataDir,
      exploreDir: args.manifest.exploreDir,
    },
    bundle: {
      includeAttempts: args.includeAttempts,
      verificationOk: args.verification.ok,
      checkedArtifacts: args.verification.checkedArtifacts,
    },
  };
}

function verifyExploreBundle(bundleDir: string): ExploreBundleVerification {
  const indexPath = path.join(bundleDir, "bundle-index.json");
  const problems: string[] = [];
  if (!fs.existsSync(indexPath) || !fs.statSync(indexPath).isFile()) {
    return {
      version: 1,
      generatedAt: new Date().toISOString(),
      bundleDir,
      indexPath,
      ok: false,
      checkedFiles: 0,
      problems: [`bundle-index.json missing at ${indexPath}`],
      files: [],
    };
  }
  const index = readJson<Partial<ExploreBundleIndex>>(indexPath);
  if (!index) {
    return {
      version: 1,
      generatedAt: new Date().toISOString(),
      bundleDir,
      indexPath,
      ok: false,
      checkedFiles: 0,
      problems: [`bundle-index.json is invalid at ${indexPath}`],
      files: [],
    };
  }
  if (index.version !== 1) problems.push("bundle-index.version is not 1");
  const checks: ExploreBundleFileVerification[] = [];
  if (Array.isArray(index.coreFiles) && index.coreFiles.length > 0) {
    for (const coreFile of index.coreFiles) {
      checks.push(verifyBundleFileRecord(bundleDir, coreFile));
    }
  } else {
    checks.push(
      verifyBundleExistingFile(bundleDir, "manifest", index.files?.manifest),
      verifyBundleExistingFile(bundleDir, "evidence-markdown", index.files?.evidenceMarkdown),
      verifyBundleExistingFile(bundleDir, "evidence-json", index.files?.evidenceJson),
      verifyBundleExistingFile(bundleDir, "provenance", index.files?.provenance),
    );
  }
  for (const artifact of index.copiedArtifacts ?? []) {
    checks.push(verifyBundleCopiedArtifact(bundleDir, artifact));
  }
  if (index.files?.checksums) {
    checks.push(verifyBundleExistingFile(bundleDir, "checksums", index.files.checksums));
    problems.push(
      ...verifyBundleChecksums(bundleDir, index.files.checksums, [
        ...(Array.isArray(index.coreFiles) && index.coreFiles.length > 0
          ? index.coreFiles.map((file) => file.bundlePath)
          : [
              index.files?.manifest,
              index.files?.evidenceMarkdown,
              index.files?.evidenceJson,
            ].filter((value): value is string => typeof value === "string")),
        "bundle-index.json",
        ...(index.copiedArtifacts ?? []).map((artifact) => artifact.bundlePath),
      ]),
    );
  }
  problems.push(...checks.flatMap((check) => (check.problem ? [check.problem] : [])));
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    bundleDir,
    indexPath,
    projectId: index.projectId,
    runId: index.runId,
    ok: problems.length === 0,
    checkedFiles: checks.length,
    problems,
    files: checks,
  };
}

function writeBundleChecksums(bundleDir: string, relativePaths: string[]): void {
  const lines = [...new Set(relativePaths)].sort().map((relativePath) => {
    const resolved = path.join(bundleDir, relativePath);
    const bytes = fs.readFileSync(resolved);
    const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
    return `${sha256}  ${relativePath}`;
  });
  fs.writeFileSync(path.join(bundleDir, "checksums.sha256"), `${lines.join("\n")}\n`);
}

function verifyBundleChecksums(
  bundleDir: string,
  checksumRelativePath: string,
  requiredRelativePaths: string[],
): string[] {
  const checksumPath = path.join(bundleDir, checksumRelativePath);
  if (!isPathInside(bundleDir, checksumPath)) {
    return [`checksums path escapes bundle directory: ${checksumRelativePath}`];
  }
  if (!fs.existsSync(checksumPath) || !fs.statSync(checksumPath).isFile()) {
    return [`checksums missing at ${checksumRelativePath}`];
  }
  const problems: string[] = [];
  const expected = new Map<string, string>();
  for (const [lineNumber, line] of fs
    .readFileSync(checksumPath, "utf-8")
    .split(/\r?\n/)
    .entries()) {
    if (!line.trim()) continue;
    const match = /^([a-f0-9]{64}) {2}(.+)$/.exec(line);
    if (!match) {
      problems.push(`checksums line ${lineNumber + 1} is invalid`);
      continue;
    }
    expected.set(match[2]!, match[1]!);
  }
  for (const relativePath of [...new Set(requiredRelativePaths)].sort()) {
    const expectedSha256 = expected.get(relativePath);
    if (!expectedSha256) {
      problems.push(`checksums missing entry for ${relativePath}`);
      continue;
    }
    const resolved = path.join(bundleDir, relativePath);
    if (!isPathInside(bundleDir, resolved)) {
      problems.push(`checksums entry escapes bundle directory: ${relativePath}`);
      continue;
    }
    if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
      problems.push(`checksums entry missing file ${relativePath}`);
      continue;
    }
    const actualSha256 = crypto
      .createHash("sha256")
      .update(fs.readFileSync(resolved))
      .digest("hex");
    if (actualSha256 !== expectedSha256) {
      problems.push(
        `checksums mismatch for ${relativePath}: expected ${expectedSha256}, actual ${actualSha256}`,
      );
    }
  }
  return problems;
}

function bundleFileRecord(
  bundleDir: string,
  kind: string,
  filePath: string,
): ExploreBundleFileRecord {
  const bytes = fs.readFileSync(filePath);
  return {
    kind,
    bundlePath: path.relative(bundleDir, filePath),
    bytes: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
}

function verifyBundleExistingFile(
  bundleDir: string,
  kind: string,
  relativePath: string | undefined,
): ExploreBundleFileVerification {
  if (!relativePath) {
    return {
      kind,
      bundlePath: "",
      status: "invalid",
      problem: `${kind} missing from bundle-index files`,
    };
  }
  const resolved = path.join(bundleDir, relativePath);
  if (!isPathInside(bundleDir, resolved)) {
    return {
      kind,
      bundlePath: relativePath,
      status: "invalid",
      problem: `${kind} path escapes bundle directory: ${relativePath}`,
    };
  }
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    return {
      kind,
      bundlePath: relativePath,
      status: "missing",
      problem: `${kind} missing at ${relativePath}`,
    };
  }
  const bytes = fs.readFileSync(resolved);
  return {
    kind,
    bundlePath: relativePath,
    actualBytes: bytes.length,
    actualSha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    status: "ok",
  };
}

function verifyBundleFileRecord(
  bundleDir: string,
  record: Partial<ExploreBundleFileRecord>,
): ExploreBundleFileVerification {
  return verifyBundleCopiedArtifact(bundleDir, {
    kind: record.kind,
    bundlePath: record.bundlePath,
    bytes: record.bytes,
    sha256: record.sha256,
  });
}

function verifyBundleCopiedArtifact(
  bundleDir: string,
  artifact: Partial<ExploreBundleCopiedArtifact>,
): ExploreBundleFileVerification {
  const kind = typeof artifact.kind === "string" ? artifact.kind : "(unknown)";
  const bundlePath = typeof artifact.bundlePath === "string" ? artifact.bundlePath : "";
  if (!bundlePath) {
    return {
      kind,
      bundlePath,
      expectedBytes: artifact.bytes,
      expectedSha256: artifact.sha256,
      status: "invalid",
      problem: `${kind} copied artifact is missing bundlePath`,
    };
  }
  const resolved = path.join(bundleDir, bundlePath);
  if (!isPathInside(bundleDir, resolved)) {
    return {
      kind,
      bundlePath,
      expectedBytes: artifact.bytes,
      expectedSha256: artifact.sha256,
      status: "invalid",
      problem: `${kind} path escapes bundle directory: ${bundlePath}`,
    };
  }
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    return {
      kind,
      bundlePath,
      expectedBytes: artifact.bytes,
      expectedSha256: artifact.sha256,
      status: "missing",
      problem: `${kind} missing at ${bundlePath}`,
    };
  }
  const bytes = fs.readFileSync(resolved);
  const actualSha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  const bytesMatch = artifact.bytes === undefined || artifact.bytes === bytes.length;
  const shaMatch = artifact.sha256 === undefined || artifact.sha256 === actualSha256;
  const status = bytesMatch && shaMatch ? "ok" : "mismatch";
  return {
    kind,
    bundlePath,
    expectedBytes: artifact.bytes,
    actualBytes: bytes.length,
    expectedSha256: artifact.sha256,
    actualSha256,
    status,
    problem:
      status === "mismatch"
        ? `${kind} changed at ${bundlePath}: expected bytes=${artifact.bytes ?? "?"} sha256=${
            artifact.sha256 ?? "?"
          }, actual bytes=${bytes.length} sha256=${actualSha256}`
        : undefined,
  };
}

function bundleArtifactEntries(
  manifest: Partial<ExploreRunManifest>,
  includeAttempts: boolean,
): Array<{
  group: "report" | "ci" | "run" | "attempt";
  attempt?: string;
  artifact: ExploreArtifactEntry;
}> {
  const artifacts = manifest.artifacts;
  if (!artifacts) return [];
  const entries: Array<{
    group: "report" | "ci" | "run" | "attempt";
    attempt?: string;
    artifact: ExploreArtifactEntry;
  }> = [];
  for (const artifact of artifacts.reportArtifacts ?? []) {
    entries.push({ group: "report", artifact });
  }
  for (const artifact of artifacts.ciArtifacts ?? []) {
    entries.push({ group: "ci", artifact });
  }
  if (includeAttempts) {
    for (const artifact of artifacts.runArtifacts ?? []) {
      entries.push({ group: "run", artifact });
    }
    for (const attempt of artifacts.attempts ?? []) {
      for (const artifact of attempt.artifacts) {
        entries.push({ group: "attempt", attempt: attempt.dirName, artifact });
      }
    }
  }
  return entries;
}

function bundleArtifactRelativePath(entry: {
  group: "report" | "ci" | "run" | "attempt";
  attempt?: string;
  artifact: ExploreArtifactEntry;
}): string {
  const fileName = `${safeFileName(entry.artifact.kind)}-${safeFileName(
    path.basename(entry.artifact.path),
  )}`;
  if (entry.group === "attempt") {
    return path.join("attempts", safeFileName(entry.attempt ?? "unknown"), fileName);
  }
  return path.join(entry.group, fileName);
}

function safeFileName(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^_+|_+$/g, "") || "artifact";
}

function isPathInside(root: string, child: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(child));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function readExploreRunManifest(manifestPath: string): {
  manifest: Partial<ExploreRunManifest>;
  manifestBytes: Buffer;
  manifestSha256: string;
} {
  const manifestBytes = fs.readFileSync(manifestPath);
  return {
    manifest: JSON.parse(manifestBytes.toString("utf-8")) as Partial<ExploreRunManifest>,
    manifestBytes,
    manifestSha256: crypto.createHash("sha256").update(manifestBytes).digest("hex"),
  };
}

function renderExploreEvidenceMarkdown(evidence: ExploreEvidenceSummary): string {
  const lines: string[] = [
    "# DeepSec Explore Evidence",
    "",
    `- Project: ${evidence.projectId ?? "?"}`,
    `- Run: ${evidence.runId ?? "?"}`,
    `- Generated: ${evidence.generatedAt}`,
    `- Manifest: ${evidence.manifestPath}`,
    `- Manifest verification: ${evidence.verificationOk ? "ok" : "problems"}`,
    `- Audit exit code: ${evidence.auditExitCode ?? "?"}`,
    `- Findings: ${evidence.counts.findings} (${evidence.counts.accepted} accepted)`,
    `- Artifacts checked: ${evidence.counts.artifactsChecked}`,
    `- Artifact problems: ${evidence.counts.artifactProblems}`,
    "",
    "## Findings",
    "",
  ];
  if (evidence.findings.length === 0) {
    lines.push("- No bug reports recorded in the manifest.", "");
  } else {
    for (const finding of evidence.findings) {
      lines.push(
        `- ${finding.accepted ? "accepted" : "reported"} ${finding.severity ?? "?"}: ${
          finding.title ?? "(untitled)"
        }`,
      );
      lines.push(`  - Focus: ${finding.focusFile ?? "?"}`);
      lines.push(`  - Attempt: ${finding.attempt}`);
      lines.push(`  - Validation: ${finding.validationVerdict ?? "?"}`);
      if (finding.vulnSlug) lines.push(`  - Slug: ${finding.vulnSlug}`);
      if (finding.lineNumbers && finding.lineNumbers.length > 0) {
        lines.push(`  - Lines: ${finding.lineNumbers.join(", ")}`);
      }
    }
    lines.push("");
  }

  lines.push("## Audit Problems", "");
  if (evidence.auditProblems.length === 0) {
    lines.push("- None", "");
  } else {
    for (const problem of evidence.auditProblems) lines.push(`- ${problem}`);
    lines.push("");
  }

  lines.push("## Artifact Problems", "");
  if (evidence.artifactProblems.length === 0) {
    lines.push("- None", "");
  } else {
    for (const problem of evidence.artifactProblems) lines.push(`- ${problem}`);
    lines.push("");
  }

  lines.push("## Report Artifacts", "");
  appendArtifactMarkdown(lines, evidence.reportArtifacts);
  lines.push("## CI Artifacts", "");
  appendArtifactMarkdown(lines, evidence.ciArtifacts);
  lines.push("## Next Commands", "");
  for (const command of evidence.nextCommands) lines.push(`- \`${command}\``);
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function appendArtifactMarkdown(lines: string[], artifacts: ExploreArtifactEntry[]): void {
  if (artifacts.length === 0) {
    lines.push("- None", "");
    return;
  }
  for (const artifact of artifacts) {
    const hash = artifact.sha256 ? ` sha256=${artifact.sha256}` : "";
    const bytes = artifact.bytes === undefined ? "" : ` bytes=${artifact.bytes}`;
    lines.push(
      `- ${artifact.exists ? "present" : "missing"} ${artifact.kind}${bytes}${hash}: ${
        artifact.path
      }`,
    );
  }
  lines.push("");
}

function flattenManifestArtifactEntries(
  manifest: Partial<ExploreRunManifest>,
): ExploreArtifactEntry[] {
  const artifacts = manifest.artifacts;
  if (!artifacts) return [];
  const entries: ExploreArtifactEntry[] = [];
  if (Array.isArray(artifacts.runArtifacts)) entries.push(...artifacts.runArtifacts);
  if (Array.isArray(artifacts.reportArtifacts)) entries.push(...artifacts.reportArtifacts);
  if (Array.isArray(artifacts.ciArtifacts)) entries.push(...artifacts.ciArtifacts);
  if (Array.isArray(artifacts.attempts)) {
    for (const attempt of artifacts.attempts) {
      if (Array.isArray(attempt.artifacts)) entries.push(...attempt.artifacts);
    }
  }
  return entries;
}

function verifyManifestArtifactEntry(
  entry: Partial<ExploreArtifactEntry>,
): ExploreManifestArtifactVerification {
  const kind = typeof entry.kind === "string" ? entry.kind : "(unknown)";
  const artifactPath = typeof entry.path === "string" ? entry.path : "";
  const expectedExists = entry.exists === true;
  if (!artifactPath) {
    return {
      kind,
      path: artifactPath,
      expectedExists,
      actualExists: false,
      status: "invalid",
      problem: `${kind} artifact entry is missing path`,
    };
  }
  const resolved = path.resolve(artifactPath);
  const actualExists = fs.existsSync(resolved) && fs.statSync(resolved).isFile();
  if (!expectedExists) {
    return {
      kind,
      path: resolved,
      expectedExists,
      actualExists,
      expectedBytes: entry.bytes,
      expectedSha256: entry.sha256,
      status: actualExists ? "unexpected-present" : "ok",
      problem: actualExists ? `${kind} unexpectedly exists at ${resolved}` : undefined,
    };
  }
  if (!actualExists) {
    return {
      kind,
      path: resolved,
      expectedExists,
      actualExists,
      expectedBytes: entry.bytes,
      expectedSha256: entry.sha256,
      status: "missing",
      problem: `${kind} missing at ${resolved}`,
    };
  }
  const bytes = fs.readFileSync(resolved);
  const actualSha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  const expectedBytes = entry.bytes;
  const expectedSha256 = entry.sha256;
  const bytesMatch = expectedBytes === undefined || expectedBytes === bytes.length;
  const shaMatch = expectedSha256 === undefined || expectedSha256 === actualSha256;
  const status = bytesMatch && shaMatch ? "ok" : "mismatch";
  return {
    kind,
    path: resolved,
    expectedExists,
    actualExists,
    expectedBytes,
    actualBytes: bytes.length,
    expectedSha256,
    actualSha256,
    status,
    problem:
      status === "mismatch"
        ? `${kind} changed at ${resolved}: expected bytes=${expectedBytes ?? "?"} sha256=${
            expectedSha256 ?? "?"
          }, actual bytes=${bytes.length} sha256=${actualSha256}`
        : undefined,
  };
}

function compareExploreFindings(a: ExploreFindingEntry, b: ExploreFindingEntry): number {
  if (a.severity && b.severity && a.severity !== b.severity) {
    return severityAtOrAbove(a.severity, b.severity) ? -1 : 1;
  }
  if (a.accepted !== b.accepted) return a.accepted ? -1 : 1;
  return `${a.focusFile ?? ""}\0${a.title ?? ""}`.localeCompare(
    `${b.focusFile ?? ""}\0${b.title ?? ""}`,
  );
}

function makeAuditCheck(args: {
  id: string;
  label: string;
  failed: boolean;
  warning?: boolean;
  detail: string;
  problems: string[];
}): ExploreAuditCheck {
  return {
    id: args.id,
    label: args.label,
    status: args.failed ? "fail" : args.warning ? "warn" : "pass",
    detail: args.detail,
    problems: args.problems,
  };
}

function artifactAuditCheck(args: {
  id: string;
  label: string;
  required: boolean;
  artifacts: ExploreArtifactEntry[];
}): ExploreAuditCheck {
  const missing = args.artifacts.filter((artifact) => !artifact.exists);
  return makeAuditCheck({
    id: args.id,
    label: args.label,
    failed: args.required && missing.length > 0,
    warning: !args.required && missing.length > 0,
    detail:
      missing.length === 0
        ? `${args.artifacts.length} artifact(s) present`
        : `${missing.length}/${args.artifacts.length} artifact(s) missing`,
    problems: missing.map((artifact) => `${artifact.kind} missing at ${artifact.path}`),
  });
}

function matchingProblems(problems: string[], predicate: (problem: string) => boolean): string[] {
  return problems.filter(predicate);
}

function rankingProblem(problem: string): boolean {
  return problem.startsWith("rankings.") || problem.includes("rankings.json");
}

function attemptProblem(problem: string): boolean {
  return (
    problem.startsWith("attempt ") ||
    problem.startsWith("summary.attempt") ||
    problem.startsWith("summary.completedAttempts") ||
    problem.startsWith("summary.failedAttempts") ||
    problem.includes("attempt dirs")
  );
}

function isolationProblem(problem: string): boolean {
  return (
    problem.includes("runtime is") ||
    problem.includes("network is") ||
    problem.includes("rootfs is not read-only") ||
    problem.includes("no-new-privileges") ||
    problem.includes("drop all capabilities") ||
    problem.includes("privileged flag") ||
    problem.includes("pids limit") ||
    problem.includes("memory limit") ||
    problem.includes("cpu limit") ||
    problem.includes("Docker socket") ||
    problem.includes("missing mount")
  );
}

function validationProblem(problem: string): boolean {
  return problem.includes("validation");
}

function usageProblem(problem: string): boolean {
  return problem.includes("usage");
}

function countRunscContainers(status: ExploreRunStatus): number {
  let count = 0;
  for (const attempt of status.attempts) {
    if (attempt.runtime === EXPLORE_RUNTIME && attempt.networkMode === "none") count += 1;
    if (attempt.validationRuntime === EXPLORE_RUNTIME && attempt.validationNetworkMode === "none") {
      count += 1;
    }
  }
  return count;
}

function exploreNextCommands(projectId: string, runId: string): string[] {
  const args = `--project-id ${shellArg(projectId)} --run-id ${shellArg(runId)}`;
  return [
    `deepsec explore status ${args}`,
    `deepsec explore audit ${args} --fail-on-accepted-findings --min-severity MEDIUM`,
    `deepsec explore findings ${args} --json`,
    `deepsec explore artifacts ${args} --json`,
    `deepsec explore ci ${args} --min-severity MEDIUM`,
    `deepsec report ${args}`,
    `deepsec export ${args} --format sarif --out findings.sarif`,
  ];
}

function shellArg(value: string): string {
  if (/^[A-Za-z0-9._/:=+-]+$/.test(value)) return value;
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function artifactEntry(
  kind: string,
  filePath: string,
  opts: { hashes: boolean },
): ExploreArtifactEntry {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    return { kind, path: resolved, exists: false };
  }
  const bytes = fs.readFileSync(resolved);
  const entry: ExploreArtifactEntry = {
    kind,
    path: resolved,
    exists: true,
    bytes: bytes.length,
  };
  if (opts.hashes) {
    entry.sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  }
  return entry;
}

function printArtifactGroup(label: string, artifacts: ExploreArtifactEntry[]): void {
  console.log(`  ${label}`);
  printArtifactEntries(artifacts, "    ");
}

function printArtifactEntries(artifacts: ExploreArtifactEntry[], indent: string): void {
  for (const artifact of artifacts) {
    const marker = artifact.exists ? `${GREEN}ok${RESET}` : `${YELLOW}missing${RESET}`;
    const size = artifact.bytes === undefined ? "" : ` bytes=${artifact.bytes}`;
    const hash = artifact.sha256 ? ` sha256=${artifact.sha256.slice(0, 12)}` : "";
    console.log(`${indent}${marker} ${artifact.kind}${size}${hash} ${artifact.path}`);
  }
}

function printExploreReport(report: ExploreAttempt["report"], indent: string): void {
  if (report.outcome === "no-bug") {
    console.log(`${indent}outcome: no-bug`);
    console.log(`${indent}summary: ${shorten(report.summary, 220)}`);
    for (const evidence of report.evidence ?? []) {
      console.log(`${indent}evidence: ${shorten(evidence, 180)}`);
    }
    return;
  }
  console.log(`${indent}outcome:    bug`);
  console.log(`${indent}title:      ${report.title}`);
  console.log(`${indent}severity:   ${report.severity}`);
  console.log(`${indent}confidence: ${report.confidence}`);
  console.log(`${indent}slug:       ${report.vulnSlug}`);
  if (report.lineNumbers.length > 0) {
    console.log(`${indent}lines:      ${report.lineNumbers.join(",")}`);
  }
  console.log(`${indent}summary:    ${shorten(report.description, 220)}`);
  for (const step of report.reproductionSteps.slice(0, 5)) {
    console.log(`${indent}repro:      ${shorten(step, 180)}`);
  }
  for (const evidence of report.evidence.slice(0, 5)) {
    console.log(`${indent}evidence:   ${shorten(evidence, 180)}`);
  }
}

function writeExploreCiJunit(args: {
  status: ExploreRunStatus;
  minSeverity: Severity;
  failOnAcceptedFindings: boolean;
  exitCode: number;
  outputs: ExploreCiOutputs;
}): void {
  if (!args.outputs.junitXml) return;
  const acceptedAtThreshold = countAcceptedExploreFindings(args.status, args.minSeverity);
  const gateFails = args.status.ok && args.failOnAcceptedFindings && acceptedAtThreshold > 0;
  const artifactFailure = !args.status.ok
    ? failureXml(
        "explore artifact validation failed",
        args.status.problems.join("\n") || "Explore artifacts are invalid.",
      )
    : "";
  const gateFailure = gateFails
    ? failureXml(
        `accepted findings at or above ${args.minSeverity}`,
        `${acceptedAtThreshold} accepted finding(s) matched the CI threshold.`,
      )
    : "";
  const gateSkipped =
    !args.status.ok && args.failOnAcceptedFindings
      ? '\n      <skipped message="artifact validation failed first" />'
      : "";
  const failures = (artifactFailure ? 1 : 0) + (gateFailure ? 1 : 0);
  const skipped = gateSkipped ? 1 : 0;
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="2" failures="${failures}" skipped="${skipped}">
  <testsuite name="deepsec.explore.ci" tests="2" failures="${failures}" skipped="${skipped}">
    <testcase classname="deepsec.explore.ci" name="explore artifacts">${artifactFailure}
    </testcase>
    <testcase classname="deepsec.explore.ci" name="accepted finding gate">${gateFailure}${gateSkipped}
    </testcase>
    <system-out>${escapeXml(
      JSON.stringify({
        projectId: args.status.projectId,
        runId: args.status.runId,
        exitCode: args.exitCode,
        minSeverity: args.minSeverity,
        acceptedAtThreshold,
      }),
    )}</system-out>
  </testsuite>
</testsuites>
`;
  fs.writeFileSync(args.outputs.junitXml, xml);
}

function failureXml(message: string, details: string): string {
  return `\n      <failure message="${escapeXml(message)}">${escapeXml(details)}</failure>`;
}

function escapeXml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

export function exploreStatusExitCode(
  status: ExploreRunStatus,
  opts: Pick<ExploreStatusOptions, "failOnAcceptedFindings"> & { minSeverity?: Severity } = {},
): number | undefined {
  if (!status.ok) return 1;
  if (opts.failOnAcceptedFindings && countAcceptedExploreFindings(status, opts.minSeverity) > 0) {
    return 2;
  }
  return undefined;
}

export function countAcceptedExploreFindings(
  status: ExploreRunStatus,
  minSeverity?: Severity,
): number {
  if (!minSeverity) {
    return (
      status.summary?.acceptedFindings ??
      status.attempts.filter((attempt) => attempt.acceptedFinding).length
    );
  }
  return status.attempts.filter(
    (attempt) =>
      attempt.acceptedFinding &&
      attempt.bugSeverity !== undefined &&
      severityAtOrAbove(attempt.bugSeverity, minSeverity),
  ).length;
}

export async function exploreCommand(rawOpts: ExploreOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  const profile = assertExploreProfile(opts.profile);
  const runtime = opts.runtime ?? EXPLORE_RUNTIME;
  if (runtime !== EXPLORE_RUNTIME) {
    throw new Error(
      `deepsec explore requires --runtime ${EXPLORE_RUNTIME}; got ${JSON.stringify(runtime)}.`,
    );
  }

  const limit = parsePositiveInt(opts.limit, 3, "--limit");
  const concurrency = parsePositiveInt(opts.concurrency, 1, "--concurrency");
  const maxTurns = parsePositiveInt(opts.maxTurns, 40, "--max-turns");
  const maxTokens = parseOptionalPositiveInt(opts.maxTokens, "--max-tokens");
  const maxCostUsd = parseOptionalPositiveNumber(opts.maxCostUsd, "--max-cost-usd");
  const stubModel = opts.stubModel === true;
  const model = stubModel ? "stub-explore" : (opts.model ?? OPENROUTER_DEFAULT_MODEL);
  const rankModel = stubModel ? "stub-explore" : (opts.rankModel ?? model);
  const resolved = resolveProjectIdForDirect(opts.projectId, opts.root);
  const root = path.resolve(resolved.rootPath);
  ensureProject(resolved.projectId, root);

  const runId = generateRunId();
  const exploreDir = path.join(dataDir(resolved.projectId), "explore", runId);
  fs.mkdirSync(path.join(exploreDir, "attempts"), { recursive: true });
  writeJson(path.join(exploreDir, "metadata.json"), {
    projectId: resolved.projectId,
    runId,
    root,
    profile,
    runtime,
    image: EXPLORE_IMAGE,
    model,
    rankModel,
    stubModel,
    limit,
    concurrency,
    maxTurns,
    maxTokens,
    maxCostUsd,
    integrityManifest: true,
    startedAt: new Date().toISOString(),
  });

  console.log(`DeepSec explore run ${runId}`);
  console.log(`  project: ${resolved.projectId}`);
  console.log(`  root:    ${root}`);
  console.log(`  model:   ${model}`);
  console.log(`  runtime: ${runtime}`);

  console.log("Collecting production file inventory inside gVisor...");
  const inventoryContainer = await createGvisorContainer({
    root,
    runId: `${runId}-rank`,
    focusFile: "ranking",
    runtime,
    image: EXPLORE_IMAGE,
  });
  let files: SourceFileSummary[] = [];
  try {
    writeJson(path.join(exploreDir, "ranking-container.json"), inventoryContainer.metadata);
    files = await collectProductionFileSummariesFromRunner(inventoryContainer);
  } finally {
    await inventoryContainer.cleanup();
  }
  if (files.length === 0) {
    throw new Error(`No production-relevant files found under ${root}.`);
  }
  if (files.length < limit) {
    throw new Error(
      `Only ${files.length} production-relevant files found; cannot run --limit ${limit}.`,
    );
  }

  const client = maybeBudgetModelClient(
    stubModel ? new StubExploreModelClient() : new OpenRouterResponsesClient(),
    { maxTokens, maxCostUsd },
  );
  console.log(`Ranking ${files.length} files with ${rankModel}...`);
  const rankingResponse = await client.complete({
    model: rankModel,
    temperature: 0.1,
    responseFormat: RANKING_RESPONSE_FORMAT,
    messages: [
      { role: "system", content: "You rank source files for local security exploration." },
      { role: "user", content: rankingPrompt(files) },
    ],
  });
  const rankings = normalizeRankings(files, parseRankingsFromText(rankingResponse.text));
  const storedRankings: StoredRankings = {
    projectId: resolved.projectId,
    runId,
    generatedAt: new Date().toISOString(),
    model: rankModel,
    rankings,
  };
  if (rankingResponse.usage) storedRankings.usage = rankingResponse.usage;
  writeJson(path.join(exploreDir, "rankings.json"), storedRankings);

  const selected = selectTopRankedFiles(rankings, limit);
  console.log(`Selected ${selected.length} focused attempts:`);
  for (const [i, ranked] of selected.entries()) {
    console.log(`  ${i + 1}. [${ranked.score}] ${ranked.filePath}`);
  }

  const attemptResults = await mapLimit(selected, concurrency, async (focus, index) => {
    return runFocusedAttempt({
      projectId: resolved.projectId,
      root,
      runId,
      focus,
      selected,
      model,
      maxTurns,
      attemptDir: path.join(exploreDir, "attempts", `${String(index + 1).padStart(2, "0")}`),
      client,
    });
  });
  const attempts = attemptResults
    .filter((result): result is { ok: true; attempt: ExploreAttempt } => result.ok)
    .map((result) => result.attempt);
  const failures = attemptResults
    .filter((result): result is { ok: false; failure: ExploreAttemptFailure } => !result.ok)
    .map((result) => result.failure);

  const summary = refreshExploreSummary({
    projectId: resolved.projectId,
    root,
    runId,
    model,
    exploreDir,
    rankingUsage: rankingResponse.usage,
    attemptsForMerge: attempts,
  });
  writeExploreIntegrityManifest(exploreDir);

  console.log();
  console.log(`${GREEN}Explore complete${RESET}`);
  console.log(`  runId:             ${runId}`);
  console.log(`  attempts:          ${attemptResults.length}`);
  console.log(`  completed:         ${attempts.length}`);
  console.log(`  failed:            ${failures.length}`);
  console.log(`  accepted findings: ${summary.acceptedFindings}`);
  const usageText = formatModelUsage(summary.usage);
  if (usageText) console.log(`  usage:             ${usageText}`);
  if (failures.length > 0) {
    console.log(
      `${YELLOW}One or more focused attempts failed; inspect explore status for details.${RESET}`,
    );
    process.exitCode = 1;
  }
  if (summary.acceptedFindings === 0) {
    console.log(`${YELLOW}No accepted findings were merged into report/export surfaces.${RESET}`);
  }
}

export async function exploreRetryCommand(rawOpts: ExploreRetryOptions): Promise<void> {
  const opts = normalizeCommandOptions(rawOpts);
  assertExploreProfile(opts.profile);
  const runtime = opts.runtime ?? EXPLORE_RUNTIME;
  if (runtime !== EXPLORE_RUNTIME) {
    throw new Error(
      `deepsec explore retry requires --runtime ${EXPLORE_RUNTIME}; got ${JSON.stringify(runtime)}.`,
    );
  }

  const projectId = resolveProjectId(opts.projectId);
  const runId = opts.runId ?? latestExploreRunId(projectId);
  const exploreDir = path.join(dataDir(projectId), "explore", runId);
  if (!fs.existsSync(exploreDir)) {
    throw new Error(`Explore run ${runId} does not exist for project ${projectId}.`);
  }
  const metadata = readJson<Record<string, unknown>>(path.join(exploreDir, "metadata.json"));
  if (!metadata) throw new Error(`Explore run ${runId} is missing metadata.json.`);
  const rankings = readJson<StoredRankings>(path.join(exploreDir, "rankings.json"));
  if (!rankings?.rankings?.length) {
    throw new Error(`Explore run ${runId} is missing rankings.json.`);
  }

  const root = path.resolve(opts.root ?? (typeof metadata.root === "string" ? metadata.root : "."));
  const limit = parsePositiveInt(
    opts.limit,
    typeof metadata.limit === "number" ? metadata.limit : 3,
    "--limit",
  );
  const concurrency = parsePositiveInt(opts.concurrency, 1, "--concurrency");
  const maxTokens = parseOptionalPositiveInt(opts.maxTokens, "--max-tokens");
  const maxCostUsd = parseOptionalPositiveNumber(opts.maxCostUsd, "--max-cost-usd");
  const maxTurns = parsePositiveInt(
    opts.maxTurns,
    typeof metadata.maxTurns === "number" ? metadata.maxTurns : 40,
    "--max-turns",
  );
  const stubModel = opts.stubModel === true || metadata.stubModel === true;
  const model = stubModel
    ? "stub-explore"
    : (opts.model ??
      (typeof metadata.model === "string" ? metadata.model : OPENROUTER_DEFAULT_MODEL));
  const client = maybeBudgetModelClient(
    stubModel ? new StubExploreModelClient() : new OpenRouterResponsesClient(),
    { maxTokens, maxCostUsd },
  );
  const selected = selectTopRankedFiles(rankings.rankings, limit);
  const retryTargets = selected
    .map((focus, index) => ({
      focus,
      index,
      attemptDir: path.join(exploreDir, "attempts", `${String(index + 1).padStart(2, "0")}`),
    }))
    .filter((target) => opts.all || shouldRetryAttempt(target.attemptDir));

  console.log(`DeepSec explore retry ${runId}`);
  console.log(`  project: ${projectId}`);
  console.log(`  root:    ${root}`);
  console.log(`  model:   ${model}`);
  console.log(`  runtime: ${runtime}`);
  console.log(
    `  targets: ${retryTargets.length}${opts.all ? " (all selected attempts)" : " failed/missing attempts"}`,
  );

  if (retryTargets.length === 0) {
    console.log(`${GREEN}No failed or missing attempts to retry.${RESET}`);
    return;
  }

  const results = await mapLimit(retryTargets, concurrency, async (target) => {
    resetAttemptDir(target.attemptDir);
    return runFocusedAttempt({
      projectId,
      root,
      runId,
      focus: target.focus,
      selected,
      model,
      maxTurns,
      attemptDir: target.attemptDir,
      client,
    });
  });

  const summary = refreshExploreSummary({
    projectId,
    root,
    runId,
    model,
    exploreDir,
    rankingUsage: rankings.usage,
    attemptsForMerge: results
      .filter((result): result is { ok: true; attempt: ExploreAttempt } => result.ok)
      .map((result) => result.attempt),
  });
  writeExploreIntegrityManifest(exploreDir);
  const failures = results.filter((result) => !result.ok).length;

  console.log();
  console.log(`${failures === 0 ? GREEN : YELLOW}Explore retry complete${RESET}`);
  console.log(`  runId:             ${runId}`);
  console.log(`  retried:           ${results.length}`);
  console.log(`  failed:            ${failures}`);
  console.log(`  accepted findings: ${summary.acceptedFindings}`);
  const usageText = formatModelUsage(summary.usage);
  if (usageText) console.log(`  usage:             ${usageText}`);
  if (failures > 0 || summary.failedAttempts > 0) process.exitCode = 1;
}

function refreshExploreSummary(args: {
  projectId: string;
  root: string;
  runId: string;
  model: string;
  exploreDir: string;
  rankingUsage?: ModelUsage;
  attemptsForMerge?: ExploreAttempt[];
}): ExploreSummary {
  for (const attempt of args.attemptsForMerge ?? []) {
    mergeAcceptedExploreAttempt({
      projectId: args.projectId,
      root: args.root,
      runId: args.runId,
      model: args.model,
      attempt,
    });
  }

  const { attempts, failures } = readAttemptArtifacts(path.join(args.exploreDir, "attempts"));
  const attemptUsage = sumModelUsages(attempts.map((attempt) => attempt.usage));
  const totalUsage = sumModelUsages([args.rankingUsage, attemptUsage]);
  const summary: ExploreSummary = {
    projectId: args.projectId,
    runId: args.runId,
    completedAt: new Date().toISOString(),
    attempts: attempts.length + failures.length,
    completedAttempts: attempts.length,
    failedAttempts: failures.length,
    bugsReported: attempts.filter((attempt) => attempt.report.outcome === "bug").length,
    acceptedFindings: attempts.filter(
      (attempt) => attempt.report.outcome === "bug" && isAccepted(attempt.validation),
    ).length,
  };
  if (args.rankingUsage) summary.rankingUsage = args.rankingUsage;
  if (attemptUsage) summary.attemptUsage = attemptUsage;
  if (totalUsage) summary.usage = totalUsage;
  writeJson(path.join(args.exploreDir, "summary.json"), summary);
  return summary;
}

function readAttemptArtifacts(attemptsDir: string): {
  attempts: ExploreAttempt[];
  failures: ExploreAttemptFailure[];
} {
  if (!fs.existsSync(attemptsDir)) return { attempts: [], failures: [] };
  const attempts: ExploreAttempt[] = [];
  const failures: ExploreAttemptFailure[] = [];
  for (const entry of fs.readdirSync(attemptsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(attemptsDir, entry.name);
    const attempt = readJson<ExploreAttempt>(path.join(dir, "attempt.json"));
    if (attempt) {
      attempts.push(attempt);
      continue;
    }
    const failure = readJson<ExploreAttemptFailure>(path.join(dir, "attempt-error.json"));
    if (failure) failures.push(failure);
  }
  return { attempts, failures };
}

function shouldRetryAttempt(attemptDir: string): boolean {
  return (
    !fs.existsSync(path.join(attemptDir, "attempt.json")) ||
    fs.existsSync(path.join(attemptDir, "attempt-error.json"))
  );
}

function resetAttemptDir(attemptDir: string): void {
  fs.rmSync(attemptDir, { recursive: true, force: true });
  fs.mkdirSync(attemptDir, { recursive: true });
}

async function runFocusedAttempt(args: {
  projectId: string;
  root: string;
  runId: string;
  focus: RankedFile;
  selected: RankedFile[];
  model: string;
  maxTurns: number;
  attemptDir: string;
  client: ModelClient;
}): Promise<FocusedAttemptResult> {
  fs.mkdirSync(args.attemptDir, { recursive: true });
  console.log(`Starting gVisor attempt for ${args.focus.filePath}...`);
  let container: Awaited<ReturnType<typeof createGvisorContainer>> | null = null;
  try {
    container = await createGvisorContainer({
      root: args.root,
      runId: args.runId,
      focusFile: args.focus.filePath,
      runtime: EXPLORE_RUNTIME,
      image: EXPLORE_IMAGE,
    });
    const attempt = await runAgenticExploreLoop({
      projectId: args.projectId,
      runId: args.runId,
      focus: args.focus,
      topFiles: args.selected,
      model: args.model,
      maxTurns: args.maxTurns,
      client: args.client,
      runner: container,
      container: container.metadata,
      onProgress: (event) => recordExploreProgress(args.attemptDir, args.focus.filePath, event),
    });
    if (attempt.report.outcome === "bug") {
      const validationContainer = await createGvisorContainer({
        root: args.root,
        runId: `${args.runId}-validate-${path.basename(args.attemptDir)}`,
        focusFile: `${args.focus.filePath} validation`,
        runtime: EXPLORE_RUNTIME,
        image: EXPLORE_IMAGE,
      }).catch((err) => {
        attempt.validation = {
          verdict: "uncertain",
          reproducible: false,
          interesting: false,
          reasoning: `Validation container failed: ${err instanceof Error ? err.message : String(err)}`,
        };
        return null;
      });
      if (validationContainer) {
        try {
          const validation = await validateBugReport({
            client: args.client,
            model: args.model,
            report: attempt.report,
            transcript: attempt.transcript,
            runner: validationContainer,
            container: validationContainer.metadata,
            maxTurns: Math.min(args.maxTurns, 8),
            onProgress: (event) =>
              recordExploreProgress(
                args.attemptDir,
                `${args.focus.filePath} validation`,
                event,
                "validation-events.jsonl",
              ),
          }).catch(
            (err): ValidationResult => ({
              verdict: {
                verdict: "uncertain" as const,
                reproducible: false,
                interesting: false,
                reasoning: `Validation failed: ${err instanceof Error ? err.message : String(err)}`,
              },
              container: validationContainer.metadata,
            }),
          );
          attempt.validation = validation.verdict;
          attempt.validationContainer = validation.container;
          attempt.validationTranscript = validation.transcript;
          attempt.validationTurns = validation.turns;
          if (validation.usage) {
            attempt.validationUsage = validation.usage;
            attempt.usage = addModelUsage(attempt.usage, validation.usage);
          }
        } finally {
          await validationContainer.cleanup();
        }
      } else if (!attempt.validation) {
        attempt.validation = {
          verdict: "uncertain",
          reproducible: false,
          interesting: false,
          reasoning: "Validation container was not available.",
        };
      }
    }
    const workspaceChanges = collectWorkspaceChanges(args.root, container.targetRoot());
    attempt.workspaceChanges = workspaceChanges;
    writeJson(path.join(args.attemptDir, "workspace-changes.json"), workspaceChanges);
    writeJson(path.join(args.attemptDir, "attempt.json"), attempt);
    console.log(
      `Finished ${args.focus.filePath}: ${attempt.report.outcome}${
        attempt.validation ? ` (${attempt.validation.verdict})` : ""
      }`,
    );
    return { ok: true, attempt };
  } catch (err) {
    const failure: ExploreAttemptFailure = {
      projectId: args.projectId,
      runId: args.runId,
      focusFile: args.focus.filePath,
      model: args.model,
      failedAt: new Date().toISOString(),
      error: err instanceof Error ? err.message : String(err),
    };
    if (container?.metadata) failure.container = container.metadata;
    writeJson(path.join(args.attemptDir, "attempt-error.json"), failure);
    console.log(
      `${YELLOW}Failed ${args.focus.filePath}: ${
        err instanceof Error ? err.message : String(err)
      }${RESET}`,
    );
    return { ok: false, failure };
  } finally {
    await container?.cleanup();
  }
}

function recordExploreProgress(
  attemptDir: string,
  focusFile: string,
  event: ExploreProgressEvent,
  fileName = "events.jsonl",
): void {
  fs.appendFileSync(
    path.join(attemptDir, fileName),
    JSON.stringify({ focusFile, ...event }) + "\n",
  );
  const message = formatExploreProgress(event);
  if (message) {
    console.log(`  ${focusFile}: ${message}`);
  }
}

function formatExploreProgress(event: ExploreProgressEvent): string | null {
  const turn = `turn ${event.turn}/${event.maxTurns}`;
  switch (event.type) {
    case "model-request":
      return `${turn}: model${event.finalTurn ? " final" : ""} request`;
    case "model-response": {
      const usage = formatModelUsage(event.usage);
      return `${turn}: model response (${event.responseChars} chars)${usage ? ` ${usage}` : ""}`;
    }
    case "repair":
      return `${turn}: repairing malformed model JSON (${shorten(event.error, 100)})`;
    case "action":
      return `${turn}: run ${shorten(event.command, 140)}${event.redacted ? " redacted" : ""}`;
    case "command-result":
      return `${turn}: exit ${event.exitCode} in ${event.durationMs}ms${
        event.timedOut ? " timed out" : ""
      }${event.truncated ? " truncated" : ""}${event.redacted ? " redacted" : ""}`;
    case "final":
      return `${turn}: final ${event.outcome}`;
    case "final-turn-command-denied":
      return `${turn}: denied final-turn command ${shorten(event.command, 100)}${
        event.redacted ? " redacted" : ""
      }`;
  }
}

function shorten(value: string, max: number): string {
  const normalized = value.replace(/\s+/g, " ").trim();
  if (normalized.length <= max) return normalized;
  return `${normalized.slice(0, max - 1)}…`;
}

async function mapLimit<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length) as R[];
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index]!, index);
    }
  });
  await Promise.all(workers);
  return results;
}

function parsePositiveInt(value: number | undefined, fallback: number, label: string): number {
  const n = value ?? fallback;
  if (!Number.isInteger(n) || n <= 0) throw new Error(`${label} must be a positive integer.`);
  return n;
}

function parseOptionalPositiveInt(value: number | undefined, label: string): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

function parseOptionalPositiveNumber(value: number | undefined, label: string): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${label} must be a positive number.`);
  }
  return value;
}

function writeJson(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + "\n");
}

function readJson<T>(file: string): T | null {
  try {
    return JSON.parse(fs.readFileSync(file, "utf-8")) as T;
  } catch {
    return null;
  }
}

async function check<T>(label: string, fn: () => T | Promise<T>): Promise<T> {
  try {
    const result = await fn();
    console.log(`  ${GREEN}ok${RESET} ${label}`);
    return result;
  } catch (err) {
    console.log(`  ${YELLOW}fail${RESET} ${label}`);
    throw err;
  }
}

function normalizeCommandOptions<T extends object>(opts: T): T {
  const maybeCommand = opts as T & { opts?: () => T };
  if (typeof maybeCommand.opts === "function") {
    return maybeCommand.opts();
  }
  return opts;
}
