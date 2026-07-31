import fs from "node:fs/promises";
import path from "node:path";
import { isSafeSegment, sanitizeCanvasEvent, sanitizeError } from "./sanitize.mjs";

const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;

function artifactPath(dataRoot, projectId, runId, ...segments) {
  if (!isSafeSegment(projectId) || !isSafeSegment(runId)) {
    throw new Error("Unsafe project or run identifier in artifact event.");
  }
  const base = path.resolve(dataRoot);
  const candidate = path.resolve(base, projectId, "explore", runId, ...segments);
  if (candidate !== base && !candidate.startsWith(`${base}${path.sep}`)) {
    throw new Error("Artifact path escaped the configured data root.");
  }
  return { base, candidate };
}

async function readJsonArtifact(dataRoot, projectId, runId, segments) {
  const { base, candidate } = artifactPath(dataRoot, projectId, runId, ...segments);
  const stat = await fs.lstat(candidate);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Artifact is not a regular file.");
  if (stat.size > MAX_ARTIFACT_BYTES) throw new Error("Artifact exceeds the canvas hydration limit.");
  const realBase = await fs.realpath(base);
  const realCandidate = await fs.realpath(candidate);
  if (realCandidate !== realBase && !realCandidate.startsWith(`${realBase}${path.sep}`)) {
    throw new Error("Artifact symlink escaped the configured data root.");
  }
  return JSON.parse(await fs.readFile(realCandidate, "utf8"));
}

function attemptDirName(attemptIndex) {
  if (!Number.isInteger(attemptIndex) || attemptIndex < 0 || attemptIndex > 99_999) {
    throw new Error("Invalid attempt index.");
  }
  return String(attemptIndex + 1).padStart(2, "0");
}

export async function hydrateAttempt({ dataRoot, projectId, runId, attemptIndex }) {
  const attempt = await readJsonArtifact(dataRoot, projectId, runId, [
    "attempts",
    attemptDirName(attemptIndex),
    "attempt.json",
  ]);
  const report = attempt?.report && typeof attempt.report === "object" ? attempt.report : {};
  const workspace =
    attempt?.workspaceChanges && typeof attempt.workspaceChanges === "object"
      ? attempt.workspaceChanges
      : {};
  return sanitizeCanvasEvent({
    kind: "attempt-hydrated",
    at: attempt.completedAt ?? new Date().toISOString(),
    projectId,
    runId,
    attemptIndex,
    focusFile: attempt.focusFile,
    model: attempt.model,
    startedAt: attempt.startedAt,
    completedAt: attempt.completedAt,
    turns: attempt.turns,
    finding: {
      outcome: report.outcome,
      title: report.title,
      severity: report.severity,
      confidence: report.confidence,
      vulnSlug: report.vulnSlug,
      lineNumbers: report.lineNumbers,
    },
    validation: attempt.validation,
    validationTurns: attempt.validationTurns,
    usage: attempt.usage,
    isolation: {
      runtime: attempt.container?.runtime,
      networkMode: attempt.container?.networkMode,
      readOnlyRootfs: attempt.container?.readOnlyRootfs,
      noNewPrivileges: attempt.container?.noNewPrivileges,
    },
    workspaceChanges: workspace.totalChanges,
  });
}

export async function hydrateAttemptFailure({ dataRoot, projectId, runId, attemptIndex }) {
  const failure = await readJsonArtifact(dataRoot, projectId, runId, [
    "attempts",
    attemptDirName(attemptIndex),
    "attempt-error.json",
  ]);
  return sanitizeCanvasEvent({
    kind: "attempt-error-hydrated",
    at: failure.failedAt ?? new Date().toISOString(),
    projectId,
    runId,
    attemptIndex,
    focusFile: failure.focusFile,
    model: failure.model,
    failedAt: failure.failedAt,
    error: failure.error,
  });
}

export async function hydrateSummary({ dataRoot, projectId, runId }) {
  const summary = await readJsonArtifact(dataRoot, projectId, runId, ["summary.json"]);
  return sanitizeCanvasEvent({
    kind: "summary-hydrated",
    at: new Date().toISOString(),
    projectId,
    runId,
    attempts: summary.attempts,
    completedAttempts: summary.completedAttempts,
    failedAttempts: summary.failedAttempts,
    bugsReported: summary.bugsReported,
    acceptedFindings: summary.acceptedFindings,
    usage: summary.usage,
  });
}

export async function retryArtifactHydration(hydrate, attempts = 8, delayMs = 125) {
  let lastError;
  for (let index = 0; index < attempts; index += 1) {
    try {
      return await hydrate();
    } catch (error) {
      lastError = error;
      if (error?.code !== "ENOENT" && !(error instanceof SyntaxError)) break;
      await new Promise((resolve) => setTimeout(resolve, delayMs * (index + 1)));
    }
  }
  throw new Error(`Artifact hydration failed: ${sanitizeError(lastError)}`);
}

