import os from "node:os";
import path from "node:path";

const MAX_TEXT = 320;
const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const EVENT_KINDS = new Set([
  "harness-phase",
  "harness-complete",
  "run-start",
  "ranking",
  "ranking-done",
  "attempt-queued",
  "attempt-start",
  "attempt-finish",
  "attempt-fail",
  "run-complete",
  "progress",
  "attempt-hydrated",
  "attempt-error-hydrated",
  "summary-hydrated",
  "bridge-state",
  "supervisor-pulse",
  "canvas-reset",
  "replay-reset",
]);

export function isSafeSegment(value) {
  return typeof value === "string" && SAFE_SEGMENT.test(value);
}

export function sanitizeText(value, maxLength = MAX_TEXT) {
  if (typeof value !== "string") return undefined;
  let text = value
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]")
    .replace(
      /\b(api[-_]?key|access[-_]?token|auth[-_]?token|password|passwd|secret)\s*[:=]\s*[^\s,;]+/gi,
      "$1=[redacted]",
    )
    .replace(/\b(?:gh[opusr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b/g, "[redacted]");
  const home = os.homedir();
  if (home) text = text.split(home).join("~");
  text = text.replace(/\s+/g, " ").trim();
  if (text.length > maxLength) return `${text.slice(0, Math.max(0, maxLength - 1))}…`;
  return text;
}

function safeString(value, maxLength = MAX_TEXT) {
  return sanitizeText(value, maxLength);
}

function safeInteger(value, min = 0, max = Number.MAX_SAFE_INTEGER) {
  return Number.isInteger(value) && value >= min && value <= max ? value : undefined;
}

function safeNumber(value, min = 0, max = Number.MAX_SAFE_INTEGER) {
  return typeof value === "number" && Number.isFinite(value) && value >= min && value <= max
    ? value
    : undefined;
}

function safeBoolean(value) {
  return typeof value === "boolean" ? value : undefined;
}

function compact(object) {
  return Object.fromEntries(Object.entries(object).filter(([, value]) => value !== undefined));
}

function sanitizeUsage(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const usage = compact({
    inputTokens: safeInteger(value.inputTokens),
    outputTokens: safeInteger(value.outputTokens),
    costUsd: safeNumber(value.costUsd),
  });
  return Object.keys(usage).length > 0 ? usage : undefined;
}

function commandType(command) {
  if (typeof command !== "string") return undefined;
  const normalized = command.trim().replace(/^(?:env\s+)?(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*/, "");
  const executable = normalized.match(/^([A-Za-z0-9_./+-]+)/)?.[1];
  if (!executable) return "shell";
  return path.basename(executable).slice(0, 48);
}

function sanitizeProgressEvent(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const base = compact({
    type: safeString(value.type, 48),
    at: safeString(value.at, 64),
    turn: safeInteger(value.turn, 0, 10_000),
    maxTurns: safeInteger(value.maxTurns, 1, 10_000),
  });
  switch (value.type) {
    case "model-request":
      return compact({ ...base, finalTurn: safeBoolean(value.finalTurn) });
    case "model-response":
      return compact({
        ...base,
        responseChars: safeInteger(value.responseChars),
        usage: sanitizeUsage(value.usage),
      });
    case "repair":
      return compact({ ...base, error: safeString(value.error) });
    case "action":
      return compact({
        ...base,
        action: value.action === "run_command" ? "run_command" : "action",
        commandType: commandType(value.command),
        timeoutMs: safeInteger(value.timeoutMs),
        reason: safeString(value.reason),
        redacted: true,
      });
    case "command-result":
      return compact({
        ...base,
        commandType: commandType(value.command),
        exitCode: safeInteger(value.exitCode, -255, 255),
        durationMs: safeInteger(value.durationMs),
        timedOut: safeBoolean(value.timedOut),
        truncated: safeBoolean(value.truncated),
        redacted: true,
        stdoutBytes: safeInteger(value.stdoutBytes),
        stderrBytes: safeInteger(value.stderrBytes),
      });
    case "final":
      return compact({ ...base, outcome: safeString(value.outcome, 48) });
    case "final-turn-command-denied":
      return compact({
        ...base,
        commandType: commandType(value.command),
        redacted: true,
      });
    default:
      return compact({ ...base, type: "unknown-progress" });
  }
}

function sanitizeFinding(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const lineNumbers = Array.isArray(value.lineNumbers)
    ? value.lineNumbers
        .map((line) => safeInteger(line, 1, 10_000_000))
        .filter((line) => line !== undefined)
        .slice(0, 32)
    : undefined;
  return compact({
    outcome: safeString(value.outcome, 32),
    title: safeString(value.title, 180),
    severity: safeString(value.severity, 32),
    confidence: safeString(value.confidence, 32),
    vulnSlug: safeString(value.vulnSlug, 96),
    lineNumbers,
  });
}

function sanitizeValidation(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return compact({
    verdict: safeString(value.verdict, 32),
    reproducible: safeBoolean(value.reproducible),
    interesting: safeBoolean(value.interesting),
    adjustedSeverity: safeString(value.adjustedSeverity, 32),
  });
}

export function sanitizeCanvasEvent(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return undefined;
  if (!EVENT_KINDS.has(input.kind)) return undefined;

  const common = compact({
    kind: input.kind,
    at: safeString(input.at, 64) ?? new Date().toISOString(),
    projectId: isSafeSegment(input.projectId) ? input.projectId : undefined,
    runId: isSafeSegment(input.runId) ? input.runId : undefined,
    attemptIndex: safeInteger(input.attemptIndex, 0, 100_000),
    focusFile: safeString(input.focusFile, 512),
    phase: safeString(input.phase, 64),
    status: safeString(input.status, 64),
    detail: safeString(input.detail),
    outcome: safeString(input.outcome, 48),
  });

  if (input.kind === "progress") {
    const progress = sanitizeProgressEvent(input.event);
    if (!progress) return undefined;
    return compact({ ...common, event: progress });
  }

  if (input.kind === "harness-complete") {
    return compact({
      ...common,
      exitCode: safeInteger(input.exitCode, -255, 255),
      artifacts: compact({
        manifest: safeString(input.manifest, 512),
        bundle: safeString(input.bundle, 512),
      }),
    });
  }

  if (input.kind === "attempt-hydrated") {
    return compact({
      ...common,
      model: safeString(input.model, 96),
      startedAt: safeString(input.startedAt, 64),
      completedAt: safeString(input.completedAt, 64),
      turns: safeInteger(input.turns, 0, 10_000),
      finding: sanitizeFinding(input.finding),
      validation: sanitizeValidation(input.validation),
      validationTurns: safeInteger(input.validationTurns, 0, 10_000),
      usage: sanitizeUsage(input.usage),
      isolation: input.isolation
        ? compact({
            runtime: safeString(input.isolation.runtime, 32),
            networkMode: safeString(input.isolation.networkMode, 32),
            readOnlyRootfs: safeBoolean(input.isolation.readOnlyRootfs),
            noNewPrivileges: safeBoolean(input.isolation.noNewPrivileges),
          })
        : undefined,
      workspaceChanges: safeInteger(input.workspaceChanges),
    });
  }

  if (input.kind === "attempt-error-hydrated") {
    return compact({
      ...common,
      model: safeString(input.model, 96),
      failedAt: safeString(input.failedAt, 64),
      error: safeString(input.error),
    });
  }

  if (input.kind === "summary-hydrated") {
    return compact({
      ...common,
      attempts: safeInteger(input.attempts),
      completedAttempts: safeInteger(input.completedAttempts),
      failedAttempts: safeInteger(input.failedAttempts),
      bugsReported: safeInteger(input.bugsReported),
      acceptedFindings: safeInteger(input.acceptedFindings),
      usage: sanitizeUsage(input.usage),
    });
  }

  if (input.kind === "bridge-state") {
    return compact({
      ...common,
      state: safeString(input.state, 48),
      mode: safeString(input.mode, 32),
      exitCode: safeInteger(input.exitCode, -255, 255),
      signal: safeString(input.signal, 32),
      sessionId: isSafeSegment(input.sessionId) ? input.sessionId : undefined,
    });
  }

  if (input.kind === "supervisor-pulse") {
    return compact({
      ...common,
      state: safeString(input.state, 48),
      processAlive: safeBoolean(input.processAlive),
      containerCount: safeInteger(input.containerCount, 0, 1_000),
      clientCount: safeInteger(input.clientCount, 0, 10_000),
      eventAgeMs: safeInteger(input.eventAgeMs),
      quiet: safeBoolean(input.quiet),
      stalled: safeBoolean(input.stalled),
    });
  }

  if (input.kind === "canvas-reset" || input.kind === "replay-reset") {
    return compact({
      ...common,
      sessionId: isSafeSegment(input.sessionId) ? input.sessionId : undefined,
      mode: safeString(input.mode, 32),
      reason: safeString(input.reason, 160),
      targetIndex: safeInteger(input.targetIndex, 0, 250_000),
    });
  }

  return common;
}

export function sanitizeError(error) {
  return sanitizeText(error instanceof Error ? error.message : String(error), 500) ?? "Unknown error";
}

export function sanitizeLogLine(line) {
  const text = sanitizeText(line, 240);
  if (!text) return undefined;
  if (text.includes("@@deepsec:event@@")) return undefined;
  if (/^\s*(?:\$|>|command:|running command)/i.test(text)) return "DeepSec executed a sandbox action.";
  return text;
}
