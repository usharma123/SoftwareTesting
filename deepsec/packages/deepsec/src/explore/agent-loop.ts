import type { Confidence, Severity } from "@deepsec/core";
import {
  assertSafeContainerCommand,
  redactCommandExecution,
  redactSensitiveText,
  sanitizeTimeoutMs,
  summarizeExecution,
} from "./command-policy.js";
import { asNumberArray, asRecord, asString, asStringArray, extractJsonValue } from "./json.js";
import {
  commandObservationPrompt,
  exploreInitialPrompt,
  exploreRepairPrompt,
  exploreSystemPrompt,
  finalExploreTurnPrompt,
  finalValidationTurnPrompt,
  validationPrompt,
  validationRepairPrompt,
} from "./prompts.js";
import { JSON_OBJECT_RESPONSE_FORMAT } from "./response-formats.js";
import type {
  BugReport,
  ContainerMetadata,
  ContainerRunner,
  ExploreAttempt,
  ExploreProgressEvent,
  ExploreReport,
  ModelClient,
  ModelMessage,
  ModelUsage,
  RankedFile,
  ValidationResult,
  ValidationVerdict,
} from "./types.js";
import { addModelUsage } from "./usage.js";

const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG", "LOW"]);
const CONFIDENCES = new Set(["high", "medium", "low"]);
const MAX_REPAIR_ATTEMPTS_PER_TURN = 1;
type ExploreProgressEventInput = {
  [Event in ExploreProgressEvent as Event["type"]]: Omit<Event, "at">;
}[ExploreProgressEvent["type"]];

export async function runAgenticExploreLoop(args: {
  projectId: string;
  runId: string;
  focus: RankedFile;
  topFiles: RankedFile[];
  model: string;
  maxTurns: number;
  client: ModelClient;
  runner: ContainerRunner;
  container: ContainerMetadata;
  onProgress?: (event: ExploreProgressEvent) => void;
}): Promise<ExploreAttempt> {
  const startedAt = new Date().toISOString();
  const messages: ModelMessage[] = [
    { role: "system", content: exploreSystemPrompt() },
    {
      role: "user",
      content: exploreInitialPrompt({
        projectId: args.projectId,
        focus: args.focus,
        topFiles: args.topFiles,
        maxTurns: args.maxTurns,
      }),
    },
  ];
  const transcript: ExploreAttempt["transcript"] = [];
  let usage: ModelUsage | undefined;

  for (let turn = 1; turn <= args.maxTurns; turn++) {
    if (turn === args.maxTurns) {
      messages.push({
        role: "user",
        content: finalExploreTurnPrompt(),
      });
    }
    let action: ReturnType<typeof parseExploreAction> | undefined;
    for (let repairAttempt = 0; repairAttempt <= MAX_REPAIR_ATTEMPTS_PER_TURN; repairAttempt++) {
      emitProgress(args.onProgress, {
        type: "model-request",
        turn,
        maxTurns: args.maxTurns,
        finalTurn: turn === args.maxTurns,
      });
      const response = await args.client.complete({
        model: args.model,
        messages: trimMessages(messages),
        temperature: 0.2,
        responseFormat: JSON_OBJECT_RESPONSE_FORMAT,
      });
      usage = addModelUsage(usage, response.usage);
      const responseEvent: ExploreProgressEventInput = {
        type: "model-response",
        turn,
        maxTurns: args.maxTurns,
        responseChars: response.text.length,
      };
      if (response.usage) responseEvent.usage = response.usage;
      emitProgress(args.onProgress, responseEvent);
      messages.push({ role: "assistant", content: response.text });
      transcript.push({ role: "assistant", content: response.text });
      try {
        action = parseExploreAction(response.text);
        break;
      } catch (err) {
        emitProgress(args.onProgress, {
          type: "repair",
          turn,
          maxTurns: args.maxTurns,
          error: err instanceof Error ? err.message : String(err),
        });
        messages.push({
          role: "user",
          content: exploreRepairPrompt(err instanceof Error ? err.message : String(err)),
        });
      }
    }
    if (!action) continue;
    if (action.action === "final") {
      emitProgress(args.onProgress, {
        type: "final",
        turn,
        maxTurns: args.maxTurns,
        outcome: action.result.outcome,
      });
      return withUsage(
        {
          projectId: args.projectId,
          runId: args.runId,
          focusFile: args.focus.filePath,
          model: args.model,
          startedAt,
          completedAt: new Date().toISOString(),
          turns: turn,
          container: args.container,
          transcript,
          report: action.result,
        },
        usage,
      );
    }

    if (turn === args.maxTurns) {
      const displayCommand = redactSensitiveText(action.command);
      emitProgress(args.onProgress, {
        type: "final-turn-command-denied",
        turn,
        maxTurns: args.maxTurns,
        command: displayCommand.text,
        redacted: displayCommand.redacted,
      });
      return withUsage(
        {
          projectId: args.projectId,
          runId: args.runId,
          focusFile: args.focus.filePath,
          model: args.model,
          startedAt,
          completedAt: new Date().toISOString(),
          turns: turn,
          container: args.container,
          transcript,
          report: {
            outcome: "no-bug",
            summary:
              "The model requested another command on the final allowed turn instead of returning a structured report.",
            evidence: recentToolEvidence(transcript),
          },
        },
        usage,
      );
    }

    assertSafeContainerCommand(action.command);
    const displayCommand = redactSensitiveText(action.command);
    emitProgress(args.onProgress, {
      type: "action",
      turn,
      maxTurns: args.maxTurns,
      action: "run_command",
      command: displayCommand.text,
      timeoutMs: action.timeoutMs,
      reason: action.reason,
      redacted: displayCommand.redacted,
    });
    const execution = redactCommandExecution(
      await args.runner.exec(action.command, action.timeoutMs),
    );
    emitProgress(args.onProgress, {
      type: "command-result",
      turn,
      maxTurns: args.maxTurns,
      command: execution.command,
      exitCode: execution.exitCode,
      durationMs: execution.durationMs,
      timedOut: execution.timedOut,
      truncated: execution.truncated,
      redacted: execution.redacted === true,
      stdoutBytes: execution.stdout.length,
      stderrBytes: execution.stderr.length,
    });
    transcript.push({ role: "tool", content: execution });
    messages.push({ role: "user", content: commandObservationPrompt(execution) });
  }

  return withUsage(
    {
      projectId: args.projectId,
      runId: args.runId,
      focusFile: args.focus.filePath,
      model: args.model,
      startedAt,
      completedAt: new Date().toISOString(),
      turns: args.maxTurns,
      container: args.container,
      transcript,
      report: {
        outcome: "no-bug",
        summary: `Reached max turns (${args.maxTurns}) without a structured bug report.`,
        evidence: recentToolEvidence(transcript),
      },
    },
    usage,
  );
}

export async function validateBugReport(args: {
  client: ModelClient;
  model: string;
  report: BugReport;
  transcript: ExploreAttempt["transcript"];
  runner?: ContainerRunner;
  container?: ContainerMetadata;
  maxTurns?: number;
  onProgress?: (event: ExploreProgressEvent) => void;
}): Promise<ValidationResult> {
  const transcriptTail = args.transcript
    .slice(-8)
    .map((entry) =>
      typeof entry.content === "string" ? entry.content : summarizeExecution(entry.content),
    )
    .join("\n\n---\n\n")
    .slice(-16_000);
  if (!args.runner) {
    const response = await args.client.complete({
      model: args.model,
      temperature: 0.1,
      responseFormat: JSON_OBJECT_RESPONSE_FORMAT,
      messages: [
        { role: "system", content: "You validate bounded local security bug reports." },
        { role: "user", content: validationPrompt(args.report, transcriptTail) },
      ],
    });
    const action = parseValidationAction(response.text);
    const verdict =
      action.action === "final"
        ? action.verdict
        : {
            verdict: "uncertain" as const,
            reproducible: false,
            interesting: false,
            reasoning: "Validation requested a command but no command runner was available.",
          };
    const result: ValidationResult = { verdict };
    if (response.usage) result.usage = response.usage;
    return result;
  }

  const maxTurns = Math.max(2, Math.min(args.maxTurns ?? 8, 12));
  const messages: ModelMessage[] = [
    { role: "system", content: "You validate bounded local security bug reports." },
    { role: "user", content: validationPrompt(args.report, transcriptTail) },
  ];
  const transcript: ExploreAttempt["transcript"] = [];
  let usage: ModelUsage | undefined;

  for (let turn = 1; turn <= maxTurns; turn++) {
    if (turn === maxTurns) {
      messages.push({
        role: "user",
        content: finalValidationTurnPrompt(),
      });
    }
    let action: ReturnType<typeof parseValidationAction> | undefined;
    for (let repairAttempt = 0; repairAttempt <= MAX_REPAIR_ATTEMPTS_PER_TURN; repairAttempt++) {
      emitProgress(args.onProgress, {
        type: "model-request",
        turn,
        maxTurns,
        finalTurn: turn === maxTurns,
      });
      const response = await args.client.complete({
        model: args.model,
        messages: trimMessages(messages),
        temperature: 0.1,
        responseFormat: JSON_OBJECT_RESPONSE_FORMAT,
      });
      usage = addModelUsage(usage, response.usage);
      const responseEvent: ExploreProgressEventInput = {
        type: "model-response",
        turn,
        maxTurns,
        responseChars: response.text.length,
      };
      if (response.usage) responseEvent.usage = response.usage;
      emitProgress(args.onProgress, responseEvent);
      messages.push({ role: "assistant", content: response.text });
      transcript.push({ role: "assistant", content: response.text });
      try {
        action = parseValidationAction(response.text);
        break;
      } catch (err) {
        emitProgress(args.onProgress, {
          type: "repair",
          turn,
          maxTurns,
          error: err instanceof Error ? err.message : String(err),
        });
        messages.push({
          role: "user",
          content: validationRepairPrompt(err instanceof Error ? err.message : String(err)),
        });
      }
    }
    if (!action) continue;

    if (action.action === "final") {
      emitProgress(args.onProgress, {
        type: "final",
        turn,
        maxTurns,
        outcome: action.verdict.verdict === "true-positive" ? "bug" : "no-bug",
      });
      return withValidationMetadata(
        {
          verdict: action.verdict,
          transcript,
          turns: turn,
        },
        usage,
        args.container,
      );
    }

    if (turn === maxTurns) {
      const displayCommand = redactSensitiveText(action.command);
      emitProgress(args.onProgress, {
        type: "final-turn-command-denied",
        turn,
        maxTurns,
        command: displayCommand.text,
        redacted: displayCommand.redacted,
      });
      return withValidationMetadata(
        {
          verdict: {
            verdict: "uncertain",
            reproducible: false,
            interesting: false,
            reasoning:
              "The validation model requested another command on the final allowed turn instead of returning a verdict.",
          },
          transcript,
          turns: turn,
        },
        usage,
        args.container,
      );
    }

    assertSafeContainerCommand(action.command);
    const displayCommand = redactSensitiveText(action.command);
    emitProgress(args.onProgress, {
      type: "action",
      turn,
      maxTurns,
      action: "run_command",
      command: displayCommand.text,
      timeoutMs: action.timeoutMs,
      reason: action.reason,
      redacted: displayCommand.redacted,
    });
    const execution = redactCommandExecution(
      await args.runner.exec(action.command, action.timeoutMs),
    );
    emitProgress(args.onProgress, {
      type: "command-result",
      turn,
      maxTurns,
      command: execution.command,
      exitCode: execution.exitCode,
      durationMs: execution.durationMs,
      timedOut: execution.timedOut,
      truncated: execution.truncated,
      redacted: execution.redacted === true,
      stdoutBytes: execution.stdout.length,
      stderrBytes: execution.stderr.length,
    });
    transcript.push({ role: "tool", content: execution });
    messages.push({ role: "user", content: commandObservationPrompt(execution) });
  }

  return withValidationMetadata(
    {
      verdict: {
        verdict: "uncertain",
        reproducible: false,
        interesting: false,
        reasoning: `Reached validation max turns (${maxTurns}) without a structured verdict.`,
      },
      transcript,
      turns: maxTurns,
    },
    usage,
    args.container,
  );
}

export function parseExploreAction(
  text: string,
):
  | { action: "run_command"; command: string; timeoutMs: number; reason?: string }
  | { action: "final"; result: ExploreReport } {
  const value = extractJsonValue(text);
  const object = asRecord(value, "explore action");
  const action =
    typeof object.action === "string"
      ? object.action.trim()
      : isNoBugReportLike(object)
        ? "final"
        : "";
  if (action === "run_command") {
    const command = asString(object.command, "command");
    return {
      action: "run_command",
      command,
      timeoutMs: sanitizeTimeoutMs(object.timeoutMs),
      reason: typeof object.reason === "string" ? object.reason : undefined,
    };
  }
  if (action === "final" || action === "finish" || action === "done") {
    return {
      action: "final",
      result: parseExploreReport(finalExplorePayload(object)),
    };
  }
  throw new Error(`Unsupported explore action ${JSON.stringify(action)}.`);
}

function finalExplorePayload(object: Record<string, unknown>): unknown {
  if (typeof object.result === "string" && isNoBugOutcome(object.result)) return object;
  return object.result ?? object.report ?? object;
}

export function parseExploreReport(value: unknown): ExploreReport {
  if (typeof value === "string" && isNoBugOutcome(value)) {
    return {
      outcome: "no-bug",
      summary: "Model reported no confirmed bug.",
      evidence: [value],
    };
  }
  const object = asRecord(value, "final result");
  const outcome = normalizeExploreOutcome(object.outcome ?? object.result ?? object.verdict);
  if (outcome === "no-bug") {
    return {
      outcome,
      summary: parseNoBugSummary(object),
      evidence: parseNoBugEvidence(object),
    };
  }
  if (outcome === "bug") {
    const severity = asSeverity(object.severity, "result.severity");
    const confidence = asConfidence(object.confidence, "result.confidence");
    return {
      outcome,
      title: asString(object.title, "result.title"),
      severity,
      confidence,
      vulnSlug: asString(object.vulnSlug, "result.vulnSlug"),
      lineNumbers: asNumberArray(object.lineNumbers, "result.lineNumbers"),
      description: asString(object.description, "result.description"),
      recommendation: asString(object.recommendation, "result.recommendation"),
      reproductionSteps: asStringArray(object.reproductionSteps, "result.reproductionSteps"),
      evidence: asStringArray(object.evidence, "result.evidence"),
    };
  }
  throw new Error(`Unsupported final result outcome ${JSON.stringify(outcome)}.`);
}

function normalizeExploreOutcome(value: unknown): ExploreReport["outcome"] {
  const raw = asString(value, "result.outcome");
  const normalized = raw.toLowerCase().replace(/[_\s]+/g, "-");
  if (
    normalized === "no-bug" ||
    normalized === "no-bug-found" ||
    normalized === "no-confirmed-bug" ||
    normalized === "none"
  ) {
    return "no-bug";
  }
  if (
    normalized === "bug" ||
    normalized === "bug-found" ||
    normalized === "vulnerability" ||
    normalized === "vulnerability-found"
  ) {
    return "bug";
  }
  throw new Error(`Unsupported final result outcome ${JSON.stringify(raw)}.`);
}

function isNoBugOutcome(value: unknown): boolean {
  if (typeof value !== "string") return false;
  try {
    return normalizeExploreOutcome(value) === "no-bug";
  } catch {
    return false;
  }
}

function isNoBugReportLike(object: Record<string, unknown>): boolean {
  return (
    isNoBugOutcome(object.outcome) ||
    isNoBugOutcome(object.result) ||
    isNoBugOutcome(object.verdict)
  );
}

function parseNoBugSummary(object: Record<string, unknown>): string {
  if (typeof object.summary === "string" && object.summary.trim()) return object.summary.trim();
  if (typeof object.reasoning === "string" && object.reasoning.trim()) {
    return object.reasoning.trim();
  }
  if (typeof object.evidence === "string" && object.evidence.trim()) {
    return object.evidence.trim();
  }
  if (object.evidence && typeof object.evidence === "object" && !Array.isArray(object.evidence)) {
    const evidence = object.evidence as Record<string, unknown>;
    if (typeof evidence.summary === "string" && evidence.summary.trim()) {
      return evidence.summary.trim();
    }
    if (typeof evidence.conclusion === "string" && evidence.conclusion.trim()) {
      return evidence.conclusion.trim();
    }
  }
  return "Model reported no confirmed bug.";
}

function parseNoBugEvidence(object: Record<string, unknown>): string[] | undefined {
  if (Array.isArray(object.evidence)) return asStringArray(object.evidence, "result.evidence");
  if (typeof object.evidence === "string" && object.evidence.trim())
    return [object.evidence.trim()];
  if (object.evidence && typeof object.evidence === "object" && !Array.isArray(object.evidence)) {
    const evidence = object.evidence as Record<string, unknown>;
    const items: string[] = [];
    if (typeof evidence.summary === "string" && evidence.summary.trim()) {
      items.push(evidence.summary.trim());
    }
    if (Array.isArray(evidence.observations)) {
      items.push(...asStringArray(evidence.observations, "result.evidence.observations"));
    }
    if (typeof evidence.conclusion === "string" && evidence.conclusion.trim()) {
      items.push(evidence.conclusion.trim());
    }
    return items.length ? items : undefined;
  }
  return undefined;
}

export function parseValidationVerdict(text: string): ValidationVerdict {
  return parseValidationVerdictValue(extractJsonValue(text));
}

export function parseValidationAction(
  text: string,
):
  | { action: "run_command"; command: string; timeoutMs: number; reason?: string }
  | { action: "final"; verdict: ValidationVerdict } {
  const object = asRecord(extractJsonValue(text), "validation action");
  const action =
    typeof object.action === "string"
      ? object.action
      : isValidationVerdictLike(object)
        ? "final"
        : "";
  if (action === "run_command") {
    const command = asString(object.command, "command");
    return {
      action: "run_command",
      command,
      timeoutMs: sanitizeTimeoutMs(object.timeoutMs),
      reason: typeof object.reason === "string" ? object.reason : undefined,
    };
  }
  if (action === "final" || action === "finish" || action === "done") {
    return {
      action: "final",
      verdict: parseValidationVerdictValue(finalValidationPayload(object)),
    };
  }
  throw new Error(`Unsupported validation action ${JSON.stringify(action)}.`);
}

function finalValidationPayload(object: Record<string, unknown>): unknown {
  if (typeof object.result === "string" && isValidationVerdictString(object.result)) {
    return object;
  }
  return object.result ?? object;
}

function parseValidationVerdictValue(value: unknown): ValidationVerdict {
  if (typeof value === "string") {
    return {
      verdict: normalizeValidationVerdict(value),
      reproducible: false,
      interesting: false,
      reasoning: "Model returned a bare validation verdict.",
    };
  }
  const object = asRecord(value, "validation verdict");
  const verdict = normalizeValidationVerdict(object.verdict ?? object.result);
  const adjustedSeverity =
    object.adjustedSeverity === undefined
      ? undefined
      : asSeverity(object.adjustedSeverity, "adjustedSeverity");
  return {
    verdict,
    reproducible: object.reproducible === true,
    interesting: object.interesting === true,
    reasoning: asString(object.reasoning, "reasoning"),
    adjustedSeverity,
  };
}

function normalizeValidationVerdict(value: unknown): ValidationVerdict["verdict"] {
  const raw = asString(value, "verdict");
  const normalized = raw.toLowerCase().replace(/[_\s]+/g, "-");
  if (normalized === "true-positive" || normalized === "valid" || normalized === "confirmed") {
    return "true-positive";
  }
  if (
    normalized === "false-positive" ||
    normalized === "invalid" ||
    normalized === "not-reproducible"
  ) {
    return "false-positive";
  }
  if (normalized === "uncertain" || normalized === "unknown" || normalized === "inconclusive") {
    return "uncertain";
  }
  throw new Error(`Unsupported validation verdict ${JSON.stringify(raw)}.`);
}

function isValidationVerdictLike(object: Record<string, unknown>): boolean {
  try {
    normalizeValidationVerdict(object.verdict ?? object.result);
    return true;
  } catch {
    return false;
  }
}

function isValidationVerdictString(value: string): boolean {
  try {
    normalizeValidationVerdict(value);
    return true;
  } catch {
    return false;
  }
}

function asSeverity(value: unknown, label: string): Severity {
  const severity = asString(value, label);
  if (!SEVERITIES.has(severity)) throw new Error(`${label} must be a supported severity.`);
  return severity as Severity;
}

function asConfidence(value: unknown, label: string): Confidence {
  const confidence = asString(value, label);
  if (!CONFIDENCES.has(confidence)) throw new Error(`${label} must be high, medium, or low.`);
  return confidence as Confidence;
}

function trimMessages(messages: ModelMessage[]): ModelMessage[] {
  const maxChars = 48_000;
  let used = 0;
  const kept: ModelMessage[] = [];
  for (const message of messages.slice().reverse()) {
    used += message.content.length;
    if (used > maxChars && kept.length > 0) break;
    kept.push(message);
  }
  return kept.reverse();
}

function recentToolEvidence(transcript: ExploreAttempt["transcript"]): string[] {
  return transcript
    .filter((entry) => entry.role === "tool")
    .slice(-3)
    .map((entry) =>
      typeof entry.content === "string" ? entry.content : summarizeExecution(entry.content),
    );
}

function withUsage(attempt: ExploreAttempt, usage: ModelUsage | undefined): ExploreAttempt {
  if (usage) attempt.usage = usage;
  return attempt;
}

function withValidationMetadata(
  result: ValidationResult,
  usage: ModelUsage | undefined,
  container: ContainerMetadata | undefined,
): ValidationResult {
  if (usage) result.usage = usage;
  if (container) result.container = container;
  return result;
}

function emitProgress(
  onProgress: ((event: ExploreProgressEvent) => void) | undefined,
  event: ExploreProgressEventInput,
): void {
  onProgress?.({ ...event, at: new Date().toISOString() } as ExploreProgressEvent);
}
