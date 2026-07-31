export const ATTEMPT_LIMIT = 18;
export const WORKER_LIMIT = 2;

export type RunStatus = "idle" | "connecting" | "running" | "complete" | "failed" | "stopped";
export type PhaseStatus = "pending" | "active" | "complete" | "skipped" | "failed";
export type AttemptStatus =
  | "awaiting"
  | "queued"
  | "exploring"
  | "validating"
  | "complete"
  | "failed";
export type FindingStatus = "candidate" | "accepted" | "rejected" | "uncertain";
export type ActivityTone = "neutral" | "active" | "success" | "warning" | "danger";

export interface Usage {
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
}

export interface PhaseState {
  id:
    | "setup"
    | "preflight"
    | "inventory"
    | "ranking"
    | "exploration"
    | "verification"
    | "ci"
    | "manifest"
    | "bundle";
  label: string;
  status: PhaseStatus;
}

export interface AttemptState {
  index: number;
  generation: number;
  focusFile?: string;
  status: AttemptStatus;
  phase?: "explore" | "validate";
  turn: number;
  maxTurns: number;
  lastAction: string;
  outcome?: string;
  workerSlot?: 1 | 2;
  startedAt?: number;
  updatedAt?: number;
  usage: Usage;
}

export interface FindingState {
  id: string;
  attemptIndex: number;
  generation: number;
  title: string;
  severity?: string;
  confidence?: string;
  vulnSlug?: string;
  lineNumbers?: number[];
  status: FindingStatus;
}

export interface Activity {
  id: number;
  at: string;
  label: string;
  detail: string;
  attemptIndex?: number;
  tone: ActivityTone;
}

export interface CanvasState {
  status: RunStatus;
  projectId?: string;
  runId?: string;
  startedAt?: number;
  finishedAt?: number;
  phases: PhaseState[];
  attempts: AttemptState[];
  findings: FindingState[];
  activities: Activity[];
  usage: Usage;
  eventCount: number;
  malformedEvents: number;
  artifacts: {
    manifest?: string;
    bundle?: string;
    dataRoot?: string;
  };
  supervisor?: {
    processAlive?: boolean;
    containerCount?: number;
    clientCount?: number;
    eventAgeMs?: number;
    quiet?: boolean;
    stalled?: boolean;
  };
}

export interface StreamEnvelope {
  seq?: number;
  source?: "live" | "simulation" | "hydration" | "bridge" | "replay";
  receivedAt?: string;
  event: Record<string, unknown>;
}

const PHASES: PhaseState[] = [
  { id: "setup", label: "Setup", status: "pending" },
  { id: "preflight", label: "Preflight", status: "pending" },
  { id: "inventory", label: "Inventory", status: "pending" },
  { id: "ranking", label: "Ranking", status: "pending" },
  { id: "exploration", label: "Explore", status: "pending" },
  { id: "verification", label: "Verify", status: "pending" },
  { id: "ci", label: "CI", status: "pending" },
  { id: "manifest", label: "Manifest", status: "pending" },
  { id: "bundle", label: "Bundle", status: "pending" },
];

function blankAttempt(index: number): AttemptState {
  return {
    index,
    generation: 0,
    status: "awaiting",
    turn: 0,
    maxTurns: 0,
    lastAction: "Awaiting ranked file",
    usage: { inputTokens: 0, outputTokens: 0, costUsd: 0 },
  };
}

export function createInitialState(status: RunStatus = "connecting"): CanvasState {
  return {
    status,
    phases: PHASES.map((phase) => ({ ...phase })),
    attempts: Array.from({ length: ATTEMPT_LIMIT }, (_, index) => blankAttempt(index)),
    findings: [],
    activities: [],
    usage: { inputTokens: 0, outputTokens: 0, costUsd: 0 },
    eventCount: 0,
    malformedEvents: 0,
    artifacts: {},
    supervisor: undefined,
  };
}

function stringValue(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

function numberValue(record: Record<string, unknown>, key: string): number | undefined {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function recordValue(record: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  const value = record[key];
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function truncate(value: string, length = 96): string {
  const safe = value.replace(/\s+/g, " ").trim();
  return safe.length <= length ? safe : `${safe.slice(0, length - 1)}…`;
}

function basename(path?: string): string {
  if (!path) return "Awaiting ranked file";
  const pieces = path.split(/[\\/]/);
  return pieces.at(-1) || path;
}

function cloneState(state: CanvasState): CanvasState {
  return {
    ...state,
    phases: state.phases.map((phase) => ({ ...phase })),
    attempts: state.attempts.map((attempt) => ({
      ...attempt,
      usage: { ...attempt.usage },
    })),
    findings: state.findings.map((finding) => ({ ...finding })),
    activities: [...state.activities],
    usage: { ...state.usage },
    artifacts: { ...state.artifacts },
    supervisor: state.supervisor ? { ...state.supervisor } : undefined,
  };
}

function setPhase(state: CanvasState, id: PhaseState["id"], status: PhaseStatus): void {
  const phase = state.phases.find((candidate) => candidate.id === id);
  if (phase) phase.status = status;
}

function addActivity(
  state: CanvasState,
  at: string | undefined,
  label: string,
  detail: string,
  tone: ActivityTone,
  attemptIndex?: number,
): void {
  state.activities = [
    {
      id: state.eventCount,
      at: at ? new Date(at).toLocaleTimeString([], { hour12: false }) : "--:--:--",
      label,
      detail: truncate(detail, 120),
      tone,
      attemptIndex,
    },
    ...state.activities,
  ].slice(0, 12);
}

function claimWorker(state: CanvasState, attempt: AttemptState): void {
  if (attempt.workerSlot) return;
  const occupied = new Set(
    state.attempts
      .filter(
        (candidate) =>
          candidate.index !== attempt.index &&
          (candidate.status === "exploring" || candidate.status === "validating"),
      )
      .map((candidate) => candidate.workerSlot)
      .filter(Boolean),
  );
  attempt.workerSlot = occupied.has(1) ? 2 : 1;
}

function releaseWorker(attempt: AttemptState): void {
  attempt.workerSlot = undefined;
}

function eventAttempt(state: CanvasState, event: Record<string, unknown>): AttemptState | undefined {
  const index = numberValue(event, "attemptIndex");
  if (index === undefined || !Number.isInteger(index) || index < 0 || index >= ATTEMPT_LIMIT) {
    state.malformedEvents += 1;
    return undefined;
  }
  return state.attempts[index];
}

function findingId(attempt: AttemptState): string {
  return `attempt-${attempt.index}-generation-${attempt.generation}`;
}

function upsertCandidateFinding(state: CanvasState, attempt: AttemptState): FindingState {
  const id = findingId(attempt);
  const existing = state.findings.find((finding) => finding.id === id);
  if (existing) return existing;
  const finding: FindingState = {
    id,
    attemptIndex: attempt.index,
    generation: attempt.generation,
    title: `Candidate in ${basename(attempt.focusFile)}`,
    status: "candidate",
  };
  state.findings.push(finding);
  return finding;
}

function applyHydration(state: CanvasState, event: Record<string, unknown>): boolean {
  const payload =
    recordValue(event, "attempt") ??
    recordValue(recordValue(event, "data") ?? {}, "attempt") ??
    recordValue(event, "data") ??
    recordValue(event, "artifact") ??
    event;
  if (!payload) return false;

  const index = numberValue(event, "attemptIndex") ?? numberValue(payload, "attemptIndex");
  const focusFile = stringValue(payload, "focusFile");
  const attempt =
    index !== undefined && Number.isInteger(index) && index >= 0 && index < ATTEMPT_LIMIT
      ? state.attempts[index]
      : state.attempts.find((candidate) => candidate.focusFile === focusFile);
  if (!attempt) return false;

  attempt.focusFile = focusFile ?? attempt.focusFile;
  const usage = recordValue(payload, "usage") ?? recordValue(event, "usage");
  if (usage) {
    const nextUsage = {
      inputTokens: numberValue(usage, "inputTokens") ?? attempt.usage.inputTokens,
      outputTokens: numberValue(usage, "outputTokens") ?? attempt.usage.outputTokens,
      costUsd: numberValue(usage, "costUsd") ?? attempt.usage.costUsd,
    };
    state.usage.inputTokens += nextUsage.inputTokens - attempt.usage.inputTokens;
    state.usage.outputTokens += nextUsage.outputTokens - attempt.usage.outputTokens;
    state.usage.costUsd += nextUsage.costUsd - attempt.usage.costUsd;
    attempt.usage = nextUsage;
  }

  const report =
    recordValue(payload, "report") ??
    recordValue(payload, "finding") ??
    recordValue(event, "finding");
  if (!report || stringValue(report, "outcome") !== "bug") return true;

  const finding = upsertCandidateFinding(state, attempt);
  finding.title = stringValue(report, "title") ?? finding.title;
  finding.severity = stringValue(report, "severity");
  finding.confidence = stringValue(report, "confidence");
  finding.vulnSlug = stringValue(report, "vulnSlug");
  const lineNumbers = report.lineNumbers;
  finding.lineNumbers = Array.isArray(lineNumbers)
    ? lineNumbers.filter((line): line is number => typeof line === "number")
    : undefined;

  const validation = recordValue(payload, "validation") ?? recordValue(event, "validation");
  const verdict = validation ? stringValue(validation, "verdict") : undefined;
  finding.status =
    verdict === "true-positive"
      ? "accepted"
      : verdict === "false-positive"
        ? "rejected"
        : verdict === "uncertain"
          ? "uncertain"
          : "candidate";
  const adjusted = validation ? stringValue(validation, "adjustedSeverity") : undefined;
  if (adjusted) finding.severity = adjusted;
  return true;
}

function progressDetail(nested: Record<string, unknown>): string {
  const type = stringValue(nested, "type") ?? "progress";
  const turn = numberValue(nested, "turn") ?? 0;
  const maxTurns = numberValue(nested, "maxTurns") ?? 0;
  switch (type) {
    case "model-request":
      return `Model request · turn ${turn}/${maxTurns}`;
    case "model-response":
      return `Model response · ${numberValue(nested, "responseChars") ?? 0} chars`;
    case "action":
      return truncate(stringValue(nested, "reason") ?? "Collecting bounded local evidence");
    case "command-result":
      return `Command exit ${numberValue(nested, "exitCode") ?? "?"} · ${Math.round(
        (numberValue(nested, "durationMs") ?? 0) / 1000,
      )}s`;
    case "repair":
      return "Repairing structured model response";
    case "final":
      return `Verdict · ${stringValue(nested, "outcome") ?? "complete"}`;
    case "final-turn-command-denied":
      return "Turn budget reached · final report requested";
    default:
      return type;
  }
}

function applyProgress(state: CanvasState, event: Record<string, unknown>, at?: string): void {
  const attempt = eventAttempt(state, event);
  const nested = recordValue(event, "event");
  if (!attempt || !nested) return;

  const phase = stringValue(event, "phase") === "validate" ? "validate" : "explore";
  attempt.focusFile = stringValue(event, "focusFile") ?? attempt.focusFile;
  attempt.phase = phase;
  attempt.status = phase === "validate" ? "validating" : "exploring";
  attempt.turn = numberValue(nested, "turn") ?? attempt.turn;
  attempt.maxTurns = numberValue(nested, "maxTurns") ?? attempt.maxTurns;
  attempt.lastAction = progressDetail(nested);
  attempt.updatedAt = Date.parse(stringValue(nested, "at") ?? at ?? "") || Date.now();
  attempt.startedAt ??= attempt.updatedAt;
  claimWorker(state, attempt);

  const usage = recordValue(nested, "usage");
  if (usage) {
    const inputTokens = numberValue(usage, "inputTokens") ?? 0;
    const outputTokens = numberValue(usage, "outputTokens") ?? 0;
    const costUsd = numberValue(usage, "costUsd") ?? 0;
    attempt.usage.inputTokens += inputTokens;
    attempt.usage.outputTokens += outputTokens;
    attempt.usage.costUsd += costUsd;
    state.usage.inputTokens += inputTokens;
    state.usage.outputTokens += outputTokens;
    state.usage.costUsd += costUsd;
  }

  const nestedType = stringValue(nested, "type");
  if (
    nestedType === "action" ||
    nestedType === "command-result" ||
    nestedType === "repair" ||
    nestedType === "final"
  ) {
    addActivity(
      state,
      stringValue(nested, "at") ?? at,
      phase === "validate" ? "Validation signal" : "Attempt signal",
      attempt.lastAction,
      nestedType === "repair" ? "warning" : "active",
      attempt.index,
    );
  }
}

const HARNESS_PHASE_MAP: Record<string, PhaseState["id"] | undefined> = {
  setup: "setup",
  doctor: "preflight",
  exploration: "exploration",
  verification: "verification",
  ci: "ci",
  manifest: "manifest",
  bundle: "bundle",
};

function applyHarnessPhase(state: CanvasState, event: Record<string, unknown>, at?: string): void {
  const phaseName = stringValue(event, "phase");
  const phase = phaseName ? HARNESS_PHASE_MAP[phaseName] : undefined;
  if (!phase) return;
  const rawStatus = stringValue(event, "status");
  const status: PhaseStatus =
    rawStatus === "start"
      ? "active"
      : rawStatus === "complete"
        ? "complete"
        : rawStatus === "skipped"
          ? "skipped"
          : rawStatus === "failed"
            ? "failed"
            : "pending";
  setPhase(state, phase, status);
  if (status === "active") state.status = "running";
  addActivity(
    state,
    at,
    `${state.phases.find((candidate) => candidate.id === phase)?.label ?? phase} ${status}`,
    stringValue(event, "detail") ?? "Harness phase updated",
    status === "failed" ? "danger" : status === "complete" ? "success" : "active",
  );
}

export function reduceCanvasEvent(
  previous: CanvasState,
  envelopeOrEvent: StreamEnvelope | Record<string, unknown>,
): CanvasState {
  const envelope =
    "event" in envelopeOrEvent &&
    envelopeOrEvent.event !== null &&
    typeof envelopeOrEvent.event === "object" &&
    !Array.isArray(envelopeOrEvent.event)
      ? (envelopeOrEvent as StreamEnvelope)
      : ({ event: envelopeOrEvent } as StreamEnvelope);
  const event = envelope.event;
  const kind = stringValue(event, "kind") ?? stringValue(event, "type");
  const at = stringValue(event, "at") ?? envelope.receivedAt;
  const state = cloneState(previous);
  state.eventCount += 1;

  if (!kind) {
    state.malformedEvents += 1;
    return state;
  }

  if (
    kind === "attempt-hydrated" ||
    kind === "attempt-artifact" ||
    kind === "artifact-hydrated" ||
    envelope.source === "hydration"
  ) {
    if (!applyHydration(state, event)) state.malformedEvents += 1;
    return state;
  }

  switch (kind) {
    case "bridge-ready":
    case "connected":
      state.status = state.status === "connecting" ? "idle" : state.status;
      break;
    case "harness-phase":
      applyHarnessPhase(state, event, at);
      break;
    case "harness-complete": {
      const successful = stringValue(event, "status") === "complete";
      const artifacts = recordValue(event, "artifacts");
      state.status = successful ? "complete" : "failed";
      state.finishedAt = Date.parse(at ?? "") || Date.now();
      state.projectId = stringValue(event, "projectId") ?? state.projectId;
      state.runId = stringValue(event, "runId") ?? state.runId;
      state.artifacts.dataRoot = stringValue(event, "dataRoot") ?? state.artifacts.dataRoot;
      state.artifacts.manifest =
        stringValue(event, "manifest") ??
        (artifacts ? stringValue(artifacts, "manifest") : undefined) ??
        state.artifacts.manifest;
      state.artifacts.bundle =
        stringValue(event, "bundle") ??
        (artifacts ? stringValue(artifacts, "bundle") : undefined) ??
        state.artifacts.bundle;
      addActivity(
        state,
        at,
        successful ? "Evidence ready" : "Harness stopped",
        stringValue(event, "detail") ??
          (successful ? "Portable evidence bundle complete" : "Harness failed"),
        successful ? "success" : "danger",
      );
      break;
    }
    case "run-start":
      state.status = "running";
      state.startedAt ??= Date.parse(at ?? "") || Date.now();
      state.projectId = stringValue(event, "projectId") ?? state.projectId;
      state.runId = stringValue(event, "runId") ?? state.runId;
      addActivity(
        state,
        at,
        "Explore run started",
        stringValue(event, "detail") ?? "Bounded exploration started",
        "active",
      );
      break;
    case "ranking": {
      const detail = stringValue(event, "detail") ?? "Preparing ranked files";
      if (detail.toLowerCase().includes("inventory")) {
        setPhase(state, "inventory", "active");
      } else {
        setPhase(state, "inventory", "complete");
        setPhase(state, "ranking", "active");
      }
      addActivity(state, at, "Ranking candidates", detail, "active");
      break;
    }
    case "ranking-done":
      setPhase(state, "inventory", "complete");
      setPhase(state, "ranking", "complete");
      setPhase(state, "exploration", "active");
      addActivity(
        state,
        at,
        "Ranking complete",
        stringValue(event, "detail") ?? "Focused attempts selected",
        "success",
      );
      break;
    case "attempt-queued": {
      const attempt = eventAttempt(state, event);
      if (!attempt) break;
      if (attempt.status === "complete" || attempt.status === "failed") {
        const reset = blankAttempt(attempt.index);
        Object.assign(attempt, reset, { generation: attempt.generation + 1 });
      }
      attempt.focusFile = stringValue(event, "focusFile") ?? attempt.focusFile;
      attempt.status = "queued";
      attempt.lastAction = "Waiting for a worker slot";
      attempt.updatedAt = Date.parse(at ?? "") || Date.now();
      releaseWorker(attempt);
      addActivity(state, at, `Attempt ${attempt.index + 1} queued`, basename(attempt.focusFile), "neutral");
      break;
    }
    case "attempt-start": {
      const attempt = eventAttempt(state, event);
      if (!attempt) break;
      attempt.focusFile = stringValue(event, "focusFile") ?? attempt.focusFile;
      attempt.status = "exploring";
      attempt.lastAction = "Worker sandbox started";
      attempt.startedAt = Date.parse(at ?? "") || Date.now();
      attempt.updatedAt = attempt.startedAt;
      claimWorker(state, attempt);
      addActivity(
        state,
        at,
        `Worker ${attempt.workerSlot ?? "?"} started`,
        basename(attempt.focusFile),
        "active",
        attempt.index,
      );
      break;
    }
    case "progress":
      applyProgress(state, event, at);
      break;
    case "attempt-finish": {
      const attempt = eventAttempt(state, event);
      if (!attempt) break;
      attempt.focusFile = stringValue(event, "focusFile") ?? attempt.focusFile;
      attempt.status = "complete";
      attempt.outcome = stringValue(event, "outcome") ?? attempt.outcome;
      attempt.lastAction = stringValue(event, "detail") ?? "Attempt complete";
      attempt.updatedAt = Date.parse(at ?? "") || Date.now();
      releaseWorker(attempt);
      if (attempt.outcome === "bug") upsertCandidateFinding(state, attempt);
      addActivity(
        state,
        at,
        `Attempt ${attempt.index + 1} complete`,
        `${basename(attempt.focusFile)} · ${attempt.outcome ?? "complete"}`,
        "success",
        attempt.index,
      );
      break;
    }
    case "attempt-fail": {
      const attempt = eventAttempt(state, event);
      if (!attempt) break;
      attempt.focusFile = stringValue(event, "focusFile") ?? attempt.focusFile;
      attempt.status = "failed";
      attempt.lastAction = stringValue(event, "detail") ?? "Attempt failed";
      attempt.updatedAt = Date.parse(at ?? "") || Date.now();
      releaseWorker(attempt);
      addActivity(
        state,
        at,
        `Attempt ${attempt.index + 1} failed`,
        attempt.lastAction,
        "danger",
        attempt.index,
      );
      break;
    }
    case "run-complete":
      setPhase(state, "exploration", "complete");
      addActivity(
        state,
        at,
        "Exploration complete",
        stringValue(event, "detail") ?? "All focused attempts returned",
        "success",
      );
      break;
    case "bridge-stopped":
      state.status = "stopped";
      state.finishedAt = Date.parse(at ?? "") || Date.now();
      break;
    case "supervisor-pulse": {
      state.supervisor = {
        processAlive:
          typeof event.processAlive === "boolean" ? event.processAlive : undefined,
        containerCount: numberValue(event, "containerCount"),
        clientCount: numberValue(event, "clientCount"),
        eventAgeMs: numberValue(event, "eventAgeMs"),
        quiet: typeof event.quiet === "boolean" ? event.quiet : undefined,
        stalled: typeof event.stalled === "boolean" ? event.stalled : undefined,
      };
      if (state.supervisor.stalled) {
        addActivity(
          state,
          at,
          "Supervisor warning",
          "The run is alive but structured events appear stalled",
          "warning",
        );
      }
      break;
    }
    default:
      // Forward compatibility: unknown protocol events remain counted but do not
      // create noisy shapes or expose raw payloads on the demo canvas.
      break;
  }

  return state;
}

export function applyConnectionStatus(
  state: CanvasState,
  status: "connecting" | "open" | "closed" | "error",
): CanvasState {
  if (status === "open" && state.status === "connecting") return { ...state, status: "idle" };
  if ((status === "closed" || status === "error") && state.status === "connecting") {
    return { ...state, status: "failed" };
  }
  return state;
}

export function completedAttempts(state: CanvasState): number {
  return state.attempts.filter(
    (attempt) => attempt.status === "complete" || attempt.status === "failed",
  ).length;
}

export function activeAttempts(state: CanvasState): AttemptState[] {
  return state.attempts
    .filter((attempt) => attempt.status === "exploring" || attempt.status === "validating")
    .sort((left, right) => (left.workerSlot ?? 9) - (right.workerSlot ?? 9));
}
