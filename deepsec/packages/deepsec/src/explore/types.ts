import type { Confidence, Severity } from "@deepsec/core";

export const EXPLORE_PROFILE = "java11-gradle" as const;
export const EXPLORE_IMAGE = "deepsec-explore-java11-gradle:local";
export const EXPLORE_RUNTIME = "runsc";
export const OPENROUTER_DEFAULT_BASE_URL = "https://openrouter.ai/api/v1";
export const OPENROUTER_DEFAULT_MODEL = "anthropic/claude-opus-4.8";

export type ExploreProfile = typeof EXPLORE_PROFILE;
export type ExploreRuntime = typeof EXPLORE_RUNTIME;

export interface ExploreOptions {
  projectId?: string;
  root?: string;
  profile?: string;
  runtime?: string;
  model?: string;
  rankModel?: string;
  limit?: number;
  concurrency?: number;
  maxTurns?: number;
  stubModel?: boolean;
  liveModelCheck?: boolean;
  maxTokens?: number;
  maxCostUsd?: number;
}

export interface ExploreSetupOptions {
  profile?: string;
}

export interface ExploreAttemptFailure {
  projectId: string;
  runId: string;
  focusFile: string;
  model: string;
  failedAt: string;
  error: string;
  container?: ContainerMetadata;
}

export interface WorkspaceFileChange {
  path: string;
  status: "added" | "modified" | "deleted";
  beforeSha256?: string;
  afterSha256?: string;
  afterBytes?: number;
  afterPreview?: string;
  redacted?: boolean;
  omittedReason?: string;
}

export interface WorkspaceChanges {
  generatedAt: string;
  containerTarget: "/workspace/target";
  totalChanges: number;
  capturedChanges: number;
  omittedChanges: number;
  changes: WorkspaceFileChange[];
}

export interface SourceFileSummary {
  filePath: string;
  bytes: number;
  heuristicScore: 1 | 2 | 3 | 4 | 5;
  preview: string;
}

export interface RankedFile {
  filePath: string;
  score: 1 | 2 | 3 | 4 | 5;
  reason: string;
}

export interface StoredRankings {
  projectId: string;
  runId: string;
  generatedAt: string;
  model: string;
  rankings: RankedFile[];
  usage?: ModelUsage;
}

export interface ModelUsage {
  inputTokens: number;
  outputTokens: number;
  costUsd?: number;
}

export interface ModelMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export type ModelResponseFormat =
  | { type: "json_object" }
  | { type: "json_schema"; name: string; schema: Record<string, unknown>; strict?: boolean };

export interface ModelResponse {
  text: string;
  raw: unknown;
  usage?: ModelUsage;
}

export interface ModelClient {
  complete(params: {
    model: string;
    messages: ModelMessage[];
    temperature?: number;
    responseFormat?: ModelResponseFormat;
  }): Promise<ModelResponse>;
}

export interface CommandExecution {
  command: string;
  exitCode: number;
  durationMs: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
  redacted?: boolean;
}

export interface ContainerRunner {
  exec(command: string, timeoutMs?: number, outputLimit?: number): Promise<CommandExecution>;
}

export interface ContainerMetadata {
  containerId: string;
  runtime: string;
  networkMode: string;
  image: string;
  readOnlyRootfs?: boolean;
  noNewPrivileges?: boolean;
  capDropAll?: boolean;
  privileged?: boolean;
  pidsLimit?: number;
  memoryBytes?: number;
  nanoCpus?: number;
  mountDestinations?: string[];
  copyExcludedCount?: number;
  copyExcludedPaths?: string[];
}

export interface NoBugReport {
  outcome: "no-bug";
  summary: string;
  evidence?: string[];
}

export interface BugReport {
  outcome: "bug";
  title: string;
  severity: Severity;
  confidence: Confidence;
  vulnSlug: string;
  lineNumbers: number[];
  description: string;
  recommendation: string;
  reproductionSteps: string[];
  evidence: string[];
}

export type ExploreReport = NoBugReport | BugReport;

export interface ValidationVerdict {
  verdict: "true-positive" | "false-positive" | "uncertain";
  reasoning: string;
  reproducible: boolean;
  interesting: boolean;
  adjustedSeverity?: Severity;
}

export type AgentTranscript = Array<{
  role: "assistant" | "tool";
  content: string | CommandExecution;
}>;

export type ExploreProgressEvent =
  | {
      type: "model-request";
      at: string;
      turn: number;
      maxTurns: number;
      finalTurn: boolean;
    }
  | {
      type: "model-response";
      at: string;
      turn: number;
      maxTurns: number;
      responseChars: number;
      usage?: ModelUsage;
    }
  | {
      type: "repair";
      at: string;
      turn: number;
      maxTurns: number;
      error: string;
    }
  | {
      type: "action";
      at: string;
      turn: number;
      maxTurns: number;
      action: "run_command";
      command: string;
      timeoutMs: number;
      reason?: string;
      redacted: boolean;
    }
  | {
      type: "command-result";
      at: string;
      turn: number;
      maxTurns: number;
      command: string;
      exitCode: number;
      durationMs: number;
      timedOut: boolean;
      truncated: boolean;
      redacted: boolean;
      stdoutBytes: number;
      stderrBytes: number;
    }
  | {
      type: "final";
      at: string;
      turn: number;
      maxTurns: number;
      outcome: ExploreReport["outcome"];
    }
  | {
      type: "final-turn-command-denied";
      at: string;
      turn: number;
      maxTurns: number;
      command: string;
      redacted: boolean;
    };

export interface ExploreAttempt {
  projectId: string;
  runId: string;
  focusFile: string;
  model: string;
  startedAt: string;
  completedAt: string;
  turns: number;
  container: ContainerMetadata;
  transcript: AgentTranscript;
  report: ExploreReport;
  validation?: ValidationVerdict;
  validationContainer?: ContainerMetadata;
  validationTranscript?: AgentTranscript;
  validationTurns?: number;
  validationUsage?: ModelUsage;
  usage?: ModelUsage;
  workspaceChanges?: WorkspaceChanges;
}

export interface ValidationResult {
  verdict: ValidationVerdict;
  transcript?: AgentTranscript;
  turns?: number;
  container?: ContainerMetadata;
  usage?: ModelUsage;
}
