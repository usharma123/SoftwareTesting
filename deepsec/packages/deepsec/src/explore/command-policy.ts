import type { CommandExecution } from "./types.js";

export const DEFAULT_COMMAND_TIMEOUT_MS = 30_000;
export const MAX_COMMAND_TIMEOUT_MS = 120_000;
export const DEFAULT_OUTPUT_LIMIT = 16_000;

const DENIED_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /\.env\b|\/proc\/1\/environ|\/root\/\.ssh|\/workspace\/home\/\.ssh/i,
    reason: "credential access",
  },
  {
    pattern:
      /\b(OPENROUTER_API_KEY|AI_GATEWAY_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN)\b/i,
    reason: "host credential access",
  },
  { pattern: /\b(curl|wget|nc|ncat|netcat|ssh|scp|sftp|rsync)\b/i, reason: "network tools" },
  { pattern: /\b(git\s+clone|docker|podman|kubectl|sudo|su)\b/i, reason: "host/control tools" },
  { pattern: /\/var\/run\/docker\.sock|\/run\/docker\.sock/i, reason: "Docker socket access" },
  {
    pattern: /\/Users\/|\/Volumes\/|\/private\/|\/System\/|\/Library\//i,
    reason: "host path access",
  },
  { pattern: /(^|[^A-Za-z0-9_])\.\.($|[^A-Za-z0-9_])/i, reason: "parent-directory traversal" },
  {
    pattern: /\b(chmod\s+\+s|mount|umount|iptables|sysctl|modprobe)\b/i,
    reason: "privileged operation",
  },
];

const SECRET_REDACTIONS: Array<{
  label: string;
  pattern: RegExp;
  replace?: (match: string, ...groups: string[]) => string;
}> = [
  {
    label: "private-key",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
  { label: "openrouter-api-key", pattern: /sk-or-v1-[A-Za-z0-9_-]{16,}/g },
  { label: "anthropic-api-key", pattern: /sk-ant-[A-Za-z0-9_-]{16,}/g },
  { label: "openai-api-key", pattern: /sk-proj-[A-Za-z0-9_-]{16,}/g },
  { label: "openai-api-key", pattern: /\bsk-[A-Za-z0-9_-]{24,}\b/g },
  {
    label: "github-token",
    pattern: /\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})\b/g,
  },
  { label: "aws-access-key", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { label: "bearer-token", pattern: /\bBearer\s+[A-Za-z0-9._~+/-]{24,}={0,2}/gi },
  {
    label: "secret-assignment",
    pattern:
      /\b(OPENROUTER_API_KEY|AI_GATEWAY_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY)[A-Z0-9_]*)\s*=\s*([^\s'"]{8,})/gi,
    replace: (_match, name) => `${name}=[REDACTED:secret-assignment]`,
  },
];

export function assertSafeContainerCommand(command: string): void {
  if (typeof command !== "string" || command.trim().length === 0) {
    throw new Error("Container command must be a non-empty string.");
  }
  if (command.length > 4000) {
    throw new Error("Container command is too long.");
  }
  if (command.includes("\0")) {
    throw new Error("Container command contains a null byte.");
  }
  for (const deny of DENIED_PATTERNS) {
    if (deny.pattern.test(command)) {
      throw new Error(`Denied container command: ${deny.reason}.`);
    }
  }
}

export function sanitizeTimeoutMs(value: unknown): number {
  const n =
    typeof value === "number" && Number.isFinite(value) ? value : DEFAULT_COMMAND_TIMEOUT_MS;
  return Math.max(1_000, Math.min(MAX_COMMAND_TIMEOUT_MS, Math.trunc(n)));
}

export function sanitizeExploreEnv(): Record<string, string> {
  return {
    HOME: "/workspace/home",
    GRADLE_USER_HOME: "/workspace/gradle-cache",
    JAVA_HOME: "/opt/java/jdk-17",
    JDK11_HOME: "/opt/java/jdk-11",
    GRADLE_OPTS:
      "-Dorg.gradle.java.installations.paths=/opt/java/jdk-11,/opt/java/jdk-17 -Dorg.gradle.java.installations.auto-download=false",
    PATH: "/opt/java/jdk-17/bin:/opt/java/jdk-11/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    CI: "1",
  };
}

export function truncateOutput(stdout: string, stderr: string, limit = DEFAULT_OUTPUT_LIMIT) {
  const combined = `STDOUT:\n${stdout}\n\nSTDERR:\n${stderr}`;
  if (combined.length <= limit) {
    return { stdout, stderr, truncated: false };
  }
  const keep = Math.floor(limit / 2);
  return {
    stdout: stdout.slice(0, keep),
    stderr: stderr.slice(0, keep),
    truncated: true,
  };
}

export function redactSensitiveText(input: string): { text: string; redacted: boolean } {
  let text = input;
  let redacted = false;
  for (const rule of SECRET_REDACTIONS) {
    text = text.replace(rule.pattern, (match, ...groups: string[]) => {
      redacted = true;
      return rule.replace ? rule.replace(match, ...groups) : `[REDACTED:${rule.label}]`;
    });
  }
  return { text, redacted };
}

export function redactCommandExecution(execution: CommandExecution): CommandExecution {
  const command = redactSensitiveText(execution.command);
  const stdout = redactSensitiveText(execution.stdout);
  const stderr = redactSensitiveText(execution.stderr);
  if (!command.redacted && !stdout.redacted && !stderr.redacted && !execution.redacted) {
    return execution;
  }
  return {
    ...execution,
    command: command.text,
    stdout: stdout.text,
    stderr: stderr.text,
    redacted: true,
  };
}

export function summarizeExecution(execution: CommandExecution): string {
  return [
    `$ ${execution.command}`,
    `exit=${execution.exitCode} durationMs=${execution.durationMs} timedOut=${execution.timedOut}`,
    execution.stdout ? `stdout:\n${execution.stdout}` : "",
    execution.stderr ? `stderr:\n${execution.stderr}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}
