import type { Severity } from "./types.js";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG", "LOW"] as const;

export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  HIGH_BUG: 3,
  BUG: 4,
  LOW: 5,
};

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && value in SEVERITY_ORDER;
}

export function parseSeverity(value: string | undefined, label = "severity"): Severity {
  const normalized = value?.trim().toUpperCase().replace(/-/g, "_");
  if (isSeverity(normalized)) return normalized;
  throw new Error(
    `${label}: not a valid severity: ${value ?? "(missing)"}. Expected ${SEVERITIES.join(", ")}.`,
  );
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[a] - SEVERITY_ORDER[b];
}

export function severityAtOrAbove(severity: Severity, minSeverity: Severity): boolean {
  return SEVERITY_ORDER[severity] <= SEVERITY_ORDER[minSeverity];
}

export function bestSeverity(severities: readonly Severity[]): Severity | undefined {
  return severities.length > 0 ? [...severities].sort(compareSeverity)[0] : undefined;
}
