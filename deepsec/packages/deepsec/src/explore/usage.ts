import type { ModelUsage } from "./types.js";

export function addModelUsage(
  total: ModelUsage | undefined,
  next: ModelUsage | undefined,
): ModelUsage | undefined {
  if (!next) return total;
  const usage: ModelUsage = {
    inputTokens: (total?.inputTokens ?? 0) + next.inputTokens,
    outputTokens: (total?.outputTokens ?? 0) + next.outputTokens,
  };
  if (total?.costUsd !== undefined || next.costUsd !== undefined) {
    usage.costUsd = (total?.costUsd ?? 0) + (next.costUsd ?? 0);
  }
  return usage;
}

export function sumModelUsages(values: Iterable<ModelUsage | undefined>): ModelUsage | undefined {
  let total: ModelUsage | undefined;
  for (const value of values) {
    total = addModelUsage(total, value);
  }
  return total;
}

export function formatModelUsage(usage: ModelUsage | undefined): string | null {
  if (!usage) return null;
  const tokens = usage.inputTokens + usage.outputTokens;
  const parts = [`tokens=${tokens}`, `in=${usage.inputTokens}`, `out=${usage.outputTokens}`];
  if (usage.costUsd !== undefined) parts.push(`cost=$${formatCostUsd(usage.costUsd)}`);
  return parts.join(" ");
}

function formatCostUsd(value: number): string {
  if (!Number.isFinite(value)) return "0.000000";
  return value.toFixed(6);
}
