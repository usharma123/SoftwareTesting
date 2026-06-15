export function extractJsonValue(text: string): unknown {
  const trimmed = stripCodeFence(text.trim());
  try {
    return JSON.parse(trimmed);
  } catch {}

  const firstObject = trimmed.indexOf("{");
  const firstArray = trimmed.indexOf("[");
  const start =
    firstObject === -1
      ? firstArray
      : firstArray === -1
        ? firstObject
        : Math.min(firstObject, firstArray);
  if (start === -1) {
    throw new Error("Model response did not contain JSON.");
  }

  const opener = trimmed[start];
  const closer = opener === "{" ? "}" : "]";
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < trimmed.length; i++) {
    const ch = trimmed[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === opener) depth++;
    if (ch === closer) depth--;
    if (depth === 0) {
      return JSON.parse(trimmed.slice(start, i + 1));
    }
  }
  throw new Error("Model response contained incomplete JSON.");
}

function stripCodeFence(text: string): string {
  const match = text.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  return match ? match[1]!.trim() : text;
}

export function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return value as Record<string, unknown>;
}

export function asString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${label} must be a non-empty string.`);
  }
  return value.trim();
}

export function asStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array.`);
  return value.map((item, i) => asString(item, `${label}[${i}]`));
}

export function asNumberArray(value: unknown, label: string): number[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array.`);
  return value.map((item, i) => {
    if (!Number.isFinite(item) || !Number.isInteger(item)) {
      throw new Error(`${label}[${i}] must be an integer.`);
    }
    return item as number;
  });
}
