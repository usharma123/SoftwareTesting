import {
  type ModelClient,
  type ModelMessage,
  type ModelResponse,
  type ModelResponseFormat,
  type ModelUsage,
  OPENROUTER_DEFAULT_BASE_URL,
  OPENROUTER_DEFAULT_MODEL,
} from "./types.js";

export class OpenRouterResponsesClient implements ModelClient {
  constructor(
    private readonly apiKey = requiredOpenRouterApiKey(),
    private readonly baseUrl = process.env.OPENROUTER_BASE_URL ?? OPENROUTER_DEFAULT_BASE_URL,
    private readonly timeoutMs = Number(process.env.OPENROUTER_TIMEOUT_MS ?? 240_000),
    private readonly maxOutputTokens = parseMaxOutputTokens(),
  ) {}

  async complete(params: {
    model: string;
    messages: ModelMessage[];
    temperature?: number;
    responseFormat?: ModelResponseFormat;
  }): Promise<ModelResponse> {
    const url = `${this.baseUrl.replace(/\/+$/, "")}/responses`;
    let maxOutputTokens = this.maxOutputTokens;
    let responseFormat = params.responseFormat;
    let lastError: unknown;
    for (let attempt = 1; attempt <= 4; attempt++) {
      try {
        const body = JSON.stringify(
          createResponsesRequestBody({
            model: params.model || OPENROUTER_DEFAULT_MODEL,
            messages: params.messages,
            temperature: params.temperature ?? 0.2,
            maxOutputTokens,
            responseFormat,
          }),
        );
        const { raw, text } = await postJson(url, this.apiKey, body, this.timeoutMs);
        if (raw.status >= 200 && raw.status < 300) {
          const outputText = extractResponseText(raw.json);
          if (!outputText.trim()) {
            throw new Error("OpenRouter Responses API returned an empty response.");
          }
          return { text: outputText, raw: raw.json, usage: extractUsage(raw.json) };
        }
        const message = `OpenRouter Responses API returned ${raw.status}: ${summarizeError(raw.json, text)}`;
        if (responseFormat && isResponseFormatRejected(raw.status, raw.json, text)) {
          responseFormat = undefined;
          lastError = new Error(`${message}; retrying without response_format.`);
          continue;
        }
        const affordable = raw.status === 402 ? parseAffordableOutputTokens(raw.json, text) : null;
        if (affordable !== null && affordable >= 256 && affordable < maxOutputTokens) {
          maxOutputTokens = Math.max(256, affordable - 32);
          lastError = new Error(message);
          continue;
        }
        if (!isRetryableStatus(raw.status) || attempt === 4) {
          throw new Error(message);
        }
        lastError = new Error(message);
      } catch (err) {
        lastError = err;
        if (attempt === 3 || !isRetryableError(err)) break;
      }
      await sleep(1000 * attempt);
    }
    throw normalizeOpenRouterError(lastError);
  }
}

function createResponsesRequestBody(args: {
  model: string;
  messages: ModelMessage[];
  temperature: number;
  maxOutputTokens: number;
  responseFormat?: ModelResponseFormat;
}): Record<string, unknown> {
  const body: Record<string, unknown> = {
    model: args.model,
    input: args.messages.map((m) => ({ role: m.role, content: m.content })),
    temperature: args.temperature,
    max_output_tokens: args.maxOutputTokens,
  };
  if (args.responseFormat) {
    body.response_format = toOpenRouterResponseFormat(args.responseFormat);
  }
  return body;
}

function toOpenRouterResponseFormat(format: ModelResponseFormat): Record<string, unknown> {
  if (format.type === "json_object") return { type: "json_object" };
  return {
    type: "json_schema",
    json_schema: {
      name: format.name,
      strict: format.strict ?? true,
      schema: format.schema,
    },
  };
}

async function postJson(
  url: string,
  apiKey: string,
  body: string,
  timeoutMs: number,
): Promise<{ raw: { status: number; json: unknown }; text: string }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "POST",
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/vercel-labs/deepsec",
        "X-Title": "DeepSec Explore",
      },
      body,
    });
    const text = await response.text();
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      json = { rawText: text };
    }
    return { raw: { status: response.status, json }, text };
  } finally {
    clearTimeout(timeout);
  }
}

export function requiredOpenRouterApiKey(): string {
  const key = process.env.OPENROUTER_API_KEY;
  if (!key) {
    throw new Error(
      "OPENROUTER_API_KEY is required for `deepsec explore`; direct OpenRouter is used for this local gVisor harness.",
    );
  }
  return key;
}

function parseMaxOutputTokens(): number {
  const raw = Number(process.env.OPENROUTER_MAX_OUTPUT_TOKENS ?? 4096);
  if (!Number.isFinite(raw)) return 4096;
  return Math.max(256, Math.min(16_384, Math.trunc(raw)));
}

function parseAffordableOutputTokens(raw: unknown, fallback: string): number | null {
  const message = summarizeError(raw, fallback);
  const match = message.match(/can only afford\s+(\d+)/i);
  if (!match) return null;
  const value = Number(match[1]);
  return Number.isFinite(value) ? Math.trunc(value) : null;
}

function isResponseFormatRejected(status: number, raw: unknown, fallback: string): boolean {
  if (status !== 400 && status !== 422) return false;
  const message = summarizeError(raw, fallback);
  return /\b(response_format|json_schema|structured output|schema)\b/i.test(message);
}

export function extractResponseText(raw: unknown): string {
  if (!raw || typeof raw !== "object") return "";
  const record = raw as Record<string, unknown>;
  if (typeof record.output_text === "string") return record.output_text;

  const output = record.output;
  if (Array.isArray(output)) {
    const parts: string[] = [];
    for (const item of output) {
      if (!item || typeof item !== "object") continue;
      const content = (item as Record<string, unknown>).content;
      if (!Array.isArray(content)) continue;
      for (const c of content) {
        if (!c || typeof c !== "object") continue;
        const cr = c as Record<string, unknown>;
        if (typeof cr.text === "string") parts.push(cr.text);
        if (typeof cr.output_text === "string") parts.push(cr.output_text);
      }
    }
    if (parts.length > 0) return parts.join("\n");
  }

  const choices = record.choices;
  if (Array.isArray(choices)) {
    const first = choices[0];
    if (first && typeof first === "object") {
      const message = (first as Record<string, unknown>).message;
      if (message && typeof message === "object") {
        const content = (message as Record<string, unknown>).content;
        if (typeof content === "string") return content;
      }
      const text = (first as Record<string, unknown>).text;
      if (typeof text === "string") return text;
    }
  }

  return "";
}

function extractUsage(raw: unknown): ModelUsage | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const rawUsage = (raw as Record<string, unknown>).usage;
  if (!rawUsage || typeof rawUsage !== "object") return undefined;
  const u = rawUsage as Record<string, unknown>;
  const inputTokens = pickNumber(u, ["input_tokens", "prompt_tokens"]);
  const outputTokens = pickNumber(u, ["output_tokens", "completion_tokens"]);
  if (inputTokens === undefined || outputTokens === undefined) return undefined;
  const usage: ModelUsage = { inputTokens, outputTokens };
  const costUsd = pickNumber(u, ["cost", "cost_usd", "total_cost", "total_cost_usd"]);
  if (costUsd !== undefined) usage.costUsd = costUsd;
  return usage;
}

function pickNumber(record: Record<string, unknown>, keys: string[]): number | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim() !== "") {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return undefined;
}

function summarizeError(raw: unknown, fallback: string): string {
  if (raw && typeof raw === "object") {
    const error = (raw as Record<string, unknown>).error;
    if (error && typeof error === "object") {
      const message = (error as Record<string, unknown>).message;
      if (typeof message === "string") return message.slice(0, 1000);
    }
    const message = (raw as Record<string, unknown>).message;
    if (typeof message === "string") return message.slice(0, 1000);
  }
  return fallback.slice(0, 1000);
}

function isRetryableStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

function isRetryableError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return /terminated|timeout|aborted|ECONNRESET|EPIPE|ENOTFOUND|ETIMEDOUT|fetch failed/i.test(
    message,
  );
}

function normalizeOpenRouterError(err: unknown): Error {
  if (err instanceof Error) return err;
  return new Error(String(err));
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}
