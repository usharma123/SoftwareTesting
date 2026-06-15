import { describe, expect, it } from "vitest";
import { resolveCodexProviderSettings } from "../agents/codex-sdk.js";

describe("resolveCodexProviderSettings", () => {
  it("uses OpenRouter when explicitly selected", () => {
    const settings = resolveCodexProviderSettings({
      DEEPSEC_AI_PROVIDER: "openrouter",
      OPENROUTER_API_KEY: "sk-or-x",
    } as NodeJS.ProcessEnv);

    expect(settings.apiKey).toBe("sk-or-x");
    expect(settings.baseUrl).toBe("https://openrouter.ai/api/v1");
    expect(settings.name).toBe("OpenRouter (OpenAI-compat)");
  });

  it("uses OpenRouter when it is the only available Codex key", () => {
    const settings = resolveCodexProviderSettings({
      OPENROUTER_API_KEY: "sk-or-x",
    } as NodeJS.ProcessEnv);

    expect(settings.apiKey).toBe("sk-or-x");
    expect(settings.baseUrl).toBe("https://openrouter.ai/api/v1");
  });

  it("preserves Vercel AI Gateway unless OpenRouter is selected", () => {
    const settings = resolveCodexProviderSettings({
      AI_GATEWAY_API_KEY: "gw-key",
      OPENAI_API_KEY: "gw-key",
      OPENROUTER_API_KEY: "sk-or-x",
      OPENAI_BASE_URL: "https://ai-gateway.vercel.sh/v1",
    } as NodeJS.ProcessEnv);

    expect(settings.apiKey).toBe("gw-key");
    expect(settings.baseUrl).toBe("https://ai-gateway.vercel.sh/v1");
    expect(settings.name).toBe("Vercel AI Gateway (OpenAI-compat)");
  });

  it("does not append a duplicate /v1 to OpenRouter's /api/v1 endpoint", () => {
    const settings = resolveCodexProviderSettings({
      DEEPSEC_AI_PROVIDER: "openrouter",
      OPENROUTER_API_KEY: "sk-or-x",
      OPENROUTER_BASE_URL: "https://openrouter.ai/api/v1/",
    } as NodeJS.ProcessEnv);

    expect(settings.baseUrl).toBe("https://openrouter.ai/api/v1");
  });

  it("normalizes OpenRouter's /api base to /api/v1", () => {
    const settings = resolveCodexProviderSettings({
      DEEPSEC_AI_PROVIDER: "openrouter",
      OPENROUTER_API_KEY: "sk-or-x",
      OPENROUTER_BASE_URL: "https://openrouter.ai/api",
    } as NodeJS.ProcessEnv);

    expect(settings.baseUrl).toBe("https://openrouter.ai/api/v1");
  });
});
