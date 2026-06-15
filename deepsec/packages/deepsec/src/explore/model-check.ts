import { JSON_OBJECT_RESPONSE_FORMAT } from "./response-formats.js";
import type { ModelClient, ModelUsage } from "./types.js";

export async function checkOpenRouterModelReachability(args: {
  client: ModelClient;
  model: string;
}): Promise<ModelUsage | undefined> {
  const response = await args.client.complete({
    model: args.model,
    temperature: 0,
    responseFormat: JSON_OBJECT_RESPONSE_FORMAT,
    messages: [
      {
        role: "system",
        content:
          "You are checking model API reachability for DeepSec. Reply only with compact JSON.",
      },
      {
        role: "user",
        content: 'Return exactly {"ok":true}.',
      },
    ],
  });
  let parsed: unknown;
  try {
    parsed = JSON.parse(response.text);
  } catch {
    throw new Error(`OpenRouter model check returned non-JSON output for ${args.model}.`);
  }
  if (!parsed || typeof parsed !== "object" || (parsed as Record<string, unknown>).ok !== true) {
    throw new Error(`OpenRouter model check returned an unexpected response for ${args.model}.`);
  }
  return response.usage;
}
