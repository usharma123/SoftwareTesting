import type { ModelResponseFormat } from "./types.js";

export const JSON_OBJECT_RESPONSE_FORMAT: ModelResponseFormat = { type: "json_object" };

export const RANKING_RESPONSE_FORMAT: ModelResponseFormat = {
  type: "json_schema",
  name: "deepsec_file_rankings",
  strict: true,
  schema: {
    type: "object",
    additionalProperties: false,
    properties: {
      rankings: {
        type: "array",
        minItems: 1,
        maxItems: 12,
        items: {
          type: "object",
          additionalProperties: false,
          properties: {
            filePath: { type: "string" },
            score: { type: "integer", minimum: 1, maximum: 5 },
            reason: { type: "string" },
          },
          required: ["filePath", "score", "reason"],
        },
      },
    },
    required: ["rankings"],
  },
};
