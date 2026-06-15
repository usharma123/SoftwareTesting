import type { ModelClient, ModelMessage, ModelResponse, ModelUsage } from "./types.js";
import { addModelUsage, formatModelUsage } from "./usage.js";

export interface ModelBudget {
  maxTokens?: number;
  maxCostUsd?: number;
}

export class BudgetedModelClient implements ModelClient {
  private usage: ModelUsage | undefined;

  constructor(
    private readonly inner: ModelClient,
    private readonly budget: ModelBudget,
  ) {}

  async complete(params: {
    model: string;
    messages: ModelMessage[];
    temperature?: number;
  }): Promise<ModelResponse> {
    this.assertBudgetAvailable();
    const response = await this.inner.complete(params);
    this.usage = addModelUsage(this.usage, response.usage);
    return response;
  }

  currentUsage(): ModelUsage | undefined {
    return this.usage;
  }

  private assertBudgetAvailable(): void {
    const usage = this.usage;
    if (!usage) return;
    const tokens = usage.inputTokens + usage.outputTokens;
    if (this.budget.maxTokens !== undefined && tokens >= this.budget.maxTokens) {
      throw new Error(
        `Explore model token budget exhausted: ${tokens} tokens used, max ${this.budget.maxTokens}.`,
      );
    }
    if (
      this.budget.maxCostUsd !== undefined &&
      usage.costUsd !== undefined &&
      usage.costUsd >= this.budget.maxCostUsd
    ) {
      throw new Error(
        `Explore model cost budget exhausted: ${formatModelUsage(usage) ?? "usage unavailable"}, max cost=$${this.budget.maxCostUsd.toFixed(6)}.`,
      );
    }
  }
}

export function maybeBudgetModelClient(client: ModelClient, budget: ModelBudget): ModelClient {
  if (budget.maxTokens === undefined && budget.maxCostUsd === undefined) return client;
  return new BudgetedModelClient(client, budget);
}
