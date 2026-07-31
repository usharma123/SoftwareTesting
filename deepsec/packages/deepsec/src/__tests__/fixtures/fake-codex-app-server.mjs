import readline from "node:readline";

const lines = readline.createInterface({ input: process.stdin });
const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
let nextThread = 1;

lines.on("line", (line) => {
  const message = JSON.parse(line);
  if (message.method === "initialize") {
    send({ id: message.id, result: { userAgent: "fake" } });
    return;
  }
  if (message.method === "initialized") return;
  if (message.method === "model/list") {
    send({
      id: message.id,
      result: {
        data: [
          {
            id: "gpt-5.6-sol",
            displayName: "GPT-5.6-Sol",
            supportedReasoningEfforts: [{ reasoningEffort: "high" }],
          },
        ],
      },
    });
    return;
  }
  if (message.method === "thread/start") {
    send({ id: message.id, result: { thread: { id: `thread-${nextThread++}` } } });
    return;
  }
  if (message.method === "turn/start") {
    const threadId = message.params.threadId;
    const turnId = `turn-${threadId}`;
    const prompt = message.params.input?.[0]?.text ?? "";
    send({ id: message.id, result: { turn: { id: turnId, items: [], status: "inProgress" } } });
    if (prompt.includes("TRIGGER_TOOL")) {
      send({
        method: "item/completed",
        params: {
          threadId,
          turnId,
          item: { id: "tool-1", type: "commandExecution", command: "pwd", status: "completed" },
        },
      });
    }
    const text = JSON.stringify({
      effort: message.params.effort,
      hasSchema: message.params.outputSchema !== undefined,
      model: message.params.model,
    });
    const item = { id: "message-1", type: "agentMessage", text };
    send({ method: "item/completed", params: { threadId, turnId, item } });
    send({
      method: "thread/tokenUsage/updated",
      params: {
        threadId,
        turnId,
        tokenUsage: {
          last: {
            cachedInputTokens: 0,
            inputTokens: 11,
            outputTokens: 7,
            reasoningOutputTokens: 3,
            totalTokens: 21,
          },
          total: {
            cachedInputTokens: 0,
            inputTokens: 11,
            outputTokens: 7,
            reasoningOutputTokens: 3,
            totalTokens: 21,
          },
        },
      },
    });
    send({
      method: "turn/completed",
      params: { threadId, turn: { id: turnId, items: [item], status: "completed" } },
    });
  }
});
