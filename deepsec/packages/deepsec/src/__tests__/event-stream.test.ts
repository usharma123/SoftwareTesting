import { describe, expect, it } from "vitest";
import { createProcessExploreEventSink, EXPLORE_EVENT_PREFIX } from "../explore/event-stream.js";

describe("explore event stream", () => {
  it("stays silent unless explicitly enabled", () => {
    const chunks: string[] = [];
    const sink = createProcessExploreEventSink({}, (chunk) => chunks.push(chunk));
    expect(sink).toBeUndefined();
    expect(chunks).toEqual([]);
  });

  it("writes one prefixed JSON record per event", () => {
    const chunks: string[] = [];
    const sink = createProcessExploreEventSink({ DEEPSEC_EVENT_STREAM: "1" }, (chunk) =>
      chunks.push(chunk),
    );
    sink?.({
      kind: "run-start",
      at: "2026-07-14T12:00:00.000Z",
      runId: "run-1",
      projectId: "demo",
    });

    expect(chunks).toHaveLength(1);
    expect(chunks[0]?.startsWith(EXPLORE_EVENT_PREFIX)).toBe(true);
    expect(JSON.parse(chunks[0]!.slice(EXPLORE_EVENT_PREFIX.length))).toMatchObject({
      kind: "run-start",
      runId: "run-1",
      projectId: "demo",
    });
  });
});
