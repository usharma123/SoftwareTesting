#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createCanvasBridge } from "../index.mjs";

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "deepsec-canvas-smoke-"));
const bridge = await createCanvasBridge({ port: 0, recordRoot: tempRoot });
const headers = {
  Origin: bridge.origin,
  "Content-Type": "application/json",
  "X-DeepSec-Canvas-Token": bridge.token,
};

try {
  const unauthorized = await fetch(`${bridge.origin}/api/status`);
  assert.equal(unauthorized.status, 401);

  const crossOrigin = await fetch(`${bridge.origin}/api/start`, {
    method: "POST",
    headers: { ...headers, Origin: "http://example.invalid" },
    body: JSON.stringify({ mode: "simulation" }),
  });
  assert.equal(crossOrigin.status, 403);

  const invalidLive = await fetch(`${bridge.origin}/api/start`, {
    method: "POST",
    headers,
    body: JSON.stringify({ mode: "live", options: {} }),
  });
  assert.equal(invalidLive.status, 400);

  const eventResponse = await fetch(
    `${bridge.origin}/api/events?token=${encodeURIComponent(bridge.token)}`,
  );
  assert.equal(eventResponse.status, 200);
  const eventReader = eventResponse.body.getReader();

  const start = await fetch(`${bridge.origin}/api/start`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      mode: "simulation",
      options: { limit: 4, maxTurns: 6, simulationDelayMs: 5 },
    }),
  });
  assert.equal(start.status, 202);
  const started = await start.json();
  assert.equal(started.accepted, true);

  const deadline = Date.now() + 10_000;
  let status;
  while (Date.now() < deadline) {
    const response = await fetch(
      `${bridge.origin}/api/status?token=${encodeURIComponent(bridge.token)}`,
    );
    assert.equal(response.status, 200);
    status = await response.json();
    if (status.run?.state === "complete") break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.equal(status.run.state, "complete");
  assert.equal(status.run.mode, "simulation");
  assert.equal(status.run.eventCount > 10, true);

  const recordingsResponse = await fetch(
    `${bridge.origin}/api/recordings?token=${encodeURIComponent(bridge.token)}`,
  );
  const { recordings } = await recordingsResponse.json();
  assert.equal(recordings.length, 1);
  assert.equal(recordings[0].sessionId, started.sessionId);

  const log = await fs.readFile(
    path.join(tempRoot, started.sessionId, "canvas-events.jsonl"),
    "utf8",
  );
  assert.equal(log.includes("mvn -q test"), false);
  assert.equal(log.includes('"commandType":"mvn"'), true);
  const records = log
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(records[0].event.kind, "canvas-reset");
  const firstStart = records.findIndex((record) => record.event.kind === "attempt-start");
  const secondStart = records.findIndex(
    (record, index) => index > firstStart && record.event.kind === "attempt-start",
  );
  const firstFinish = records.findIndex((record) => record.event.kind === "attempt-finish");
  assert.equal(firstStart >= 0 && secondStart > firstStart && secondStart < firstFinish, true);

  const streamChunk = await eventReader.read();
  assert.equal(new TextDecoder().decode(streamChunk.value).includes("canvas-"), true);
  await eventReader.cancel();

  const replay = await fetch(`${bridge.origin}/api/replay/start`, {
    method: "POST",
    headers,
    body: JSON.stringify({ sessionId: started.sessionId, speed: 16 }),
  });
  assert.equal(replay.status, 202);
  const replayBody = await replay.json();

  const pause = await fetch(`${bridge.origin}/api/replay/pause`, {
    method: "POST",
    headers,
    body: "{}",
  });
  assert.equal(pause.status, 200);
  const seek = await fetch(`${bridge.origin}/api/replay/seek`, {
    method: "POST",
    headers,
    body: JSON.stringify({ index: 10 }),
  });
  assert.equal(seek.status, 200);
  assert.equal((await seek.json()).index, 10);

  process.stdout.write(
    `${JSON.stringify({
      ok: true,
      events: status.run.eventCount,
      recording: recordings[0],
      replay: replayBody,
    })}\n`,
  );
} finally {
  await bridge.close();
  await fs.rm(tempRoot, { recursive: true, force: true });
}
