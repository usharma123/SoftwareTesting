#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { spawn, execFile } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  hydrateAttempt,
  hydrateAttemptFailure,
  hydrateSummary,
  retryArtifactHydration,
} from "./lib/artifacts.mjs";
import { ReplayController, readReplayEvents } from "./lib/replay.mjs";
import {
  isSafeSegment,
  sanitizeCanvasEvent,
  sanitizeError,
  sanitizeLogLine,
} from "./lib/sanitize.mjs";

const EVENT_PREFIX = "@@deepsec:event@@";
const SERVER_DIR = path.dirname(fileURLToPath(import.meta.url));
const APP_DIR = path.resolve(SERVER_DIR, "..");
const DEEPSEC_ROOT = path.resolve(SERVER_DIR, "../../..");
const HARNESS_PATH = path.join(DEEPSEC_ROOT, "scripts", "explore-harness.sh");
const DEFAULT_UI_DIR = path.join(APP_DIR, "dist");
const DEFAULT_RECORD_ROOT = path.join(DEEPSEC_ROOT, ".deepsec-explore-runs", "canvas");
const MAX_BODY_BYTES = 64 * 1024;
const MAX_HISTORY = 20_000;
const MAX_LINE_BYTES = 1024 * 1024;
const SSE_HEARTBEAT_MS = 15_000;

export async function createCanvasBridge(options = {}) {
  const bridge = new CanvasBridge(options);
  await bridge.listen();
  return bridge;
}

class CanvasBridge {
  constructor(options) {
    this.host = "127.0.0.1";
    this.port = normalizePort(options.port ?? 0);
    this.uiDir = path.resolve(options.uiDir ?? DEFAULT_UI_DIR);
    this.recordRoot = path.resolve(options.recordRoot ?? DEFAULT_RECORD_ROOT);
    this.token = options.token ?? crypto.randomBytes(32).toString("base64url");
    this.startedAt = new Date().toISOString();
    this.sequence = 0;
    this.history = [];
    this.clients = new Set();
    this.active = undefined;
    this.lastRun = undefined;
    this.lastError = undefined;
    this.lastLog = undefined;
    this.replayState = {
      state: "idle",
      index: 0,
      total: 0,
      position: 0,
      speed: 1,
      sessionId: undefined,
    };
    this.replay = new ReplayController({
      emit: (event) => this.publish(event, "replay", { record: false }),
      onState: (state) => {
        this.replayState = { ...this.replayState, ...state };
      },
      onReset: ({ targetIndex }) => {
        this.publish(
          {
            kind: "replay-reset",
            at: new Date().toISOString(),
            sessionId: this.replayState.sessionId,
            mode: "replay",
            reason: targetIndex === 0 ? "Replay started" : "Replay seek rebuilt canvas state",
            targetIndex,
          },
          "bridge",
          { record: false },
        );
      },
    });
    this.server = http.createServer((request, response) => {
      this.handleRequest(request, response).catch((error) => {
        this.lastError = sanitizeError(error);
        if (!response.headersSent) {
          const status =
            Number.isInteger(error?.status) && error.status >= 400 && error.status <= 499
              ? error.status
              : 500;
          sendJson(response, status, {
            error: status === 500 ? "Internal bridge error." : this.lastError,
          });
        } else {
          response.destroy();
        }
      });
    });
  }

  async listen() {
    await fsp.mkdir(this.recordRoot, { recursive: true, mode: 0o700 });
    await new Promise((resolve, reject) => {
      const onError = (error) => {
        this.server.off("listening", onListening);
        reject(error);
      };
      const onListening = () => {
        this.server.off("error", onError);
        resolve();
      };
      this.server.once("error", onError);
      this.server.once("listening", onListening);
      this.server.listen(this.port, this.host);
    });
    const address = this.server.address();
    if (!address || typeof address === "string") throw new Error("Bridge did not bind a TCP port.");
    this.port = address.port;
    this.origin = `http://${this.host}:${this.port}`;
    this.heartbeat = setInterval(() => {
      for (const client of this.clients) client.write(": heartbeat\n\n");
    }, SSE_HEARTBEAT_MS);
    this.heartbeat.unref?.();
    this.supervisorTimer = setInterval(() => void this.pollSupervisor(), 10_000);
    this.supervisorTimer.unref?.();
    return this;
  }

  get url() {
    return `${this.origin}/?token=${encodeURIComponent(this.token)}`;
  }

  status() {
    const active = this.active;
    return {
      bridge: {
        state: "ready",
        host: this.host,
        port: this.port,
        startedAt: this.startedAt,
        clients: this.clients.size,
        offline: true,
      },
      run: active
        ? {
            sessionId: active.sessionId,
            mode: active.mode,
            state: active.state,
            pid: active.child?.pid,
            projectId: active.projectId,
            runId: active.runId,
            dataRoot: active.dataRoot,
            targetRoot: active.targetRoot,
            startedAt: active.startedAt,
            endedAt: active.endedAt,
            exitCode: active.exitCode,
            signal: active.signal,
            phase: active.phase,
            eventCount: active.eventCount,
            lastEventAt: active.lastEventAt,
            stopRequested: active.stopRequested,
          }
        : this.lastRun,
      replay: this.replayState,
      lastError: this.lastError,
      lastLog: this.lastLog,
      routes: {
        events: "/api/events",
        status: "/api/status",
        start: "/api/start",
        stop: "/api/stop",
        recordings: "/api/recordings",
        replay: "/api/replay/{start,pause,resume,seek,stop}",
      },
    };
  }

  async close() {
    if (this.active && ["starting", "running", "stopping"].includes(this.active.state)) {
      await this.stopRun();
    }
    this.replay.stop();
    clearInterval(this.heartbeat);
    clearInterval(this.supervisorTimer);
    for (const client of this.clients) client.end();
    this.clients.clear();
    await new Promise((resolve) => this.server.close(() => resolve()));
  }

  async handleRequest(request, response) {
    setSecurityHeaders(response);
    if (!this.validHost(request)) {
      sendJson(response, 421, { error: "Invalid Host header." });
      return;
    }

    const url = new URL(request.url ?? "/", this.origin);
    if (request.method === "GET" && url.pathname === "/api/status") {
      if (!this.authorized(request, url)) return sendJson(response, 401, { error: "Unauthorized." });
      sendJson(response, 200, this.status());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/events") {
      if (!this.authorized(request, url)) return sendJson(response, 401, { error: "Unauthorized." });
      this.openEventStream(request, response);
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/recordings") {
      if (!this.authorized(request, url)) return sendJson(response, 401, { error: "Unauthorized." });
      sendJson(response, 200, { recordings: await this.listRecordings() });
      return;
    }

    if (request.method === "POST" && url.pathname.startsWith("/api/")) {
      if (!this.authorized(request, url)) return sendJson(response, 401, { error: "Unauthorized." });
      if (!this.sameOrigin(request)) {
        return sendJson(response, 403, { error: "Mutation requires the bridge's exact origin." });
      }
      if (!isJsonRequest(request)) {
        return sendJson(response, 415, { error: "Mutation body must be application/json." });
      }
      const body = await readJsonBody(request);
      await this.handleMutation(url.pathname, body, response);
      return;
    }

    if (request.method === "GET" || request.method === "HEAD") {
      await this.serveStatic(url.pathname, request.method === "HEAD", response);
      return;
    }
    sendJson(response, 404, { error: "Not found." });
  }

  validHost(request) {
    return request.headers.host === `${this.host}:${this.port}`;
  }

  authorized(request, url) {
    const queryToken = url.searchParams.get("token");
    const headerToken = request.headers["x-deepsec-canvas-token"];
    const bearer = request.headers.authorization?.replace(/^Bearer\s+/i, "");
    return safeTokenEqual(this.token, queryToken ?? headerToken ?? bearer);
  }

  sameOrigin(request) {
    return request.headers.origin === this.origin;
  }

  async handleMutation(pathname, body, response) {
    switch (pathname) {
      case "/api/start": {
        const result = await this.startRun(body);
        sendJson(response, 202, result);
        return;
      }
      case "/api/stop": {
        const result = await this.stopRun();
        sendJson(response, 200, result);
        return;
      }
      case "/api/replay/start": {
        const result = await this.startReplay(body);
        sendJson(response, 202, result);
        return;
      }
      case "/api/replay/pause":
        this.replay.pause();
        sendJson(response, 200, this.replayState);
        return;
      case "/api/replay/resume":
        this.replay.resume();
        sendJson(response, 200, this.replayState);
        return;
      case "/api/replay/seek":
        this.history = [];
        this.replay.seek(body);
        sendJson(response, 200, this.replayState);
        return;
      case "/api/replay/stop":
        this.replay.stop();
        this.replayState.sessionId = undefined;
        sendJson(response, 200, this.replayState);
        return;
      default:
        sendJson(response, 404, { error: "Unknown mutation route." });
    }
  }

  openEventStream(request, response) {
    response.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    response.flushHeaders?.();
    response.write(`event: canvas-status\ndata: ${JSON.stringify(this.status())}\n\n`);
    const lastId = Number.parseInt(request.headers["last-event-id"] ?? "0", 10);
    for (const record of this.history) {
      if (!Number.isFinite(lastId) || record.seq > lastId) writeSse(response, record);
    }
    this.clients.add(response);
    request.on("close", () => this.clients.delete(response));
  }

  async startRun(body) {
    if (this.active && ["starting", "running", "stopping"].includes(this.active.state)) {
      throw httpError(409, "A run is already active.");
    }
    if (["running", "paused"].includes(this.replayState.state)) {
      throw httpError(409, "Stop the replay before starting a run.");
    }
    this.replay.stop();
    this.replayState.sessionId = undefined;
    const mode = body?.mode === "live" ? "live" : body?.mode === "simulation" ? "simulation" : undefined;
    if (!mode) throw httpError(400, "mode must be live or simulation.");

    const runOptions = normalizeRunOptions(body?.options ?? {}, mode);
    const sessionId = createSessionId(mode);
    const sessionDir = safeSessionPath(this.recordRoot, sessionId);
    const dataRoot = path.join(sessionDir, "deepsec-data");
    await fsp.mkdir(dataRoot, { recursive: true, mode: 0o700 });
    const eventLogPath = path.join(sessionDir, "canvas-events.jsonl");
    const logStream = fs.createWriteStream(eventLogPath, {
      flags: "wx",
      encoding: "utf8",
      mode: 0o600,
    });
    await new Promise((resolve, reject) => {
      logStream.once("open", resolve);
      logStream.once("error", reject);
    });

    const active = {
      sessionId,
      sessionDir,
      dataRoot,
      eventLogPath,
      logStream,
      mode,
      state: "starting",
      startedAt: new Date().toISOString(),
      endedAt: undefined,
      exitCode: undefined,
      signal: undefined,
      stopRequested: false,
      eventCount: 0,
      lastEventAt: undefined,
      phase: "initialization",
      projectId: runOptions.projectId,
      runId: undefined,
      targetRoot: runOptions.root,
      child: undefined,
      timers: new Set(),
      recording: {
        schemaVersion: 1,
        sessionId,
        mode,
        state: "starting",
        createdAt: new Date().toISOString(),
        projectId: runOptions.projectId,
        targetLabel: runOptions.root ? path.basename(runOptions.root) : undefined,
        configuration: {
          profile: runOptions.profile,
          modelProvider: runOptions.modelProvider,
          model: runOptions.model,
          rankModel: runOptions.rankModel,
          reasoningEffort: runOptions.reasoningEffort,
          limit: runOptions.allFiles ? undefined : runOptions.limit,
          allFiles: runOptions.allFiles,
          concurrency: runOptions.concurrency,
          maxTurns: runOptions.maxTurns,
          stubModel: runOptions.stubModel,
          skipSetup: runOptions.skipSetup,
          skipDoctor: runOptions.skipDoctor,
        },
      },
    };
    this.active = active;
    this.lastError = undefined;
    this.history = [];
    await this.writeRecordingMetadata(active);
    this.publish(
      {
        kind: "canvas-reset",
        at: active.startedAt,
        sessionId,
        mode,
        reason: "New run session",
      },
      "bridge",
    );
    this.publish(
      {
        kind: "bridge-state",
        at: active.startedAt,
        state: "starting",
        mode,
        sessionId,
        detail: mode === "live" ? "Launching DeepSec harness" : "Launching deterministic simulation",
      },
      "bridge",
    );

    if (mode === "simulation") {
      active.state = "running";
      this.runSimulation(active, runOptions);
    } else {
      await this.launchHarness(active, runOptions);
    }
    return { accepted: true, sessionId, mode, status: this.status().run };
  }

  async launchHarness(active, options) {
    const args = buildHarnessArgs(options, active.dataRoot);
    const child = spawn(HARNESS_PATH, args, {
      cwd: DEEPSEC_ROOT,
      env: {
        ...process.env,
        DEEPSEC_EVENT_STREAM: "1",
        DEEPSEC_HARNESS_ROOT: DEEPSEC_ROOT,
      },
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    active.child = child;
    active.state = "running";
    this.consumeLines(child.stdout, (line) => this.handleHarnessLine(line, active));
    this.consumeLines(child.stderr, (line) => this.handleHarnessLog(line));
    child.once("error", (error) => {
      this.lastError = sanitizeError(error);
      this.publish(
        {
          kind: "bridge-state",
          at: new Date().toISOString(),
          state: "failed",
          mode: "live",
          sessionId: active.sessionId,
          detail: this.lastError,
        },
        "bridge",
      );
    });
    child.once("close", (exitCode, signal) => {
      this.finishActiveRun(active, {
        exitCode: exitCode ?? (active.stopRequested ? 0 : 1),
        signal,
        state: active.stopRequested ? "stopped" : exitCode === 0 ? "complete" : "failed",
      });
    });
    this.publish(
      {
        kind: "bridge-state",
        at: new Date().toISOString(),
        state: "running",
        mode: "live",
        sessionId: active.sessionId,
        detail: `Harness process ${child.pid} started`,
      },
      "bridge",
    );
  }

  consumeLines(stream, onLine) {
    let buffer = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      buffer += chunk;
      if (Buffer.byteLength(buffer, "utf8") > MAX_LINE_BYTES * 2) {
        buffer = buffer.slice(-MAX_LINE_BYTES);
        this.lastError = "Harness emitted an overlong output line; it was truncated.";
      }
      let newline = buffer.indexOf("\n");
      while (newline !== -1) {
        const line = buffer.slice(0, newline).replace(/\r$/, "");
        buffer = buffer.slice(newline + 1);
        onLine(line);
        newline = buffer.indexOf("\n");
      }
    });
    stream.on("end", () => {
      if (buffer) onLine(buffer);
    });
  }

  handleHarnessLine(line, active) {
    const marker = line.indexOf(EVENT_PREFIX);
    if (marker < 0) {
      this.handleHarnessLog(line);
      return;
    }
    const json = line.slice(marker + EVENT_PREFIX.length);
    let parsed;
    try {
      parsed = JSON.parse(json);
    } catch {
      this.lastError = "DeepSec emitted a malformed structured event.";
      return;
    }
    const event = sanitizeCanvasEvent(parsed);
    if (!event) return;
    this.updateRunFromEvent(active, event);
    this.publish(event, "live");
    this.hydrateForEvent(active, event);
  }

  handleHarnessLog(line) {
    const sanitized = sanitizeLogLine(line);
    if (sanitized) this.lastLog = sanitized;
  }

  async pollSupervisor() {
    const active = this.active;
    if (!active || active.state !== "running" || active.supervisorPolling) return;
    active.supervisorPolling = true;
    try {
      const eventAgeMs = active.lastEventAt
        ? Math.max(0, Date.now() - Date.parse(active.lastEventAt))
        : Math.max(0, Date.now() - Date.parse(active.startedAt));
      const processAlive =
        active.mode === "simulation"
          ? true
          : Boolean(active.child?.pid && exactProcessAlive(active.child.pid));
      const containers =
        active.mode === "live" && active.runId
          ? await this.listOwnedContainers(active.runId, false)
          : [];
      this.publish(
        {
          kind: "supervisor-pulse",
          at: new Date().toISOString(),
          state: processAlive ? "healthy" : "process-exited",
          phase: active.phase,
          processAlive,
          containerCount: containers.length,
          clientCount: this.clients.size,
          eventAgeMs,
          quiet: eventAgeMs >= 120_000,
          stalled: eventAgeMs >= 360_000,
        },
        "supervisor",
      );
    } catch (error) {
      this.lastError = `Supervisor check failed: ${sanitizeError(error)}`;
    } finally {
      active.supervisorPolling = false;
    }
  }

  updateRunFromEvent(active, event) {
    active.lastEventAt = event.at ?? new Date().toISOString();
    if (event.kind === "run-start") {
      active.projectId = event.projectId;
      active.runId = event.runId;
    }
    if (event.kind === "harness-phase") active.phase = event.phase ?? active.phase;
    if (event.projectId && isSafeSegment(event.projectId)) active.projectId = event.projectId;
    if (event.runId && isSafeSegment(event.runId)) active.runId = event.runId;
  }

  hydrateForEvent(active, event) {
    if (!active.projectId || !active.runId) return;
    const identity = {
      dataRoot: active.dataRoot,
      projectId: active.projectId,
      runId: active.runId,
    };
    if (event.kind === "attempt-finish" && Number.isInteger(event.attemptIndex)) {
      retryArtifactHydration(() =>
        hydrateAttempt({ ...identity, attemptIndex: event.attemptIndex }),
      )
        .then((hydrated) => hydrated && this.publish(hydrated, "hydration"))
        .catch((error) => {
          this.lastError = sanitizeError(error);
        });
    }
    if (event.kind === "attempt-fail" && Number.isInteger(event.attemptIndex)) {
      retryArtifactHydration(() =>
        hydrateAttemptFailure({ ...identity, attemptIndex: event.attemptIndex }),
      )
        .then((hydrated) => hydrated && this.publish(hydrated, "hydration"))
        .catch((error) => {
          this.lastError = sanitizeError(error);
        });
    }
    if (event.kind === "run-complete") {
      retryArtifactHydration(() => hydrateSummary(identity))
        .then((hydrated) => hydrated && this.publish(hydrated, "hydration"))
        .catch((error) => {
          this.lastError = sanitizeError(error);
        });
    }
  }

  publish(input, source, options = {}) {
    const event = sanitizeCanvasEvent(input);
    if (!event) return undefined;
    const record = {
      seq: ++this.sequence,
      source,
      receivedAt: new Date().toISOString(),
      event,
    };
    this.history.push(record);
    if (this.history.length > MAX_HISTORY) this.history.splice(0, this.history.length - MAX_HISTORY);
    if (this.active && options.record !== false && source !== "replay") {
      this.active.eventCount += 1;
      if (source !== "supervisor" && source !== "bridge") {
        this.active.lastEventAt = record.receivedAt;
      }
      this.active.logStream.write(`${JSON.stringify(record)}\n`);
    }
    for (const client of this.clients) writeSse(client, record);
    return record;
  }

  runSimulation(active, options) {
    const now = () => new Date().toISOString();
    const runId = `sim-${crypto.randomBytes(6).toString("hex")}`;
    const projectId = options.projectId ?? "deepsec-demo";
    active.projectId = projectId;
    active.runId = runId;
    const files = Array.from({ length: options.limit }, (_, index) => {
      const names = [
        "src/main/java/com/acme/AuthService.java",
        "src/main/java/com/acme/PaymentParser.java",
        "src/main/java/com/acme/ArchiveReader.java",
        "src/main/java/com/acme/TokenValidator.java",
      ];
      return names[index % names.length].replace(".java", `${index + 1}.java`);
    });
    const schedule = [];
    schedule.push({ kind: "harness-phase", at: now(), phase: "setup", status: "skipped" });
    schedule.push({ kind: "harness-phase", at: now(), phase: "doctor", status: "complete" });
    schedule.push({
      kind: "harness-phase",
      at: now(),
      phase: "exploration",
      status: "start",
    });
    schedule.push({ kind: "run-start", at: now(), projectId, runId, detail: "simulation" });
    schedule.push({ kind: "ranking", at: now(), detail: "ranking simulated production files" });
    schedule.push({
      kind: "ranking-done",
      at: now(),
      detail: `selected ${files.length} focused attempts`,
    });
    files.forEach((focusFile, attemptIndex) => {
      schedule.push({
        kind: "attempt-queued",
        at: now(),
        attemptIndex,
        focusFile,
        detail: `score ${5 - (attemptIndex % 3)}`,
      });
    });
    for (let waveStart = 0; waveStart < files.length; waveStart += options.concurrency) {
      const wave = files
        .slice(waveStart, waveStart + options.concurrency)
        .map((focusFile, offset) => ({ focusFile, attemptIndex: waveStart + offset }));
      for (const { focusFile, attemptIndex } of wave) {
        schedule.push({ kind: "attempt-start", at: now(), attemptIndex, focusFile });
      }
      for (let turn = 1; turn <= 3; turn += 1) {
        for (const { focusFile, attemptIndex } of wave) {
          schedule.push({
            kind: "progress",
            attemptIndex,
            focusFile,
            phase: "explore",
            event: { type: "model-request", at: now(), turn, maxTurns: options.maxTurns },
          });
          schedule.push({
            kind: "progress",
            attemptIndex,
            focusFile,
            phase: "explore",
            event: {
              type: "model-response",
              at: now(),
              turn,
              maxTurns: options.maxTurns,
              responseChars: 800 + attemptIndex * 17,
              usage: { inputTokens: 900 + turn * 40, outputTokens: 220 + turn * 20 },
            },
          });
          schedule.push({
            kind: "progress",
            attemptIndex,
            focusFile,
            phase: "explore",
            event: {
              type: "action",
              at: now(),
              turn,
              maxTurns: options.maxTurns,
              action: "run_command",
              command: turn === 1 ? "rg auth src" : "mvn -q test",
              timeoutMs: 60_000,
              reason: turn === 1 ? "Trace trust boundaries" : "Validate the candidate path",
              redacted: false,
            },
          });
        }
      }
      for (const { focusFile, attemptIndex } of wave) {
        const bug = attemptIndex % 5 === 1;
        schedule.push({
          kind: "attempt-finish",
          at: now(),
          attemptIndex,
          focusFile,
          outcome: bug ? "bug" : "no-bug",
          detail: bug ? "bug (true-positive)" : "no-bug",
        });
        schedule.push({
          kind: "attempt-hydrated",
          at: now(),
          projectId,
          runId,
          attemptIndex,
          focusFile,
          model: "simulation",
          turns: 3,
          finding: bug
            ? {
                outcome: "bug",
                title: "Archive entry escapes the intended extraction directory",
                severity: attemptIndex % 2 ? "HIGH" : "MEDIUM",
                confidence: "HIGH",
                vulnSlug: "path-traversal",
                lineNumbers: [42 + attemptIndex],
              }
            : { outcome: "no-bug" },
          validation: bug
            ? { verdict: "true-positive", reproducible: true, interesting: true }
            : undefined,
          usage: { inputTokens: 2_940, outputTokens: 720 },
          isolation: {
            runtime: "runsc",
            networkMode: "none",
            readOnlyRootfs: true,
            noNewPrivileges: true,
          },
          workspaceChanges: 0,
        });
      }
    }
    schedule.push({
      kind: "run-complete",
      at: now(),
      projectId,
      runId,
      detail: `${files.length} completed · 0 failed`,
    });
    schedule.push({
      kind: "summary-hydrated",
      at: now(),
      projectId,
      runId,
      attempts: files.length,
      completedAttempts: files.length,
      failedAttempts: 0,
      bugsReported: files.filter((_, index) => index % 5 === 1).length,
      acceptedFindings: files.filter((_, index) => index % 5 === 1).length,
    });
    schedule.push({
      kind: "harness-phase",
      at: now(),
      phase: "bundle",
      status: "complete",
    });
    schedule.push({
      kind: "harness-complete",
      at: now(),
      status: "complete",
      exitCode: 0,
      projectId,
      runId,
    });

    const delayMs = options.simulationDelayMs;
    let index = 0;
    const tick = () => {
      if (this.active !== active || active.stopRequested) return;
      const event = schedule[index];
      index += 1;
      if (!event) {
        this.finishActiveRun(active, { exitCode: 0, state: "complete" });
        return;
      }
      this.updateRunFromEvent(active, event);
      this.publish(event, event.kind.endsWith("-hydrated") ? "hydration" : "simulation");
      const timer = setTimeout(tick, delayMs);
      active.timers.add(timer);
      timer.unref?.();
    };
    tick();
  }

  finishActiveRun(active, result) {
    if (active.finished) return;
    active.finished = true;
    for (const timer of active.timers) clearTimeout(timer);
    active.timers.clear();
    active.state = result.state;
    active.exitCode = result.exitCode;
    active.signal = result.signal ?? undefined;
    active.endedAt = new Date().toISOString();
    active.recording = {
      ...active.recording,
      state: active.state,
      projectId: active.projectId,
      runId: active.runId,
      endedAt: active.endedAt,
      exitCode: active.exitCode,
      signal: active.signal,
      eventCount: active.eventCount,
    };
    this.publish(
      {
        kind: "bridge-state",
        at: active.endedAt,
        state: active.state,
        mode: active.mode,
        exitCode: active.exitCode,
        signal: active.signal,
        sessionId: active.sessionId,
      },
      "bridge",
    );
    active.recording.eventCount = active.eventCount;
    active.logStream.end();
    void this.writeRecordingMetadata(active).catch((error) => {
      this.lastError = `Recording metadata failed: ${sanitizeError(error)}`;
    });
    this.lastRun = {
      sessionId: active.sessionId,
      mode: active.mode,
      state: active.state,
      projectId: active.projectId,
      runId: active.runId,
      dataRoot: active.dataRoot,
      targetRoot: active.targetRoot,
      startedAt: active.startedAt,
      endedAt: active.endedAt,
      exitCode: active.exitCode,
      signal: active.signal,
      phase: active.phase,
      eventCount: active.eventCount,
      lastEventAt: active.lastEventAt,
      stopRequested: active.stopRequested,
    };
    if (this.active === active) this.active = undefined;
  }

  async stopRun() {
    const active = this.active;
    if (!active || !["starting", "running", "stopping"].includes(active.state)) {
      return { stopped: false, reason: "No active run." };
    }
    active.stopRequested = true;
    active.state = "stopping";
    this.publish(
      {
        kind: "bridge-state",
        at: new Date().toISOString(),
        state: "stopping",
        mode: active.mode,
        sessionId: active.sessionId,
      },
      "bridge",
    );
    for (const timer of active.timers) clearTimeout(timer);
    active.timers.clear();
    if (active.mode === "simulation") {
      this.finishActiveRun(active, { exitCode: 0, state: "stopped" });
      return { stopped: true, sessionId: active.sessionId };
    }

    const child = active.child;
    if (child?.pid && child.exitCode === null) {
      signalExactProcess(child.pid, "SIGTERM");
      await waitForChild(child, 4_000);
    }
    const containers = await this.removeOwnedContainers(active.runId);
    if (child?.pid && child.exitCode === null) {
      signalExactProcess(child.pid, "SIGKILL");
      await waitForChild(child, 2_000);
    }
    if (!active.finished) this.finishActiveRun(active, { exitCode: 0, state: "stopped" });
    return { stopped: true, sessionId: active.sessionId, containers };
  }

  async removeOwnedContainers(runId) {
    const ids = await this.listOwnedContainers(runId, true);
    const removed = [];
    for (const id of ids) {
      try {
        await execFilePromise("docker", ["rm", "-f", id], 20_000);
        removed.push(id);
      } catch {
        // The harness may have removed the exact container concurrently.
      }
    }
    return removed;
  }

  async listOwnedContainers(runId, includeStopped) {
    if (!isSafeSegment(runId)) return [];
    let stdout;
    try {
      const args = ["ps"];
      if (includeStopped) args.push("-a");
      args.push("--format", "{{.ID}}\t{{.Names}}");
      ({ stdout } = await execFilePromise("docker", args));
    } catch {
      return [];
    }
    const prefix = `deepsec-explore-${runId}-`;
    return stdout
      .split(/\r?\n/)
      .map((line) => line.split("\t"))
      .filter(([id, name]) => /^[a-f0-9]{12,64}$/i.test(id ?? "") && name?.startsWith(prefix))
      .map(([id]) => id);
  }

  async listRecordings() {
    let entries;
    try {
      entries = await fsp.readdir(this.recordRoot, { withFileTypes: true });
    } catch {
      return [];
    }
    const recordings = [];
    for (const entry of entries) {
      if (!entry.isDirectory() || !isSafeSegment(entry.name)) continue;
      const eventLog = path.join(safeSessionPath(this.recordRoot, entry.name), "canvas-events.jsonl");
      try {
        const stat = await fsp.lstat(eventLog);
        if (stat.isFile() && !stat.isSymbolicLink()) {
          let metadata;
          try {
            metadata = JSON.parse(
              await fsp.readFile(
                path.join(safeSessionPath(this.recordRoot, entry.name), "recording.json"),
                "utf8",
              ),
            );
          } catch {
            metadata = undefined;
          }
          recordings.push({
            sessionId: entry.name,
            bytes: stat.size,
            modifiedAt: stat.mtime.toISOString(),
            mode: metadata?.mode,
            state: metadata?.state,
            projectId: metadata?.projectId,
            runId: metadata?.runId,
            eventCount: metadata?.eventCount,
          });
        }
      } catch {
        // Ignore incomplete recording directories.
      }
    }
    return recordings.sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt));
  }

  async startReplay(body) {
    if (this.active && ["starting", "running", "stopping"].includes(this.active.state)) {
      throw httpError(409, "Stop the active run before replaying.");
    }
    const recordings = await this.listRecordings();
    const sessionId = body?.sessionId ?? recordings[0]?.sessionId;
    if (!isSafeSegment(sessionId)) throw httpError(404, "No replayable recording was found.");
    if (!recordings.some((recording) => recording.sessionId === sessionId)) {
      throw httpError(404, "Recording was not found.");
    }
    const filePath = path.join(safeSessionPath(this.recordRoot, sessionId), "canvas-events.jsonl");
    const records = await readReplayEvents(filePath);
    this.replayState.sessionId = sessionId;
    this.history = [];
    this.replay.start(records, body?.speed);
    return { accepted: true, sessionId, ...this.replayState };
  }

  async writeRecordingMetadata(active) {
    const target = path.join(active.sessionDir, "recording.json");
    const temporary = path.join(active.sessionDir, `.recording-${process.pid}.tmp`);
    await fsp.writeFile(temporary, `${JSON.stringify(active.recording, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    await fsp.rename(temporary, target);
  }

  async serveStatic(pathname, headOnly, response) {
    let stat;
    try {
      stat = await fsp.stat(this.uiDir);
    } catch {
      stat = undefined;
    }
    if (!stat?.isDirectory()) {
      if (pathname !== "/") return sendJson(response, 404, { error: "UI build is not available." });
      const html = fallbackHtml();
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": Buffer.byteLength(html),
      });
      if (!headOnly) response.end(html);
      else response.end();
      return;
    }

    const relative = decodeURIComponent(pathname).replace(/^\/+/, "");
    let candidate = path.resolve(this.uiDir, relative || "index.html");
    if (candidate !== this.uiDir && !candidate.startsWith(`${this.uiDir}${path.sep}`)) {
      return sendJson(response, 404, { error: "Not found." });
    }
    try {
      const candidateStat = await fsp.lstat(candidate);
      if (!candidateStat.isFile() || candidateStat.isSymbolicLink()) throw new Error("not file");
    } catch {
      candidate = path.join(this.uiDir, "index.html");
    }
    const fileStat = await fsp.lstat(candidate);
    if (!fileStat.isFile() || fileStat.isSymbolicLink()) {
      return sendJson(response, 404, { error: "Not found." });
    }
    response.writeHead(200, {
      "Content-Type": contentType(candidate),
      "Content-Length": fileStat.size,
      "Cache-Control": candidate.endsWith("index.html")
        ? "no-cache"
        : "public, max-age=31536000, immutable",
    });
    if (headOnly) response.end();
    else fs.createReadStream(candidate).pipe(response);
  }
}

function normalizeRunOptions(input, mode) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw httpError(400, "options must be an object.");
  }
  const root = mode === "live" ? resolveTargetRoot(input.root) : undefined;
  return {
    root,
    projectId:
      input.projectId === undefined
        ? mode === "simulation"
          ? "deepsec-demo"
          : undefined
        : assertSafeOption(input.projectId, "projectId"),
    profile: safeChoice(input.profile, ["java11-gradle"], "java11-gradle"),
    modelProvider: safeChoice(
      input.modelProvider,
      ["codex-app-server", "openrouter"],
      "codex-app-server",
    ),
    model: safeModel(input.model ?? "gpt-5.6-sol"),
    rankModel: input.rankModel === undefined ? undefined : safeModel(input.rankModel),
    reasoningEffort: safeChoice(
      input.reasoningEffort,
      ["low", "medium", "high", "xhigh"],
      "high",
    ),
    limit: boundedInteger(input.limit, 1, 256, 18),
    allFiles: input.allFiles === true,
    concurrency: boundedInteger(input.concurrency, 1, 16, 2),
    maxTurns: boundedInteger(input.maxTurns, 1, 200, 40),
    maxTokens:
      input.maxTokens === undefined ? undefined : boundedInteger(input.maxTokens, 1, 1_000_000),
    maxCostUsd:
      input.maxCostUsd === undefined ? undefined : boundedNumber(input.maxCostUsd, 0.01, 100_000),
    minSeverity: safeChoice(
      input.minSeverity,
      ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      "MEDIUM",
    ),
    stubModel: input.stubModel === true,
    liveModelCheck: input.liveModelCheck === true,
    skipSetup: input.skipSetup !== false,
    skipDoctor: input.skipDoctor === true,
    verifyManifest: input.verifyManifest === true,
    includeAttempts: input.includeAttempts === true,
    failOnFindings: input.failOnFindings === true,
    simulationDelayMs: boundedInteger(input.simulationDelayMs, 5, 5_000, 35),
  };
}

function buildHarnessArgs(options, dataRoot) {
  const args = ["--root", options.root, "--profile", options.profile, "--runtime", "runsc"];
  if (options.projectId) args.push("--project-id", options.projectId);
  args.push(
    "--model-provider",
    options.modelProvider,
    "--model",
    options.model,
    "--reasoning-effort",
    options.reasoningEffort,
    "--concurrency",
    String(options.concurrency),
    "--max-turns",
    String(options.maxTurns),
    "--min-severity",
    options.minSeverity,
    "--data-root",
    dataRoot,
    "--no-open-report",
  );
  if (options.rankModel) args.push("--rank-model", options.rankModel);
  if (options.allFiles) args.push("--all-files");
  else args.push("--limit", String(options.limit));
  if (options.maxTokens !== undefined) args.push("--max-tokens", String(options.maxTokens));
  if (options.maxCostUsd !== undefined) args.push("--max-cost-usd", String(options.maxCostUsd));
  if (options.stubModel) args.push("--stub-model");
  if (options.liveModelCheck) args.push("--live-model-check");
  if (options.skipSetup) args.push("--skip-setup");
  if (options.skipDoctor) args.push("--skip-doctor");
  if (options.verifyManifest) args.push("--verify-manifest");
  if (options.includeAttempts) args.push("--include-attempts");
  if (options.failOnFindings) args.push("--fail-on-findings");
  return args;
}

function resolveTargetRoot(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw httpError(400, "A target root is required for a live run.");
  }
  let real;
  try {
    real = fs.realpathSync(value);
  } catch {
    throw httpError(400, "The target root does not exist.");
  }
  if (!fs.statSync(real).isDirectory()) throw httpError(400, "The target root is not a directory.");
  return real;
}

function boundedInteger(value, min, max, fallback) {
  if (value === undefined && fallback !== undefined) return fallback;
  if (!Number.isInteger(value) || value < min || value > max) {
    throw httpError(400, `Expected an integer from ${min} to ${max}.`);
  }
  return value;
}

function boundedNumber(value, min, max) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max) {
    throw httpError(400, `Expected a number from ${min} to ${max}.`);
  }
  return value;
}

function safeChoice(value, choices, fallback) {
  if (value === undefined) return fallback;
  if (!choices.includes(value)) throw httpError(400, `Expected one of: ${choices.join(", ")}.`);
  return value;
}

function safeModel(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$/.test(value)) {
    throw httpError(400, "Invalid model name.");
  }
  return value;
}

function assertSafeOption(value, label) {
  if (!isSafeSegment(value)) throw httpError(400, `Invalid ${label}.`);
  return value;
}

function createSessionId(mode) {
  const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  return `${mode}-${timestamp}-${crypto.randomBytes(5).toString("hex")}`;
}

function safeSessionPath(recordRoot, sessionId) {
  if (!isSafeSegment(sessionId)) throw httpError(400, "Invalid session identifier.");
  const base = path.resolve(recordRoot);
  const candidate = path.resolve(base, sessionId);
  if (!candidate.startsWith(`${base}${path.sep}`)) throw httpError(400, "Unsafe session path.");
  return candidate;
}

function signalExactProcess(pid, signal) {
  if (!Number.isInteger(pid) || pid <= 1) return;
  try {
    if (process.platform === "win32") process.kill(pid, signal);
    else process.kill(-pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

function exactProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "EPERM") return true;
    if (error?.code === "ESRCH") return false;
    throw error;
  }
}

function waitForChild(child, timeoutMs) {
  if (child.exitCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(done, timeoutMs);
    function done() {
      clearTimeout(timer);
      child.off("close", done);
      resolve();
    }
    child.once("close", done);
  });
}

function execFilePromise(command, args, timeout = 10_000) {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout, maxBuffer: 2 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) reject(error);
      else resolve({ stdout, stderr });
    });
  });
}

function normalizePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new Error("Port must be an integer from 0 to 65535.");
  }
  return port;
}

function safeTokenEqual(expected, supplied) {
  if (typeof supplied !== "string") return false;
  const left = Buffer.from(expected);
  const right = Buffer.from(supplied);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(httpError(413, "Request body is too large."));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      try {
        resolve(chunks.length === 0 ? {} : JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(httpError(400, "Request body is not valid JSON."));
      }
    });
    request.on("error", reject);
  });
}

function isJsonRequest(request) {
  return /^application\/json(?:;|$)/i.test(request.headers["content-type"] ?? "");
}

function sendJson(response, status, payload) {
  if (response.writableEnded) return;
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  });
  response.end(body);
}

function writeSse(response, record) {
  if (response.destroyed || response.writableEnded) return;
  response.write(
    `id: ${record.seq}\nevent: canvas-event\ndata: ${JSON.stringify(record)}\n\n`,
  );
}

function setSecurityHeaders(response) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  );
}

function contentType(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  return (
    {
      ".html": "text/html; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
      ".mjs": "text/javascript; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".json": "application/json; charset=utf-8",
      ".svg": "image/svg+xml",
      ".png": "image/png",
      ".webp": "image/webp",
      ".woff2": "font/woff2",
      ".map": "application/json; charset=utf-8",
    }[extension] ?? "application/octet-stream"
  );
}

function fallbackHtml() {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>DeepSec Canvas bridge</title>
<style>body{margin:0;background:#10131a;color:#e9edf5;font:16px/1.5 system-ui,sans-serif}main{max-width:720px;margin:12vh auto;padding:32px;border:1px solid #30394a;border-radius:18px;background:#181d27}code{color:#80d7ff}</style>
</head>
<body><main><h1>DeepSec Canvas bridge is ready</h1>
<p>The local API is running, but the offline UI has not been built yet.</p>
<p>Build the app, then restart this bridge. Status is available at <code>/api/status</code>.</p>
</main></body></html>`;
}

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const bridge = await createCanvasBridge(args);
  process.stdout.write(
    `DEEPSEC_CANVAS_READY ${JSON.stringify({
      url: bridge.url,
      origin: bridge.origin,
      token: bridge.token,
      recordRoot: bridge.recordRoot,
    })}\n`,
  );
  if (args.simulate) {
    await bridge.startRun({
      mode: "simulation",
      options: {
        limit: args.limit ?? args.simulationLimit,
        concurrency: args.concurrency,
        maxTurns: args.maxTurns,
        simulationDelayMs: args.simulationDelayMs,
      },
    });
  } else if (args.live) {
    await bridge.startRun({
      mode: "live",
      options: {
        root: args.targetRoot,
        projectId: args.projectId,
        modelProvider: args.modelProvider,
        model: args.model,
        reasoningEffort: args.reasoningEffort,
        limit: args.limit,
        concurrency: args.concurrency,
        maxTurns: args.maxTurns,
        skipSetup: args.skipSetup,
        skipDoctor: args.skipDoctor,
        verifyManifest: args.verifyManifest,
        includeAttempts: args.includeAttempts,
      },
    });
  } else if (args.replay) {
    await bridge.startReplay({
      sessionId: args.replaySession,
      speed: args.replaySpeed,
    });
  }
  let closing = false;
  const shutdown = async () => {
    if (closing) return;
    closing = true;
    await bridge.close();
  };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--port") options.port = argv[++index];
    else if (argument === "--record-root") options.recordRoot = argv[++index];
    else if (argument === "--ui-dir") options.uiDir = argv[++index];
    else if (argument === "--simulate") options.simulate = true;
    else if (argument === "--live") options.live = true;
    else if (argument === "--replay") options.replay = true;
    else if (argument === "--replay-session") options.replaySession = argv[++index];
    else if (argument === "--replay-speed") options.replaySpeed = Number(argv[++index]);
    else if (argument === "--target-root" || argument === "--root") {
      options.targetRoot = argv[++index];
    } else if (argument === "--project-id") options.projectId = argv[++index];
    else if (argument === "--model-provider") options.modelProvider = argv[++index];
    else if (argument === "--model") options.model = argv[++index];
    else if (argument === "--reasoning-effort") options.reasoningEffort = argv[++index];
    else if (argument === "--limit") options.limit = Number(argv[++index]);
    else if (argument === "--concurrency") options.concurrency = Number(argv[++index]);
    else if (argument === "--max-turns") options.maxTurns = Number(argv[++index]);
    else if (argument === "--with-setup") options.skipSetup = false;
    else if (argument === "--skip-setup") options.skipSetup = true;
    else if (argument === "--skip-doctor") options.skipDoctor = true;
    else if (argument === "--verify-manifest") options.verifyManifest = true;
    else if (argument === "--include-attempts") options.includeAttempts = true;
    else if (argument === "--simulation-limit") options.simulationLimit = Number(argv[++index]);
    else if (argument === "--simulation-delay-ms") {
      options.simulationDelayMs = Number(argv[++index]);
    } else if (argument === "--help" || argument === "-h") {
      process.stdout.write(`Usage: node server/index.mjs [options]

Options:
  --port <n>                 Loopback port; 0 chooses an available port (default).
  --record-root <path>       Local recording directory.
  --ui-dir <path>            Offline UI build directory (default: ../dist).
  --simulate                 Start a deterministic demo run after launch.
  --live                     Start the canonical DeepSec harness after launch.
  --replay                   Replay the latest local recording after launch.
  --replay-session <id>      Replay a specific canvas recording.
  --replay-speed <n>         Replay speed from 0.25 to 16 (default: 1).
  --target-root <path>       Explicit live target repository.
  --project-id <id>          Explicit DeepSec project ID.
  --model-provider <name>    Live provider (default: codex-app-server).
  --model <name>             Live model (default: gpt-5.6-sol).
  --reasoning-effort <name>  Live reasoning effort (default: high).
  --limit <n>                Selected files (default: 18).
  --concurrency <n>          Concurrent attempts (default: 2).
  --max-turns <n>            Turn cap per attempt (default: 40).
  --skip-setup               Reuse the existing gVisor image (default).
  --with-setup               Rebuild/setup before the live run.
  --skip-doctor              Skip preflight checks.
  --verify-manifest          Verify the evidence manifest.
  --include-attempts         Include raw attempts in the evidence bundle.
  --simulation-limit <n>     Number of simulated attempts (default: 18).
  --simulation-delay-ms <n>  Delay between simulated events (default: 35).
`);
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  const modes = [options.simulate, options.live, options.replay].filter(Boolean).length;
  if (modes > 1) throw new Error("Choose only one of --simulate, --live, or --replay.");
  if (options.live && !options.targetRoot) {
    throw new Error("--live requires --target-root.");
  }
  return options;
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`DeepSec Canvas bridge failed: ${sanitizeError(error)}\n`);
    process.exitCode = 1;
  });
}
