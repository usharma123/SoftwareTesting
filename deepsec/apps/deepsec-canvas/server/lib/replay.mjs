import fs from "node:fs";
import readline from "node:readline";

export async function readReplayEvents(filePath, maxEvents = 250_000) {
  const records = [];
  const input = fs.createReadStream(filePath, { encoding: "utf8" });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    if (!parsed?.event || typeof parsed.event !== "object") continue;
    records.push(parsed);
    if (records.length > maxEvents) {
      input.destroy();
      throw new Error(`Replay contains more than ${maxEvents} events.`);
    }
  }
  return records;
}

export class ReplayController {
  constructor({ emit, onState, onReset }) {
    this.emit = emit;
    this.onState = onState;
    this.onReset = onReset;
    this.records = [];
    this.index = 0;
    this.speed = 1;
    this.state = "idle";
    this.timer = undefined;
  }

  snapshot() {
    return {
      state: this.state,
      index: this.index,
      total: this.records.length,
      position: this.records.length === 0 ? 0 : this.index / this.records.length,
      speed: this.speed,
    };
  }

  start(records, speed = 1) {
    this.stop();
    this.records = records;
    this.index = 0;
    this.speed = clampSpeed(speed);
    this.state = "running";
    this.onReset?.({ targetIndex: 0 });
    this.onState(this.snapshot());
    this.schedule(0);
  }

  pause() {
    if (this.state !== "running") return;
    clearTimeout(this.timer);
    this.timer = undefined;
    this.state = "paused";
    this.onState(this.snapshot());
  }

  resume() {
    if (this.state !== "paused") return;
    this.state = "running";
    this.onState(this.snapshot());
    this.schedule(0);
  }

  seek({ index, position }) {
    const nextIndex = Number.isInteger(index)
      ? index
      : typeof position === "number" && Number.isFinite(position)
        ? Math.round(this.records.length * Math.max(0, Math.min(1, position)))
        : undefined;
    if (nextIndex === undefined) throw new Error("Replay seek requires an index or position.");
    const targetIndex = Math.max(0, Math.min(this.records.length, nextIndex));
    const priorState = this.state;
    clearTimeout(this.timer);
    this.timer = undefined;
    this.onReset?.({ targetIndex });
    this.index = 0;
    while (this.index < targetIndex) {
      const record = this.records[this.index];
      this.index += 1;
      this.emit(record.event);
    }
    this.state = priorState;
    this.onState(this.snapshot());
    if (this.state === "running") this.schedule(0);
  }

  stop() {
    clearTimeout(this.timer);
    this.timer = undefined;
    this.records = [];
    this.index = 0;
    this.state = "idle";
    this.onState(this.snapshot());
  }

  schedule(delay) {
    clearTimeout(this.timer);
    if (this.state !== "running") return;
    if (this.index >= this.records.length) {
      this.state = "complete";
      this.onState(this.snapshot());
      return;
    }
    this.timer = setTimeout(() => {
      if (this.state !== "running") return;
      const record = this.records[this.index];
      this.index += 1;
      this.emit(record.event);
      this.onState(this.snapshot());
      const previousAt = Date.parse(record.receivedAt ?? record.event?.at ?? "");
      const next = this.records[this.index];
      const nextAt = Date.parse(next?.receivedAt ?? next?.event?.at ?? "");
      const elapsed =
        Number.isFinite(previousAt) && Number.isFinite(nextAt) ? Math.max(0, nextAt - previousAt) : 0;
      this.schedule(Math.min(2_000, elapsed / this.speed));
    }, Math.max(0, delay));
    this.timer.unref?.();
  }
}

function clampSpeed(speed) {
  const numeric = Number(speed);
  if (!Number.isFinite(numeric)) return 1;
  return Math.max(0.25, Math.min(16, numeric));
}
