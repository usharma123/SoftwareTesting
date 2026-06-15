import { spawn } from "node:child_process";

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

export async function execFileCapture(
  file: string,
  args: string[],
  opts: {
    cwd?: string;
    timeoutMs?: number;
    outputLimit?: number;
    env?: NodeJS.ProcessEnv;
  } = {},
): Promise<ExecResult> {
  const started = Date.now();
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const outputLimit = opts.outputLimit ?? 64_000;
  return await new Promise((resolve, reject) => {
    const child = spawn(file, args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 1500).unref();
    }, timeoutMs);

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout = appendCapped(stdout, chunk.toString("utf-8"), outputLimit);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr = appendCapped(stderr, chunk.toString("utf-8"), outputLimit);
    });
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        exitCode: code ?? (timedOut ? 124 : 1),
        stdout,
        stderr,
        durationMs: Date.now() - started,
        timedOut,
      });
    });
  });
}

function appendCapped(current: string, next: string, limit: number): string {
  const combined = current + next;
  if (combined.length <= limit) return combined;
  return combined.slice(0, limit);
}
