import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  assertSafeContainerCommand,
  sanitizeExploreEnv,
  sanitizeTimeoutMs,
  truncateOutput,
} from "./command-policy.js";
import { execFileCapture } from "./process.js";
import {
  type CommandExecution,
  type ContainerMetadata,
  type ContainerRunner,
  EXPLORE_IMAGE,
  EXPLORE_PROFILE,
  EXPLORE_RUNTIME,
  type ExploreProfile,
} from "./types.js";

export interface DockerInspectSummary {
  runtime: string;
  networkMode: string;
  readOnlyRootfs: boolean;
  noNewPrivileges: boolean;
  capDropAll: boolean;
  privileged: boolean;
  pidsLimit: number;
  memoryBytes: number;
  nanoCpus: number;
  mountDestinations: string[];
}

export async function assertRunscRegistered(runtime = EXPLORE_RUNTIME): Promise<void> {
  const result = await execFileCapture("docker", ["info", "--format", "{{json .Runtimes}}"], {
    timeoutMs: 30_000,
  });
  if (result.exitCode !== 0) {
    throw new Error(
      `Failed to inspect Docker runtimes (${formatExecFailure(result)}): ${result.stderr || result.stdout || "no output"}`,
    );
  }
  let runtimes: Record<string, unknown>;
  try {
    runtimes = JSON.parse(result.stdout.trim());
  } catch {
    throw new Error(`Docker returned malformed runtime data: ${result.stdout}`);
  }
  if (!Object.hasOwn(runtimes, runtime)) {
    throw new Error(
      `Docker runtime ${JSON.stringify(runtime)} is not registered. Run \`deepsec explore setup --profile ${EXPLORE_PROFILE}\` after registering runsc with Docker Desktop.`,
    );
  }
}

function formatExecFailure(result: { exitCode: number; durationMs: number; timedOut: boolean }) {
  if (result.timedOut) return `timed out after ${result.durationMs}ms`;
  return `exit ${result.exitCode} after ${result.durationMs}ms`;
}

export async function assertExploreImageExists(image = EXPLORE_IMAGE): Promise<void> {
  const result = await execFileCapture("docker", ["image", "inspect", image], {
    timeoutMs: 15_000,
  });
  if (result.exitCode !== 0) {
    throw new Error(
      `Explore image ${image} is missing. Run \`deepsec explore setup --profile ${EXPLORE_PROFILE}\`.`,
    );
  }
}

export function assertGradleCacheAvailable(): void {
  const { modules, wrapperDists } = gradleCacheSourcePaths();
  if (!fs.existsSync(modules) || !fs.existsSync(wrapperDists)) {
    throw new Error(
      "Gradle offline cache is missing modules-2 or wrapper/dists. Run a host Gradle build once, then re-run explore setup.",
    );
  }
}

export function validateContainerInspectRuntime(
  inspectJson: unknown,
  expectedRuntime = EXPLORE_RUNTIME,
): DockerInspectSummary {
  const item = Array.isArray(inspectJson) ? inspectJson[0] : inspectJson;
  if (!item || typeof item !== "object") {
    throw new Error("Docker inspect returned no container metadata.");
  }
  const hostConfig = (item as Record<string, unknown>).HostConfig;
  if (!hostConfig || typeof hostConfig !== "object") {
    throw new Error("Docker inspect did not include HostConfig.");
  }
  const hc = hostConfig as Record<string, unknown>;
  const runtime = typeof hc.Runtime === "string" ? hc.Runtime : "";
  const networkMode = typeof hc.NetworkMode === "string" ? hc.NetworkMode : "";
  const readOnlyRootfs = hc.ReadonlyRootfs === true;
  const privileged = hc.Privileged === true;
  const securityOpt = stringArray(hc.SecurityOpt);
  const noNewPrivileges = securityOpt.some(
    (opt) => opt === "no-new-privileges" || opt === "no-new-privileges:true",
  );
  const capDrop = stringArray(hc.CapDrop).map((cap) => cap.toUpperCase());
  const capDropAll = capDrop.includes("ALL");
  const pidsLimit = typeof hc.PidsLimit === "number" ? hc.PidsLimit : 0;
  const memoryBytes = typeof hc.Memory === "number" ? hc.Memory : 0;
  const nanoCpus = typeof hc.NanoCpus === "number" ? hc.NanoCpus : 0;
  const mountDestinations = inspectMountDestinations(item);
  if (runtime !== expectedRuntime) {
    throw new Error(
      `Explore container runtime must be ${expectedRuntime}; Docker reported ${runtime || "(empty)"}.`,
    );
  }
  if (networkMode !== "none") {
    throw new Error(
      `Explore container network must be none; Docker reported ${networkMode || "(empty)"}.`,
    );
  }
  if (!readOnlyRootfs) {
    throw new Error("Explore container root filesystem must be read-only.");
  }
  if (privileged) {
    throw new Error("Explore container must not run privileged.");
  }
  if (!noNewPrivileges) {
    throw new Error("Explore container must enable no-new-privileges.");
  }
  if (!capDropAll) {
    throw new Error("Explore container must drop all Linux capabilities.");
  }
  if (pidsLimit <= 0 || pidsLimit > 512) {
    throw new Error(`Explore container pids limit must be 1-512; Docker reported ${pidsLimit}.`);
  }
  if (memoryBytes <= 0) {
    throw new Error("Explore container must have a memory limit.");
  }
  if (nanoCpus <= 0) {
    throw new Error("Explore container must have a CPU limit.");
  }
  if (
    mountDestinations.some((dst) => dst === "/var/run/docker.sock" || dst === "/run/docker.sock")
  ) {
    throw new Error("Explore container must not mount a Docker socket.");
  }
  for (const required of [
    "/workspace/target",
    "/workspace/out",
    "/workspace/home",
    "/workspace/gradle-cache",
  ]) {
    if (!mountDestinations.includes(required)) {
      throw new Error(`Explore container missing required mount ${required}.`);
    }
  }
  return {
    runtime,
    networkMode,
    readOnlyRootfs,
    noNewPrivileges,
    capDropAll,
    privileged,
    pidsLimit,
    memoryBytes,
    nanoCpus,
    mountDestinations,
  };
}

export async function createGvisorContainer(args: {
  root: string;
  runId: string;
  focusFile: string;
  runtime?: string;
  profile?: ExploreProfile;
  image?: string;
}): Promise<GvisorContainer> {
  const runtime = args.runtime ?? EXPLORE_RUNTIME;
  const image = args.image ?? EXPLORE_IMAGE;
  await assertRunscRegistered(runtime);
  await assertExploreImageExists(image);

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), `deepsec-explore-${args.runId}-`));
  const targetDir = path.join(tempRoot, "target");
  const outDir = path.join(tempRoot, "out");
  const homeDir = path.join(tempRoot, "home");
  const gradleCacheDir = path.join(tempRoot, "gradle-cache");
  fs.mkdirSync(targetDir, { recursive: true });
  fs.mkdirSync(outDir, { recursive: true });
  fs.mkdirSync(homeDir, { recursive: true });
  prepareGradleCache(gradleCacheDir);
  const copySummary = copyProjectTree(path.resolve(args.root), targetDir);

  const name = `deepsec-explore-${args.runId}-${crypto.randomBytes(4).toString("hex")}`;
  const env = sanitizeExploreEnv();
  const dockerArgs = [
    "run",
    "-d",
    "--name",
    name,
    "--runtime",
    runtime,
    "--network",
    "none",
    "--read-only",
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--pids-limit",
    "512",
    "--memory",
    "4g",
    "--cpus",
    "2",
    "--tmpfs",
    "/tmp:rw,nosuid,nodev",
    "--mount",
    bindMount(targetDir, "/workspace/target"),
    "--mount",
    bindMount(outDir, "/workspace/out"),
    "--mount",
    bindMount(homeDir, "/workspace/home"),
    "--mount",
    bindMount(gradleCacheDir, "/workspace/gradle-cache"),
    "--workdir",
    "/workspace/target",
  ];
  for (const [key, value] of Object.entries(env)) {
    dockerArgs.push("--env", `${key}=${value}`);
  }
  dockerArgs.push(image, "sh", "-lc", "sleep infinity");

  const run = await execFileCapture("docker", dockerArgs, { timeoutMs: 45_000 });
  if (run.exitCode !== 0) {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    throw new Error(`Failed to start gVisor explore container: ${run.stderr || run.stdout}`);
  }
  const containerId = run.stdout.trim();
  const container = new GvisorContainer(containerId, image, tempRoot);
  try {
    const inspect = await container.inspect();
    const summary = validateContainerInspectRuntime(inspect, runtime);
    container.metadata = { containerId, image, ...summary, ...copySummary };
    await assertGradleOfflineUsable(container);
    return container;
  } catch (err) {
    await container.cleanup();
    throw err;
  }
}

export class GvisorContainer implements ContainerRunner {
  metadata: ContainerMetadata;

  constructor(
    private readonly containerId: string,
    image: string,
    private readonly tempRoot: string,
  ) {
    this.metadata = {
      containerId,
      runtime: "",
      networkMode: "",
      image,
    };
  }

  async inspect(): Promise<unknown> {
    const result = await execFileCapture("docker", ["inspect", this.containerId], {
      timeoutMs: 15_000,
      outputLimit: 256_000,
    });
    if (result.exitCode !== 0) {
      throw new Error(`Failed to inspect explore container: ${result.stderr || result.stdout}`);
    }
    return JSON.parse(result.stdout);
  }

  async exec(command: string, timeoutMs?: number, outputLimit = 64_000): Promise<CommandExecution> {
    assertSafeContainerCommand(command);
    const timeout = sanitizeTimeoutMs(timeoutMs);
    const cappedOutputLimit = Math.max(16_000, Math.min(2_000_000, Math.trunc(outputLimit)));
    const result = await execFileCapture(
      "docker",
      ["exec", "--workdir", "/workspace/target", this.containerId, "sh", "-lc", command],
      { timeoutMs: timeout, outputLimit: cappedOutputLimit },
    );
    const capped = truncateOutput(result.stdout, result.stderr, cappedOutputLimit);
    return {
      command,
      exitCode: result.exitCode,
      durationMs: result.durationMs,
      stdout: capped.stdout,
      stderr: capped.stderr,
      timedOut: result.timedOut,
      truncated: capped.truncated,
    };
  }

  targetRoot(): string {
    return path.join(this.tempRoot, "target");
  }

  async cleanup(): Promise<void> {
    await execFileCapture("docker", ["rm", "-f", this.containerId], { timeoutMs: 20_000 }).catch(
      () => undefined,
    );
    fs.rmSync(this.tempRoot, { recursive: true, force: true });
  }
}

function bindMount(src: string, dst: string): string {
  return `type=bind,src=${src},dst=${dst}`;
}

function copyProjectTree(
  src: string,
  dst: string,
): { copyExcludedCount: number; copyExcludedPaths: string[] } {
  const excluded = new Set<string>();
  fs.cpSync(src, dst, {
    recursive: true,
    dereference: false,
    filter: (source) => {
      const rel = path.relative(src, source);
      const allowed = shouldCopyProjectPath(rel);
      if (!allowed) excluded.add(rel.replace(/\\/g, "/"));
      return allowed;
    },
  });
  const copyExcludedPaths = [...excluded].sort().slice(0, 200);
  return { copyExcludedCount: excluded.size, copyExcludedPaths };
}

export function shouldCopyProjectPath(rel: string): boolean {
  if (!rel) return true;
  const normalized = rel.replace(/\\/g, "/");
  const parts = normalized.split("/");
  const base = parts.at(-1) ?? "";
  if (
    parts.some((part) =>
      [
        ".git",
        ".gradle",
        ".hg",
        ".svn",
        ".ssh",
        ".aws",
        ".gnupg",
        "build",
        "dist",
        "node_modules",
        "target",
      ].includes(part),
    )
  ) {
    return false;
  }
  if (/^\.env($|\.)/i.test(base)) return false;
  if (/^(id_rsa|id_dsa|id_ecdsa|id_ed25519|known_hosts|authorized_keys)$/i.test(base)) {
    return false;
  }
  if (/\.(pem|key|p12|pfx|jks|keystore|kdb|gpg|asc)$/i.test(base)) return false;
  if (/(^|[._-])(secret|secrets|credential|credentials|token|tokens)([._-]|$)/i.test(base)) {
    return false;
  }
  if (/^(aws_credentials|credentials)$/i.test(base)) return false;
  return true;
}

function prepareGradleCache(dst: string): void {
  fs.mkdirSync(dst, { recursive: true });
  const { modules, wrapperDists } = gradleCacheSourcePaths();
  assertGradleCacheAvailable();
  copyIfExists(modules, path.join(dst, "caches", "modules-2"));
  copyIfExists(wrapperDists, path.join(dst, "wrapper", "dists"));
}

function gradleCacheSourcePaths(): { modules: string; wrapperDists: string } {
  const sourceRoot = path.join(os.homedir(), ".gradle");
  return {
    modules: path.join(sourceRoot, "caches", "modules-2"),
    wrapperDists: path.join(sourceRoot, "wrapper", "dists"),
  };
}

function copyIfExists(src: string, dst: string): void {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.cpSync(src, dst, {
    recursive: true,
    dereference: false,
    filter: (source) => !source.endsWith(".lock"),
  });
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function inspectMountDestinations(item: object): string[] {
  const mounts = (item as Record<string, unknown>).Mounts;
  if (!Array.isArray(mounts)) return [];
  return mounts
    .map((mount) =>
      mount && typeof mount === "object"
        ? (mount as Record<string, unknown>).Destination
        : undefined,
    )
    .filter((dst): dst is string => typeof dst === "string")
    .sort();
}

async function assertGradleOfflineUsable(container: GvisorContainer): Promise<void> {
  const hasGradlew = await container.exec(
    "test -x ./gradlew && ./gradlew --offline -q help",
    90_000,
  );
  if (hasGradlew.exitCode === 0) return;
  const output = `${hasGradlew.stdout}\n${hasGradlew.stderr}`;
  if (/No cached version|Could not resolve|Could not download|offline mode/i.test(output)) {
    throw new Error(
      "Gradle offline dependencies are missing inside the gVisor container. Run `./gradlew --refresh-dependencies build` on the host or prefetch project dependencies, then rerun `deepsec explore setup --profile java11-gradle`.",
    );
  }
  throw new Error(`Gradle offline preflight failed:\n${output.slice(0, 3000)}`);
}
