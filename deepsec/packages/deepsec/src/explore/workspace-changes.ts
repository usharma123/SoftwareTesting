import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { redactSensitiveText } from "./command-policy.js";
import { shouldCopyProjectPath } from "./docker.js";
import type { WorkspaceChanges, WorkspaceFileChange } from "./types.js";

const MAX_CHANGE_COUNT = 200;
const MAX_PREVIEW_BYTES = 64_000;
const MAX_PREVIEW_CHARS = 20_000;

export function collectWorkspaceChanges(
  originalRoot: string,
  targetRoot: string,
): WorkspaceChanges {
  const before = collectFiles(originalRoot);
  const after = collectFiles(targetRoot);
  const allPaths = [...new Set([...before.keys(), ...after.keys()])].sort();
  const changes: WorkspaceFileChange[] = [];

  for (const rel of allPaths) {
    const original = before.get(rel);
    const current = after.get(rel);
    if (original?.sha256 === current?.sha256) continue;
    if (!current) {
      changes.push({
        path: rel,
        status: "deleted",
        beforeSha256: original?.sha256,
      });
      continue;
    }

    const change: WorkspaceFileChange = {
      path: rel,
      status: original ? "modified" : "added",
      beforeSha256: original?.sha256,
      afterSha256: current.sha256,
      afterBytes: current.bytes,
    };
    addPreview(change, path.join(targetRoot, rel), current.bytes);
    changes.push(change);
  }

  const captured = changes.slice(0, MAX_CHANGE_COUNT);
  return {
    generatedAt: new Date().toISOString(),
    containerTarget: "/workspace/target",
    totalChanges: changes.length,
    capturedChanges: captured.length,
    omittedChanges: Math.max(0, changes.length - captured.length),
    changes: captured,
  };
}

function collectFiles(root: string): Map<string, { sha256: string; bytes: number }> {
  const files = new Map<string, { sha256: string; bytes: number }>();
  walk(root, "");
  return files;

  function walk(dir: string, relDir: string): void {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (!shouldCopyProjectPath(rel)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full, rel);
        continue;
      }
      if (!entry.isFile()) continue;
      const bytes = fs.readFileSync(full);
      files.set(rel, {
        bytes: bytes.length,
        sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
      });
    }
  }
}

function addPreview(change: WorkspaceFileChange, file: string, bytes: number): void {
  if (bytes > MAX_PREVIEW_BYTES) {
    change.omittedReason = `file is larger than ${MAX_PREVIEW_BYTES} bytes`;
    return;
  }
  const raw = fs.readFileSync(file);
  if (raw.includes(0)) {
    change.omittedReason = "file appears to be binary";
    return;
  }
  const redacted = redactSensitiveText(raw.toString("utf-8"));
  change.afterPreview = redacted.text.slice(0, MAX_PREVIEW_CHARS);
  if (redacted.text.length > MAX_PREVIEW_CHARS) {
    change.omittedReason = `preview truncated to ${MAX_PREVIEW_CHARS} characters`;
  }
  if (redacted.redacted) change.redacted = true;
}
