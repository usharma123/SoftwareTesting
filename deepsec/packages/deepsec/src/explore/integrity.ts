import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const EXPLORE_INTEGRITY_MANIFEST = "integrity-manifest.json";

export interface ExploreIntegrityManifest {
  version: 1;
  algorithm: "sha256";
  generatedAt: string;
  files: Array<{
    path: string;
    bytes: number;
    sha256: string;
  }>;
}

export interface ExploreIntegrityStatus {
  present: boolean;
  files: number;
  problems: string[];
}

export function writeExploreIntegrityManifest(exploreDir: string): ExploreIntegrityManifest {
  const manifest: ExploreIntegrityManifest = {
    version: 1,
    algorithm: "sha256",
    generatedAt: new Date().toISOString(),
    files: collectArtifactHashes(exploreDir),
  };
  fs.writeFileSync(
    path.join(exploreDir, EXPLORE_INTEGRITY_MANIFEST),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  return manifest;
}

export function verifyExploreIntegrityManifest(exploreDir: string): ExploreIntegrityStatus {
  const manifestPath = path.join(exploreDir, EXPLORE_INTEGRITY_MANIFEST);
  if (!fs.existsSync(manifestPath)) {
    return { present: false, files: 0, problems: [] };
  }

  let manifest: ExploreIntegrityManifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8")) as ExploreIntegrityManifest;
  } catch {
    return { present: true, files: 0, problems: ["integrity-manifest.json is invalid"] };
  }

  const problems: string[] = [];
  if (manifest.version !== 1) problems.push(`integrity manifest version is ${manifest.version}`);
  if (manifest.algorithm !== "sha256") {
    problems.push(`integrity manifest algorithm is ${String(manifest.algorithm)}`);
  }
  if (!Array.isArray(manifest.files)) {
    return { present: true, files: 0, problems: ["integrity manifest files is not an array"] };
  }

  const expected = new Map<string, { bytes: number; sha256: string }>();
  for (const file of manifest.files) {
    if (!isSafeRelativeArtifactPath(file.path)) {
      problems.push(`integrity manifest contains unsafe path ${JSON.stringify(file.path)}`);
      continue;
    }
    expected.set(file.path, { bytes: file.bytes, sha256: file.sha256 });
  }

  const actual = new Map(
    collectArtifactHashes(exploreDir).map((file) => [
      file.path,
      { bytes: file.bytes, sha256: file.sha256 },
    ]),
  );
  for (const [rel, expectedHash] of expected) {
    const actualHash = actual.get(rel);
    if (!actualHash) {
      problems.push(`integrity missing artifact ${rel}`);
      continue;
    }
    if (actualHash.bytes !== expectedHash.bytes || actualHash.sha256 !== expectedHash.sha256) {
      problems.push(`integrity mismatch for ${rel}`);
    }
  }
  for (const rel of actual.keys()) {
    if (!expected.has(rel)) problems.push(`integrity unexpected artifact ${rel}`);
  }

  return { present: true, files: expected.size, problems };
}

function collectArtifactHashes(exploreDir: string): ExploreIntegrityManifest["files"] {
  return collectArtifactFiles(exploreDir)
    .map((file) => {
      const bytes = fs.readFileSync(path.join(exploreDir, file));
      return {
        path: file,
        bytes: bytes.length,
        sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
      };
    })
    .sort((a, b) => a.path.localeCompare(b.path));
}

function collectArtifactFiles(exploreDir: string): string[] {
  const files: string[] = [];
  walk(exploreDir, "");
  return files.sort();

  function walk(dir: string, relDir: string): void {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (rel === EXPLORE_INTEGRITY_MANIFEST) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full, rel);
      } else if (entry.isFile()) {
        files.push(rel);
      }
    }
  }
}

function isSafeRelativeArtifactPath(value: string): boolean {
  if (typeof value !== "string" || value.length === 0) return false;
  if (path.isAbsolute(value)) return false;
  return !value.split("/").some((segment) => segment === ".." || segment === "");
}
