import fs from "node:fs";
import path from "node:path";
import { redactSensitiveText } from "./command-policy.js";
import { asRecord, asString, extractJsonValue } from "./json.js";
import type { ContainerRunner, RankedFile, SourceFileSummary } from "./types.js";

const IGNORE_DIRS = new Set([
  ".git",
  ".gradle",
  ".idea",
  ".mvn",
  "build",
  "dist",
  "node_modules",
  "out",
  "target",
]);

const PRODUCTION_EXTENSIONS = new Set([
  ".java",
  ".kt",
  ".kts",
  ".groovy",
  ".scala",
  ".xml",
  ".json",
  ".properties",
  ".yml",
  ".yaml",
]);

const HIGH_VALUE_PATTERNS = [
  /parse|parser|reader|decoder|encoder|serializer|deserializer/i,
  /auth|token|credential|secret|signature|crypto|certificate|keystore/i,
  /http|request|response|socket|network|upload|download/i,
  /xml|json|swift|rje|fin|message|mt\d+/i,
  /validation|validate|escape|sanitize|filter/i,
];

const CONTAINER_INVENTORY_OUTPUT_LIMIT = 2_000_000;

export function collectProductionFileSummaries(root: string, limit = 80): SourceFileSummary[] {
  const absoluteRoot = path.resolve(root);
  const files: SourceFileSummary[] = [];
  walk(absoluteRoot, "");
  return files
    .sort((a, b) => b.heuristicScore - a.heuristicScore || a.filePath.localeCompare(b.filePath))
    .slice(0, limit);

  function walk(dir: string, relDir: string): void {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name)) continue;
        walk(path.join(dir, entry.name), relDir ? `${relDir}/${entry.name}` : entry.name);
        continue;
      }
      if (!entry.isFile()) continue;
      const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (!isProductionRelevant(rel)) continue;
      const full = path.join(absoluteRoot, rel);
      let bytes = 0;
      let preview = "";
      try {
        const stat = fs.statSync(full);
        bytes = stat.size;
        if (stat.size > 1_000_000) continue;
        preview = fs.readFileSync(full, "utf-8").slice(0, 600);
      } catch {
        continue;
      }
      files.push({
        filePath: rel,
        bytes,
        heuristicScore: heuristicScore(rel, preview),
        preview: compactPreview(redactSensitiveText(preview).text),
      });
    }
  }
}

export async function collectProductionFileSummariesFromRunner(
  runner: ContainerRunner,
  limit = 80,
): Promise<SourceFileSummary[]> {
  const result = await runner.exec(
    containerInventoryCommand(),
    60_000,
    CONTAINER_INVENTORY_OUTPUT_LIMIT,
  );
  if (result.exitCode !== 0) {
    throw new Error(`Container file inventory failed:\n${result.stdout}\n${result.stderr}`);
  }
  if (result.truncated) {
    throw new Error("Container file inventory output was truncated; reduce the project file set.");
  }
  return parseContainerFileSummaries(result.stdout, limit);
}

export function parseContainerFileSummaries(stdout: string, limit = 80): SourceFileSummary[] {
  const files: SourceFileSummary[] = [];
  for (const chunk of stdout.split("\x1e").slice(1)) {
    const end = chunk.indexOf("\x1f");
    if (end === -1) continue;
    const body = chunk.slice(0, end);
    const lines = body.split(/\r?\n/);
    const filePath = lines.shift()?.trim() ?? "";
    const bytes = Number(lines.shift()?.trim() ?? "NaN");
    const preview = lines.join("\n").trimEnd();
    if (!filePath || !Number.isFinite(bytes)) continue;
    if (!isProductionRelevant(filePath)) continue;
    files.push({
      filePath,
      bytes,
      heuristicScore: heuristicScore(filePath, preview),
      preview: compactPreview(redactSensitiveText(preview).text),
    });
  }
  return files
    .sort((a, b) => b.heuristicScore - a.heuristicScore || a.filePath.localeCompare(b.filePath))
    .slice(0, limit);
}

export function parseRankingsFromText(text: string): RankedFile[] {
  const value = extractJsonValue(text);
  const list = Array.isArray(value) ? value : asArray(asRecord(value, "ranking response").rankings);
  const rankings: RankedFile[] = [];
  for (let i = 0; i < list.length; i++) {
    const item = asRecord(list[i], `rankings[${i}]`);
    const filePath = asString(item.filePath, `rankings[${i}].filePath`);
    const score = parseScore(item.score, `rankings[${i}].score`);
    const reason = asString(item.reason ?? "No rationale provided.", `rankings[${i}].reason`);
    rankings.push({ filePath, score, reason });
  }
  if (rankings.length === 0) throw new Error("Ranking response contained no files.");
  return rankings;
}

export function normalizeRankings(
  files: SourceFileSummary[],
  modelRankings: RankedFile[],
): RankedFile[] {
  const modelRanked: RankedFile[] = [];
  const seen = new Set<string>();
  for (const r of modelRankings) {
    if (files.some((f) => f.filePath === r.filePath) && !seen.has(r.filePath)) {
      modelRanked.push(r);
      seen.add(r.filePath);
    }
  }
  const fallback: RankedFile[] = [];
  for (const f of files) {
    if (!seen.has(f.filePath)) {
      fallback.push({
        filePath: f.filePath,
        score: f.heuristicScore,
        reason: "Model omitted this file; using local production-risk heuristic.",
      });
    }
  }
  return [
    ...modelRanked.sort((a, b) => b.score - a.score || a.filePath.localeCompare(b.filePath)),
    ...fallback.sort((a, b) => b.score - a.score || a.filePath.localeCompare(b.filePath)),
  ];
}

export function selectTopRankedFiles(rankings: RankedFile[], limit: number): RankedFile[] {
  if (!Number.isInteger(limit) || limit <= 0) {
    throw new Error("--limit must be a positive integer.");
  }
  return rankings.slice(0, limit);
}

function isProductionRelevant(rel: string): boolean {
  const ext = path.extname(rel);
  if (!PRODUCTION_EXTENSIONS.has(ext)) return false;
  const normalized = rel.replace(/\\/g, "/");
  if (/(^|\/)(src\/generated|generated)(\/|$)/i.test(normalized)) return false;
  if (/(^|\/)package-info\.java$/i.test(normalized)) return false;
  if (/(^|\/)(src\/test|test|tests|fixtures?|examples?|samples?)(\/|$)/i.test(normalized)) {
    return false;
  }
  if (/gradle-wrapper\.(jar|properties)$/i.test(normalized)) return false;
  return true;
}

function heuristicScore(filePath: string, preview: string): 1 | 2 | 3 | 4 | 5 {
  const haystack = `${filePath}\n${preview}`;
  let score = 1;
  for (const pattern of HIGH_VALUE_PATTERNS) {
    if (pattern.test(haystack)) score++;
  }
  if (/src\/main\//.test(filePath)) score++;
  if (/public|private|protected|class|interface|enum/.test(preview)) score++;
  return Math.max(1, Math.min(5, score)) as 1 | 2 | 3 | 4 | 5;
}

function compactPreview(input: string): string {
  return input
    .split(/\r?\n/)
    .slice(0, 24)
    .map((line) => line.slice(0, 110))
    .join("\n");
}

function asArray(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error("ranking response.rankings must be an array.");
  return value;
}

function parseScore(value: unknown, label: string): 1 | 2 | 3 | 4 | 5 {
  const n = typeof value === "string" ? Number(value) : value;
  if (!Number.isInteger(n) || (n as number) < 1 || (n as number) > 5) {
    throw new Error(`${label} must be an integer from 1 to 5.`);
  }
  return n as 1 | 2 | 3 | 4 | 5;
}

function containerInventoryCommand(): string {
  const pruneDirs = [...IGNORE_DIRS]
    .map((dir) => `-path './${dir}' -o -path './${dir}/*'`)
    .join(" -o ");
  const extensionFilter = [...PRODUCTION_EXTENSIONS].map((ext) => `-name '*${ext}'`).join(" -o ");
  const script = `find . \\( ${pruneDirs} \\) -prune -o -type f \\( ${extensionFilter} \\) -print0 | sort -z | while IFS= read -r -d '' file; do
  rel="\${file#./}"
  bytes=$(wc -c < "$file" | tr -d ' ')
  if [ "$bytes" -gt 1000000 ]; then
    continue
  fi
  printf '\\036%s\\n%s\\n' "$rel" "$bytes"
  sed -n '1,24p' "$file" | cut -c1-110
  printf '\\037\\n'
done`;
  return `bash -lc ${shellQuote(script)}`;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}
