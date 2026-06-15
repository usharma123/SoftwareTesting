import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { FileRecord, Finding, Severity } from "@deepsec/core";
import {
  compareSeverity,
  dataDir,
  getDataRoot,
  loadAllFileRecords,
  parseSeverity,
  SEVERITIES,
  severityAtOrAbove,
} from "@deepsec/core";
import { BOLD, DIM, GREEN, RESET, YELLOW } from "../formatters.js";
import { resolveAgentType } from "../resolve-agent-type.js";

interface OwnerSummary {
  assignee?: string;
  assigneeSource?: "oncall" | "manager" | "top-contributor" | "last-committer";
  teams: { name: string; slug: string }[];
  oncall: { name: string; email: string; slack_user_id?: string; github_username?: string }[];
  managers: { email: string; slack_user_id?: string }[];
  contributors: { name: string; email: string; github_username?: string; score: number }[];
  recentCommitters: { name: string; email: string; date: string }[];
}

interface ExportedFinding {
  title: string;
  description: string;
  severity: Severity;
  labels: string[];
  /** Best-guess owner email, suitable for downstream issue-tracker assignment. */
  assignee?: string;
  metadata: {
    projectId: string;
    filePath: string;
    lineNumbers: number[];
    severity: Severity;
    vulnSlug: string;
    confidence: string;
    discoveredAt: string;
    runId: string;
    revalidation?: {
      verdict: string;
      reasoning: string;
    };
    githubUrl?: string;
    owners: OwnerSummary;
  };
}

function summarizeOwners(record: FileRecord): OwnerSummary {
  const teams = (record.gitInfo?.ownership?.escalationTeams ?? []).map((t) => ({
    name: t.name,
    slug: t.slug,
  }));
  const oncall = (record.gitInfo?.ownership?.escalationTeams ?? [])
    .map((t) => t.current_oncall)
    .filter((o) => o?.email)
    .map((o) => ({
      name: o.name,
      email: o.email,
      slack_user_id: o.slack_user_id,
      github_username: o.github_username,
    }));
  const managers = (record.gitInfo?.ownership?.escalationTeams ?? [])
    .map((t) => t.manager)
    .filter((m) => m?.email)
    .map((m) => ({ email: m.email, slack_user_id: m.slack_user_id }));
  const contributors = (record.gitInfo?.ownership?.contributors ?? []).slice(0, 5).map((c) => ({
    name: c.name,
    email: c.email,
    github_username: c.github_username,
    score: c.score,
  }));
  const recentCommitters = (record.gitInfo?.recentCommitters ?? []).slice(0, 5);

  let assignee: string | undefined;
  let assigneeSource: OwnerSummary["assigneeSource"];
  if (oncall[0]?.email) {
    assignee = oncall[0].email;
    assigneeSource = "oncall";
  } else if (managers[0]?.email) {
    assignee = managers[0].email;
    assigneeSource = "manager";
  } else if (contributors[0]?.email) {
    assignee = contributors[0].email;
    assigneeSource = "top-contributor";
  } else if (recentCommitters[0]?.email) {
    assignee = recentCommitters[0].email;
    assigneeSource = "last-committer";
  }

  return { assignee, assigneeSource, teams, oncall, managers, contributors, recentCommitters };
}

function projectRepoUrl(projectId: string): string | undefined {
  try {
    const p = JSON.parse(fs.readFileSync(path.join(dataDir(projectId), "project.json"), "utf-8"));
    return p.githubUrl;
  } catch {
    return undefined;
  }
}

function makeGithubLink(
  repoUrl: string | undefined,
  filePath: string,
  lines: number[],
): string | undefined {
  if (!repoUrl) return undefined;
  const base = repoUrl.replace(/\/+$/, "").replace(/\/blob\/[^/]+$/, "");
  const firstLine = lines[0];
  const lastLine = lines[lines.length - 1];
  const anchor = firstLine === lastLine ? `#L${firstLine}` : `#L${firstLine}-L${lastLine}`;
  const branch = repoUrl.match(/\/blob\/([^/]+)/)?.[1] ?? "main";
  return `${base}/blob/${branch}/${filePath}${anchor}`;
}

function buildDescription(
  finding: Finding,
  record: FileRecord,
  projectId: string,
  owners: OwnerSummary,
  githubUrl?: string,
): string {
  const head = githubUrl
    ? `**File:** [\`${record.filePath}\`](${githubUrl}) (lines ${finding.lineNumbers.join(", ")})`
    : `**File:** \`${record.filePath}\` (lines ${finding.lineNumbers.join(", ")})`;

  const parts: string[] = [
    head,
    `**Project:** ${projectId}`,
    `**Severity:** ${finding.severity}  •  **Confidence:** ${finding.confidence}  •  **Slug:** \`${finding.vulnSlug}\``,
  ];

  if (owners.assignee || owners.teams.length > 0 || owners.oncall.length > 0) {
    parts.push("", "## Owners");
    if (owners.assignee) {
      parts.push(
        "",
        `**Suggested assignee:** \`${owners.assignee}\` _(via ${owners.assigneeSource})_`,
      );
    }
    if (owners.teams.length > 0) {
      parts.push(
        "",
        "**Teams:**",
        ...owners.teams.slice(0, 3).map((t) => `- ${t.name} (\`${t.slug}\`)`),
      );
    }
    if (owners.oncall.length > 0) {
      parts.push(
        "",
        "**Current on-call:**",
        ...owners.oncall.slice(0, 3).map((o) => {
          const gh = o.github_username
            ? ` • [@${o.github_username}](https://github.com/${o.github_username})`
            : "";
          return `- ${o.name} <${o.email}>${gh}`;
        }),
      );
    }
    if (owners.managers.length > 0) {
      parts.push("", "**Managers:**", ...owners.managers.slice(0, 3).map((m) => `- <${m.email}>`));
    }
  }

  parts.push(
    "",
    "## Finding",
    "",
    finding.description,
    "",
    "## Recommendation",
    "",
    finding.recommendation,
  );

  if (finding.revalidation) {
    parts.push(
      "",
      "## Revalidation",
      "",
      `**Verdict:** ${finding.revalidation.verdict}`,
      "",
      finding.revalidation.reasoning,
    );
  }

  if (owners.contributors.length > 0) {
    parts.push(
      "",
      "## Top contributors",
      "",
      ...owners.contributors.map((c) => `- ${c.name} <${c.email}> (score: ${c.score.toFixed(2)})`),
    );
  }
  if (owners.recentCommitters.length > 0) {
    parts.push(
      "",
      "## Recent committers (`git log`)",
      "",
      ...owners.recentCommitters.map((c) => `- ${c.name} <${c.email}> (${c.date.slice(0, 10)})`),
    );
  }

  return parts.join("\n");
}

function inDay(iso: string, dayStart: number, dayEnd: number): boolean {
  const t = Date.parse(iso);
  return !Number.isNaN(t) && t >= dayStart && t < dayEnd;
}

function startOfTodayLocal(): number {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

function listProjectIds(): string[] {
  const dataDirPath = path.resolve(getDataRoot());
  if (!fs.existsSync(dataDirPath)) return [];
  return fs
    .readdirSync(dataDirPath, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .filter((p) => fs.existsSync(path.join(dataDirPath, p, "project.json")));
}

/** Stable, filesystem-safe filename for a finding in md-dir mode. */
function findingFilename(f: ExportedFinding): string {
  const hash = crypto
    .createHash("sha1")
    .update(
      `${f.metadata.projectId}\0${f.metadata.filePath}\0${f.metadata.lineNumbers.join(",")}\0${f.metadata.vulnSlug}`,
    )
    .digest("hex")
    .slice(0, 10);
  const safeSlug = f.metadata.vulnSlug.replace(/[^a-zA-Z0-9-]/g, "-");
  const safeProject = f.metadata.projectId.replace(/[^a-zA-Z0-9-]/g, "-");
  return `${safeProject}-${safeSlug}-${hash}.md`;
}

function writeJson(findings: ExportedFinding[], out: string | undefined) {
  const json = JSON.stringify(findings, null, 2);
  if (out) {
    fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
    fs.writeFileSync(out, json + "\n");
    console.log(`\n${GREEN}Exported ${findings.length} finding(s)${RESET} → ${BOLD}${out}${RESET}`);
  } else {
    process.stdout.write(json + "\n");
  }
}

function writeSarif(findings: ExportedFinding[], out: string | undefined) {
  const sarif = JSON.stringify(buildSarifLog(findings), null, 2);
  if (out) {
    fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
    fs.writeFileSync(out, sarif + "\n");
    console.log(
      `\n${GREEN}Exported ${findings.length} SARIF result(s)${RESET} → ${BOLD}${out}${RESET}`,
    );
  } else {
    process.stdout.write(sarif + "\n");
  }
}

function writeMdDir(findings: ExportedFinding[], out: string) {
  const root = path.resolve(out);
  fs.mkdirSync(root, { recursive: true });

  // The set of files this export is authoritative for. Anything else in
  // the severity subdirs is left over from a prior run — most often a
  // finding that has since been revalidated as fixed/false-positive/
  // accepted-risk and is now filtered out of the export. Without this
  // sweep, those orphans linger forever and make the export directory
  // misleading (the user thinks they still have unresolved findings on a
  // file we've already patched).
  const wantedFiles = new Set<string>();
  for (const f of findings) {
    wantedFiles.add(path.join(root, f.metadata.severity, findingFilename(f)));
  }

  // Only sweep severity subdirs we recognize — keeps an accidental
  // `--out ~/Documents` from nuking unrelated files. Severity values are
  // a closed enum (see `Severity` in @deepsec/core), so this list IS the
  // namespace md-dir mode owns.
  let droppedStale = 0;
  for (const sev of SEVERITIES) {
    const dir = path.join(root, sev);
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isFile() || !entry.name.endsWith(".md")) continue;
      const full = path.join(dir, entry.name);
      if (!wantedFiles.has(full)) {
        fs.unlinkSync(full);
        droppedStale++;
      }
    }
    // Drop now-empty severity dirs so a 0-finding export leaves a clean
    // root rather than a forest of empty directories.
    try {
      if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir);
    } catch {}
  }

  for (const f of findings) {
    const dir = path.join(root, f.metadata.severity);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, findingFilename(f));
    const body = `# ${f.title}\n\n${f.description}\n`;
    fs.writeFileSync(file, body);
  }

  const staleNote = droppedStale > 0 ? ` (removed ${droppedStale} stale file(s))` : "";
  console.log(
    `\n${GREEN}Exported ${findings.length} finding(s)${RESET} → ${BOLD}${root}/${RESET}${staleNote}`,
  );
}

function buildSarifLog(findings: ExportedFinding[]) {
  const rulesBySlug = new Map<string, { index: number; rule: Record<string, unknown> }>();
  const rules: Record<string, unknown>[] = [];
  for (const finding of findings) {
    const slug = finding.metadata.vulnSlug;
    if (rulesBySlug.has(slug)) continue;
    const rule = {
      id: slug,
      name: slug,
      shortDescription: { text: slug },
      fullDescription: { text: firstParagraph(finding.description) },
      help: { text: finding.description, markdown: finding.description },
      properties: {
        tags: ["security", `deepsec:${slug}`],
        precision: confidenceToPrecision(finding.metadata.confidence),
        "security-severity": sarifSecuritySeverity(finding.severity),
      },
    };
    rulesBySlug.set(slug, { index: rules.length, rule });
    rules.push(rule);
  }

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "DeepSec",
            informationUri: "https://github.com/vercel/deepsec",
            rules,
          },
        },
        results: findings.map((finding) => {
          const rule = rulesBySlug.get(finding.metadata.vulnSlug);
          const lineNumbers = finding.metadata.lineNumbers;
          const startLine = lineNumbers[0] ?? 1;
          const endLine = lineNumbers.at(-1) ?? startLine;
          return {
            ruleId: finding.metadata.vulnSlug,
            ruleIndex: rule?.index ?? 0,
            level: sarifLevel(finding.severity),
            message: { text: finding.title },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: finding.metadata.filePath,
                    uriBaseId: "PROJECTROOT",
                  },
                  region: {
                    startLine,
                    endLine,
                  },
                },
              },
            ],
            properties: {
              projectId: finding.metadata.projectId,
              severity: finding.severity,
              confidence: finding.metadata.confidence,
              runId: finding.metadata.runId,
              discoveredAt: finding.metadata.discoveredAt,
              labels: finding.labels,
              assignee: finding.assignee,
              revalidation: finding.metadata.revalidation,
              githubUrl: finding.metadata.githubUrl,
            },
          };
        }),
      },
    ],
  };
}

function firstParagraph(text: string): string {
  return (
    text
      .split(/\n\s*\n/)[0]
      ?.replace(/\s+/g, " ")
      .trim() || "DeepSec finding."
  );
}

function confidenceToPrecision(confidence: string): "very-high" | "high" | "medium" | "low" {
  switch (confidence) {
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "medium";
  }
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
    case "HIGH_BUG":
      return "error";
    case "MEDIUM":
    case "BUG":
      return "warning";
    case "LOW":
      return "note";
  }
}

function sarifSecuritySeverity(severity: Severity): string {
  switch (severity) {
    case "CRITICAL":
      return "9.0";
    case "HIGH":
    case "HIGH_BUG":
      return "8.0";
    case "MEDIUM":
    case "BUG":
      return "5.0";
    case "LOW":
      return "2.0";
  }
}

export async function exportCommand(opts: {
  projectId?: string;
  minSeverity?: string;
  onlySeverity?: string;
  discoveredToday?: boolean;
  since?: string;
  onlyTruePositive?: boolean;
  /** Deprecated: false-positive is now hidden by default. Kept as a no-op for back-compat. */
  excludeFalsePositive?: boolean;
  /**
   * Restore old behavior of including resolved verdicts (fixed,
   * false-positive, accepted-risk) in the output. Off by default.
   */
  includeResolved?: boolean;
  onlySlugs?: string;
  skipSlugs?: string;
  runId?: string;
  out?: string;
  format?: string;
  /** Drop findings without any ownership data (no assignee, no teams) */
  requireOwner?: boolean;
  /** Only include findings produced by this agent backend (e.g. `codex`) */
  onlyAgent?: string;
  /** Only include findings produced under this --reinvestigate wave marker */
  onlyMarker?: string;
}) {
  const projectIds = opts.projectId
    ? opts.projectId
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : listProjectIds();

  const format = opts.format ?? "json";
  if (format !== "json" && format !== "md-dir" && format !== "sarif") {
    throw new Error(`--format must be "json", "md-dir", or "sarif", got "${format}"`);
  }
  if (format === "md-dir" && !opts.out) {
    throw new Error(`--format md-dir requires --out <dir>`);
  }

  const minSeverity = opts.minSeverity
    ? parseSeverity(opts.minSeverity, "--min-severity")
    : undefined;
  const onlySeverity = opts.onlySeverity
    ? parseSeverity(opts.onlySeverity, "--only-severity")
    : undefined;

  let sinceMs: number | undefined;
  let untilMs = Number.POSITIVE_INFINITY;
  if (opts.discoveredToday) {
    sinceMs = startOfTodayLocal();
    untilMs = sinceMs + 24 * 60 * 60 * 1000;
  } else if (opts.since) {
    const t = Date.parse(opts.since);
    if (Number.isNaN(t)) throw new Error(`--since: not a valid ISO timestamp: ${opts.since}`);
    sinceMs = t;
  }

  const onlySlugs = opts.onlySlugs
    ?.split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const skipSlugs = opts.skipSlugs
    ?.split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const onlySlugSet = onlySlugs?.length ? new Set(onlySlugs) : undefined;
  const skipSlugSet = skipSlugs?.length ? new Set(skipSlugs) : undefined;

  console.log(`${BOLD}Exporting findings (${format})${RESET}`);
  console.log(`  Projects: ${projectIds.join(", ") || "(none)"}`);
  if (minSeverity) console.log(`  Min severity: ${minSeverity}`);
  if (onlySeverity) console.log(`  Only severity: ${onlySeverity}`);
  if (opts.discoveredToday) console.log(`  ${YELLOW}Filter: discovered today only${RESET}`);
  if (opts.since) console.log(`  Filter: discovered since ${opts.since}`);
  if (opts.onlyTruePositive) console.log(`  Filter: only revalidated true-positive`);
  if (opts.runId) console.log(`  Filter: run ${opts.runId}`);
  if (opts.includeResolved) {
    console.log(`  Filter: including resolved verdicts (fixed/false-positive/accepted-risk)`);
  } else {
    console.log(`  Filter: hiding resolved verdicts (fixed/false-positive/accepted-risk)`);
  }
  if (opts.excludeFalsePositive) {
    console.log(
      `  ${YELLOW}Note: --exclude-false-positive is now the default; flag is a no-op.${RESET}`,
    );
  }
  if (onlySlugs) console.log(`  Only slugs: ${onlySlugs.join(", ")}`);
  if (skipSlugs) console.log(`  Skip slugs: ${skipSlugs.join(", ")}`);
  if (opts.requireOwner)
    console.log(`  ${YELLOW}Filter: only findings with ownership data${RESET}`);
  const onlyMarker = opts.onlyMarker !== undefined ? Number(opts.onlyMarker) : undefined;
  if (onlyMarker !== undefined && !Number.isFinite(onlyMarker)) {
    throw new Error(`--only-marker must be a number, got "${opts.onlyMarker}"`);
  }
  const onlyAgent = opts.onlyAgent ? resolveAgentType(opts.onlyAgent) : undefined;
  if (opts.onlyAgent) console.log(`  Only agent: ${opts.onlyAgent}`);
  if (onlyMarker !== undefined) console.log(`  Only marker: ${onlyMarker}`);

  const findings: ExportedFinding[] = [];
  let droppedNoOwner = 0;
  let withAssignee = 0;
  let withTeam = 0;

  for (const projectId of projectIds) {
    let records: FileRecord[];
    try {
      records = loadAllFileRecords(projectId);
    } catch (err) {
      console.error(
        `  ${DIM}[${projectId}] skipped: ${err instanceof Error ? err.message : err}${RESET}`,
      );
      continue;
    }
    const repoUrl = projectRepoUrl(projectId);
    let emitted = 0;

    for (const record of records) {
      const latest = record.analysisHistory?.[record.analysisHistory.length - 1];
      if (!latest) continue;

      if (sinceMs !== undefined && !inDay(latest.investigatedAt, sinceMs, untilMs)) continue;

      // Build a map: finding-index → analysisHistory entry that produced it.
      // Findings are appended in analysisHistory order, so the i-th finding
      // belongs to whichever entry's findingCount range covers i.
      const findingSource: Array<(typeof record.analysisHistory)[number] | undefined> = [];
      let cursor = 0;
      for (const h of record.analysisHistory ?? []) {
        const fc = h.findingCount ?? 0;
        for (let k = 0; k < fc; k++) findingSource[cursor++] = h;
      }

      let findingIndex = -1;
      for (const finding of record.findings ?? []) {
        findingIndex++;
        if (minSeverity && !severityAtOrAbove(finding.severity, minSeverity)) continue;
        if (onlySeverity && finding.severity !== onlySeverity) continue;
        if (onlySlugSet && !onlySlugSet.has(finding.vulnSlug)) continue;
        if (skipSlugSet?.has(finding.vulnSlug)) continue;
        if (opts.onlyTruePositive && finding.revalidation?.verdict !== "true-positive") continue;
        // Default behavior: hide every "resolved" verdict. fixed = patched,
        // false-positive = not real, accepted-risk = real but consciously
        // accepted, duplicate = same issue as another finding in the file
        // (the primary carries the canonical signal). None of these are
        // work the export consumer should action. Pass --include-resolved
        // to surface them anyway (audit / history use cases). The legacy
        // --exclude-false-positive flag is now a no-op — preserved so
        // existing scripts don't break.
        if (
          !opts.includeResolved &&
          (finding.revalidation?.verdict === "fixed" ||
            finding.revalidation?.verdict === "false-positive" ||
            finding.revalidation?.verdict === "accepted-risk" ||
            finding.revalidation?.verdict === "duplicate")
        ) {
          continue;
        }

        const source = findingSource[findingIndex];
        const findingRunId = finding.producedByRunId ?? source?.runId ?? latest.runId;
        if (opts.runId && findingRunId !== opts.runId) continue;
        if (onlyAgent && source?.agentType !== onlyAgent) continue;
        if (onlyMarker !== undefined && source?.reinvestigateMarker !== onlyMarker) continue;
        const discoveredAt =
          source?.runId === findingRunId
            ? source.investigatedAt
            : ((record.analysisHistory ?? []).find((entry) => entry.runId === findingRunId)
                ?.investigatedAt ?? latest.investigatedAt);

        const githubUrl = makeGithubLink(repoUrl, record.filePath, finding.lineNumbers);
        const owners = summarizeOwners(record);

        const hasOwner = !!owners.assignee || owners.teams.length > 0 || owners.oncall.length > 0;
        if (opts.requireOwner && !hasOwner) {
          droppedNoOwner++;
          continue;
        }

        const labels = [
          "security",
          `project:${projectId}`,
          `severity:${finding.severity}`,
          `slug:${finding.vulnSlug}`,
          `confidence:${finding.confidence}`,
        ];
        if (finding.revalidation?.verdict)
          labels.push(`revalidation:${finding.revalidation.verdict}`);
        for (const t of owners.teams.slice(0, 3)) labels.push(`owning-team:${t.slug}`);
        if (!hasOwner) labels.push("missing-owner");

        if (owners.assignee) withAssignee++;
        if (owners.teams.length > 0) withTeam++;

        findings.push({
          title: `[${finding.severity}] ${finding.title}`,
          description: buildDescription(finding, record, projectId, owners, githubUrl),
          severity: finding.severity,
          labels,
          assignee: owners.assignee,
          metadata: {
            projectId,
            filePath: record.filePath,
            lineNumbers: finding.lineNumbers,
            severity: finding.severity,
            vulnSlug: finding.vulnSlug,
            confidence: finding.confidence,
            discoveredAt,
            runId: findingRunId,
            revalidation: finding.revalidation
              ? { verdict: finding.revalidation.verdict, reasoning: finding.revalidation.reasoning }
              : undefined,
            githubUrl,
            owners,
          },
        });
        emitted++;
      }
    }
    console.log(`  [${projectId}] ${emitted} finding(s)`);
  }

  // Sort: severity ascending (CRITICAL first), then project, then file
  findings.sort((a, b) => {
    const severityOrder = compareSeverity(a.metadata.severity, b.metadata.severity);
    if (severityOrder !== 0) return severityOrder;
    if (a.metadata.projectId !== b.metadata.projectId)
      return a.metadata.projectId.localeCompare(b.metadata.projectId);
    return a.metadata.filePath.localeCompare(b.metadata.filePath);
  });

  if (format === "md-dir") {
    writeMdDir(findings, opts.out!);
  } else if (format === "sarif") {
    writeSarif(findings, opts.out);
  } else {
    writeJson(findings, opts.out);
  }

  if (findings.length > 0) {
    const pct = (n: number) => `${((n / findings.length) * 100).toFixed(0)}%`;
    console.log();
    console.log(`${BOLD}Ownership coverage:${RESET}`);
    console.log(`  with assignee:    ${withAssignee}/${findings.length} (${pct(withAssignee)})`);
    console.log(`  with owning team: ${withTeam}/${findings.length} (${pct(withTeam)})`);
    if (droppedNoOwner > 0) {
      console.log(`  ${YELLOW}dropped (--require-owner): ${droppedNoOwner}${RESET}`);
    }
  }
}
