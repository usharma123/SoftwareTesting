import { config as dotenvConfig } from "dotenv";

dotenvConfig({ path: ".env.local" });
dotenvConfig(); // also load .env as fallback

import { getRegistry } from "@deepsec/core";
import { Command } from "commander";
import { enrichCommand } from "./commands/enrich.js";
import {
  exploreArtifactsCommand,
  exploreAttemptCommand,
  exploreAuditCommand,
  exploreBundleCommand,
  exploreCiCommand,
  exploreCommand,
  exploreDoctorCommand,
  exploreEvidenceCommand,
  exploreFindingsCommand,
  exploreListCommand,
  exploreManifestCommand,
  exploreRetryCommand,
  exploreSetupCommand,
  exploreStatusCommand,
  exploreVerifyBundleCommand,
  exploreVerifyManifestCommand,
} from "./commands/explore.js";
import { exportCommand } from "./commands/export.js";
import { initCommand } from "./commands/init.js";
import { initProjectCommand } from "./commands/init-project.js";
import { metricsCommand } from "./commands/metrics.js";
import { processCommand } from "./commands/process.js";
import { reportCommand } from "./commands/report.js";
import { revalidateCommand } from "./commands/revalidate.js";
import { sandboxAllCommand } from "./commands/sandbox-all.js";
import { sandboxCommand } from "./commands/sandbox-process.js";
import { scanCommand } from "./commands/scan.js";
import { statusCommand } from "./commands/status.js";
import { triageCommand } from "./commands/triage.js";
import { loadConfig } from "./load-config.js";
import { applyAiGatewayDefaults } from "./preflight.js";
import { getDeepsecVersion } from "./version.js";

const program = new Command();

function addExploreOptions(command: Command): Command {
  return command
    .option(
      "--project-id <id>",
      "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
    )
    .option("--root <path>", "Override the project's root for this explore run")
    .option(
      "--profile <profile>",
      "Explore runtime profile (default: java11-gradle)",
      "java11-gradle",
    )
    .option("--runtime <runtime>", "Docker runtime; must be runsc", "runsc")
    .option(
      "--model <model>",
      "OpenRouter model for focused exploration",
      "anthropic/claude-opus-4.8",
    )
    .option("--rank-model <model>", "OpenRouter model for file ranking")
    .option("--stub-model", "Use a deterministic local stub model for harness testing")
    .option(
      "--live-model-check",
      "In explore doctor, spend a tiny OpenRouter request to verify selected model access",
    )
    .option("--limit <n>", "Number of ranked files to explore (default: 3)", parseInt)
    .option("--concurrency <n>", "Focused attempts to run in parallel (default: 1)", parseInt)
    .option("--max-turns <n>", "Max model turns per focused attempt (default: 40)", parseInt)
    .option(
      "--max-tokens <n>",
      "Stop before the next model call after this many reported tokens",
      parseInt,
    )
    .option(
      "--max-cost-usd <n>",
      "Stop before the next model call after this much reported provider cost",
      parseFloat,
    );
}

program
  .name("deepsec")
  .description("AI-powered vulnerability scanner for any codebase")
  .version(getDeepsecVersion())
  .addHelpText(
    "after",
    `
Quickstart:
  cd <your-repo>                 first, in the codebase you want to scan
  npx deepsec init               scaffold .deepsec/ + register this repo
  cd .deepsec && pnpm install
  pnpm deepsec scan    --project-id <id>
  pnpm deepsec process --project-id <id>

  See \`deepsec init --help\` and the docs at:
    https://github.com/vercel/deepsec`,
  );

program
  .command("init [workspace] [target-root]")
  .description("Scaffold .deepsec/ in your repo and register the first project")
  .option("--id <project-id>", "Override the project id (default: basename of <target-root>)")
  .option("--force", "Allow writing into a non-empty workspace directory")
  .addHelpText(
    "after",
    `
Defaults:
  workspace     .deepsec
  target-root   .              (the codebase you ran init from)
  project id    derived from the target's directory basename

Examples:
  $ npx deepsec init                          # most common — from your repo root
  $ npx deepsec init audits ../my-app         # custom workspace + target
  $ npx deepsec init .deepsec . --id my-app   # override the auto-derived id`,
  )
  .action(
    (
      workspace: string | undefined,
      targetRoot: string | undefined,
      opts: { id?: string; force?: boolean },
    ) =>
      initCommand({
        workspace,
        targetRoot,
        id: opts.id,
        force: opts.force,
      }),
  );

program
  .command("init-project <target-root>")
  .description("Register an additional project in the current .deepsec workspace")
  .option("--id <project-id>", "Override the project id (default: basename of <target-root>)")
  .option("--force", "Overwrite an existing project of the same id")
  .addHelpText(
    "after",
    `
Run from inside a .deepsec/ workspace. Appends an entry to
deepsec.config.ts (above the marker comment) and writes a fresh
data/<id>/{INFO.md,SETUP.md,project.json}.

Examples:
  $ pnpm deepsec init-project ../another-app
  $ pnpm deepsec init-project ./packages/api --id api`,
  )
  .action((targetRoot: string | undefined, opts: { id?: string; force?: boolean }) =>
    initProjectCommand({ targetRoot, id: opts.id, force: opts.force }),
  );

program
  .command("scan")
  .description("Run regex matchers across a project to find candidate vulnerability sites")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option(
    "--root <path>",
    "Override the project's root (rare — use only for sandbox runs or one-off scans against a different checkout)",
  )
  .option(
    "--matchers <slugs>",
    "Comma-separated matcher slugs to run (default: all registered matchers)",
  )
  .addHelpText(
    "after",
    `
The root is resolved from deepsec.config.ts (or data/<id>/project.json
once a project has been scanned). Pass --root only when overriding.

Examples:
  $ pnpm deepsec scan --project-id my-app
  $ pnpm deepsec scan --project-id my-app --matchers auth-bypass,xss
  $ pnpm deepsec scan --project-id my-app --root ../checkout-on-pr-branch`,
  )
  .action(scanCommand);

program
  .command("process")
  .description("Investigate candidates with an AI agent")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Resume a specific processing run")
  .option(
    "--agent <type>",
    "Agent plugin type: codex or claude (default: defaultAgent in deepsec.config.ts, else codex)",
  )
  .option(
    "--model <model>",
    "Model to use (default: claude-opus-4-8 for claude, gpt-5.5 for codex)",
  )
  .option("--max-turns <n>", "Max conversation turns per batch (default: 150)", parseInt)
  .option(
    "--reinvestigate [n]",
    "Re-investigate files. No arg = all files. Pass N as a wave marker — productive analyses are tagged with N, and re-running with the same N skips already-done files. Bump N to request another pass.",
  )
  .option("--limit <n>", "Max number of files to process", parseInt)
  .option("--concurrency <n>", "Batches to process in parallel (default: cores - 1)", parseInt)
  .option("--filter <prefix>", "Only process files matching this path prefix")
  .option("--batch-size <n>", "Files per batch (default: 5)", parseInt)
  .option("--root <path>", "Override rootPath from project.json (for sandbox execution)")
  .option(
    "--manifest <path>",
    "JSON file with array of file paths to process (instead of all pending)",
  )
  .option("--only-slugs <csv>", "Only process files that have a candidate with one of these slugs")
  .option("--skip-slugs <csv>", "Skip files whose candidate slugs are all in this set")
  .option(
    "--diff <ref>",
    "Direct mode: investigate files changed between <ref> and HEAD (e.g. origin/main, HEAD~1..HEAD). Auto-creates the project if needed. Exits 1 if any finding is produced.",
  )
  .option("--diff-staged", "Direct mode: investigate files in the git index (vs HEAD)")
  .option("--diff-working", "Direct mode: investigate uncommitted + untracked files")
  .option("--files <csv>", "Direct mode: investigate this comma-separated path list")
  .option(
    "--files-from <path>",
    "Direct mode: read newline-delimited paths from <path> (or '-' for stdin)",
  )
  .option("--no-ignore", "In direct mode, skip the default ignore filter (test files, dist, etc.)")
  .option(
    "--comment-out <path>",
    "Write a PR-comment-shaped markdown summary to <path> (only when findings exist)",
  )
  .action(processCommand);

const exploreCmd = program
  .command("explore")
  .description(
    "Run Mythos-style local gVisor exploration: model-ranked files, focused isolated attempts, and final validation.",
  )
  .addHelpText(
    "after",
    `
Run options:
  --project-id <id>      Project identifier
  --root <path>          Override the project's root for this explore run
  --profile <profile>    Explore runtime profile
  --runtime <runtime>    Docker runtime; must be runsc
  --model <model>        OpenRouter model for focused exploration
  --rank-model <model>   OpenRouter model for file ranking
  --stub-model           Use deterministic local model responses for harness testing
  --live-model-check     In doctor, spend a tiny OpenRouter request to verify selected model access
  --limit <n>            Number of ranked files to explore
  --concurrency <n>      Focused attempts to run in parallel
  --max-turns <n>        Max model turns per focused attempt
  --max-tokens <n>       Stop before the next model call after this many reported tokens
  --max-cost-usd <n>     Stop before the next model call after this much reported provider cost

Examples:
  $ pnpm deepsec explore setup --profile java11-gradle
  $ pnpm deepsec explore doctor --root ../lib-testing/prowide-core --profile java11-gradle --runtime runsc
  $ pnpm deepsec explore list --project-id prowide-core
  $ pnpm deepsec explore status --project-id prowide-core
  $ pnpm deepsec explore status --project-id prowide-core --fail-on-accepted-findings
  $ pnpm deepsec explore status --project-id prowide-core --fail-on-accepted-findings --min-severity MEDIUM
  $ pnpm deepsec explore attempt 01 --project-id prowide-core --run-id <runId>
  $ pnpm deepsec explore findings --project-id prowide-core --run-id <runId> --json
  $ pnpm deepsec explore artifacts --project-id prowide-core --run-id <runId> --json
  $ pnpm deepsec explore audit --project-id prowide-core --run-id <runId> --json
  $ pnpm deepsec explore manifest --project-id prowide-core --run-id <runId> --out manifest.json
  $ pnpm deepsec explore verify-manifest manifest.json
  $ pnpm deepsec explore evidence manifest.json --out evidence.md
  $ pnpm deepsec explore bundle manifest.json --out-dir evidence-bundle --include-attempts
  $ pnpm deepsec explore verify-bundle evidence-bundle
  $ pnpm deepsec explore ci --project-id prowide-core --run-id <runId> --min-severity MEDIUM
  $ pnpm deepsec explore retry --project-id prowide-core --run-id <runId>
  $ pnpm deepsec explore --project-id prowide-core --root ../lib-testing/prowide-core --profile java11-gradle --runtime runsc --limit 3`,
  );

addExploreOptions(
  exploreCmd
    .command("run", { isDefault: true })
    .description("Run ranked, focused gVisor exploration attempts"),
).action(exploreCommand);

exploreCmd
  .command("setup")
  .description("Build the local java11-gradle gVisor image")
  .option(
    "--profile <profile>",
    "Explore runtime profile (default: java11-gradle)",
    "java11-gradle",
  )
  .action(exploreSetupCommand);

addExploreOptions(
  exploreCmd
    .command("doctor")
    .description(
      "Check local runsc/image/cache/OpenRouter readiness; add --live-model-check for an API probe",
    ),
).action(exploreDoctorCommand);

exploreCmd
  .command("list")
  .description("List completed explore runs for a project")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--json", "Print machine-readable run list JSON")
  .option("--limit <n>", "Maximum runs to list, newest first (default: 20)", parseInt)
  .action(exploreListCommand);

exploreCmd
  .command("attempt <attempt>")
  .description("Inspect one focused explore attempt by index or attempt directory name")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Explore run id (default: latest explore run for the project)")
  .option("--json", "Print machine-readable attempt inspection JSON")
  .option("--transcript", "Include full attempt transcripts in JSON output")
  .action((attempt: string, opts: Omit<Parameters<typeof exploreAttemptCommand>[0], "attempt">) =>
    exploreAttemptCommand({ ...opts, attempt }),
  );

exploreCmd
  .command("findings")
  .description("List bug reports from an explore run, accepted findings by default")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Explore run id (default: latest explore run for the project)")
  .option("--json", "Print machine-readable findings JSON")
  .option("--min-severity <sev>", "Minimum severity to include")
  .option("--all", "Include non-accepted bug reports as well as accepted findings")
  .action(exploreFindingsCommand);

exploreCmd
  .command("status")
  .description("Summarize and verify a completed explore run's artifacts")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Explore run id (default: latest explore run for the project)")
  .option("--json", "Print machine-readable status JSON")
  .option(
    "--min-severity <sev>",
    "Minimum accepted finding severity for --fail-on-accepted-findings (default: LOW)",
  )
  .option(
    "--fail-on-accepted-findings",
    "Exit 2 when artifact checks pass but accepted validated findings are present",
  )
  .action(exploreStatusCommand);

exploreCmd
  .command("artifacts")
  .description("List machine-readable paths and hashes for a completed explore run")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Explore run id (default: latest explore run for the project)")
  .option("--json", "Print machine-readable artifact index JSON")
  .option("--no-hashes", "Skip SHA-256 hashing of existing artifacts")
  .action(exploreArtifactsCommand);

exploreCmd
  .command("audit")
  .description("Print a named fail-closed checklist for a completed explore run")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Explore run id (default: latest explore run for the project)")
  .option("--json", "Print machine-readable audit JSON")
  .option(
    "--min-severity <sev>",
    "Minimum accepted finding severity for --fail-on-accepted-findings",
  )
  .option(
    "--fail-on-accepted-findings",
    "Exit 2 when artifact checks pass but accepted validated findings are present",
  )
  .option("--require-report", "Fail if run-scoped report artifacts are missing")
  .option("--require-ci", "Fail if CI artifacts are missing")
  .option("--fail-on-warnings", "Exit 1 when warning checks are present")
  .action(exploreAuditCommand);

exploreCmd
  .command("manifest")
  .description("Print or write a compact JSON manifest for a completed explore run")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Explore run id (default: latest explore run for the project)")
  .option("--json", "Print manifest JSON even when --out is provided")
  .option("--out <path>", "Write manifest JSON to this path")
  .option(
    "--min-severity <sev>",
    "Minimum accepted finding severity for --fail-on-accepted-findings",
  )
  .option(
    "--fail-on-accepted-findings",
    "Exit 2 when artifact checks pass but accepted validated findings are present",
  )
  .option("--require-report", "Fail if run-scoped report artifacts are missing")
  .option("--require-ci", "Fail if CI artifacts are missing")
  .option("--fail-on-warnings", "Exit 1 when warning checks are present")
  .action(exploreManifestCommand);

exploreCmd
  .command("verify-manifest <manifest>")
  .description("Verify artifact existence and hashes recorded in an explore manifest")
  .option("--json", "Print machine-readable manifest verification JSON")
  .action(
    (
      manifest: string,
      opts: Omit<Parameters<typeof exploreVerifyManifestCommand>[0], "manifest">,
    ) => exploreVerifyManifestCommand({ ...opts, manifest }),
  );

exploreCmd
  .command("evidence <manifest>")
  .description("Render a reviewer-friendly evidence summary from an explore manifest")
  .option("--json", "Print machine-readable evidence summary JSON")
  .option("--out <path>", "Write Markdown evidence summary, or JSON when paired with --json")
  .action(
    (manifest: string, opts: Omit<Parameters<typeof exploreEvidenceCommand>[0], "manifest">) =>
      exploreEvidenceCommand({ ...opts, manifest }),
  );

exploreCmd
  .command("bundle <manifest>")
  .description("Create a portable hashed evidence bundle directory from an explore manifest")
  .option("--out-dir <path>", "Output directory for the evidence bundle")
  .option(
    "--include-attempts",
    "Include raw run and per-attempt artifacts in addition to report/CI artifacts",
  )
  .option("--force", "Overwrite a non-empty output directory")
  .option("--json", "Print machine-readable bundle index JSON")
  .action((manifest: string, opts: Omit<Parameters<typeof exploreBundleCommand>[0], "manifest">) =>
    exploreBundleCommand({ ...opts, manifest }),
  );

exploreCmd
  .command("verify-bundle <bundle-dir>")
  .description("Verify copied files and hashes in a portable explore evidence bundle")
  .option("--json", "Print machine-readable bundle verification JSON")
  .action(
    (
      bundleDir: string,
      opts: Omit<Parameters<typeof exploreVerifyBundleCommand>[0], "bundleDir">,
    ) => exploreVerifyBundleCommand({ ...opts, bundleDir }),
  );

exploreCmd
  .command("ci")
  .description("Fail-closed CI wrapper for explore status, report, JSON export, and SARIF export")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Explore run id (default: latest explore run for the project)")
  .option(
    "--min-severity <sev>",
    "Minimum accepted finding severity for the CI failure gate (default: LOW)",
  )
  .option(
    "--out-dir <path>",
    "Directory for CI JSON/SARIF exports (default: data/<project>/ci/<runId>)",
  )
  .option("--no-fail-on-accepted-findings", "Only fail when explore artifacts are invalid")
  .option("--no-report", "Skip run-scoped report generation")
  .option("--no-export-json", "Skip run-scoped JSON export")
  .option("--no-export-sarif", "Skip run-scoped SARIF export")
  .option("--no-junit", "Skip JUnit XML output")
  .action(exploreCiCommand);

addExploreOptions(
  exploreCmd
    .command("retry")
    .description("Retry failed or missing focused attempts from an existing explore run")
    .option("--run-id <id>", "Explore run id (default: latest explore run for the project)")
    .option("--all", "Retry all selected attempts instead of only failed or missing attempts"),
).action(exploreRetryCommand);

program
  .command("report")
  .description("Generate a markdown + JSON report from current analysis state.")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Filter to a specific run's results")
  .action(reportCommand);

program
  .command("revalidate")
  .description("Re-check existing findings for false positives")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Resume a specific revalidation run")
  .option(
    "--agent <type>",
    "Agent plugin type: codex or claude (default: defaultAgent in deepsec.config.ts, else codex)",
  )
  .option(
    "--model <model>",
    "Model to use (default: claude-opus-4-8 for claude, gpt-5.5 for codex)",
  )
  .option("--max-turns <n>", "Max conversation turns per batch (default: 150)", parseInt)
  .option(
    "--min-severity <sev>",
    "Only revalidate findings at this severity or above (CRITICAL, HIGH, MEDIUM, HIGH_BUG, BUG)",
  )
  .option("--force", "Re-check already-validated findings")
  .option("--limit <n>", "Max files to revalidate", parseInt)
  .option("--concurrency <n>", "Parallel batches (default: cores - 1)", parseInt)
  .option("--batch-size <n>", "Files per revalidation batch (default: 5)", parseInt)
  .option("--filter <prefix>", "Only revalidate files matching path prefix")
  .option("--root <path>", "Override rootPath from project.json (for sandbox execution)")
  .option("--manifest <path>", "JSON file with array of file paths to revalidate")
  .option("--only-slugs <csv>", "Only revalidate findings with one of these vulnSlugs")
  .option("--skip-slugs <csv>", "Skip findings with any of these vulnSlugs")
  .action(revalidateCommand);

program
  .command("enrich")
  .description("Enrich files with git history + ownership oracle")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--filter <prefix>", "Only enrich files matching path prefix")
  .option(
    "--min-severity <sev>",
    "Only enrich files with a finding at this severity or above (CRITICAL, HIGH, MEDIUM, HIGH_BUG, BUG, LOW)",
  )
  .option("--force", "Re-enrich already-enriched files")
  .option("--concurrency <n>", "Parallel ownership oracle requests (default: cores - 1)", parseInt)
  .action(enrichCommand);

program
  .command("triage")
  .description("Classify findings by priority (P0/P1/P2/skip) — lightweight, no code reading")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--severity <sev>", "Severity to triage (default: MEDIUM)", "MEDIUM")
  .option("--model <model>", "Model to use (default: claude-sonnet-4-6 — cheaper)")
  .option("--force", "Re-triage already-triaged findings")
  .option("--limit <n>", "Max findings to triage", parseInt)
  .option("--concurrency <n>", "Parallel triage batches (default: cores - 1)", parseInt)
  .action(triageCommand);

program
  .command("status")
  .description("Show current state of the project mirror")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .action(statusCommand);

program
  .command("export")
  .description("Export findings as JSON, SARIF, or a directory of per-finding markdown files")
  .option("--format <kind>", "Output format: json (default), sarif, or md-dir", "json")
  .option("--project-id <csv>", "Comma-separated project IDs (omit for all)")
  .option(
    "--min-severity <sev>",
    "Only export findings at this severity or above (CRITICAL, HIGH, MEDIUM, HIGH_BUG, BUG, LOW)",
  )
  .option(
    "--only-severity <sev>",
    "Only export findings at this exact severity (CRITICAL, HIGH, MEDIUM, HIGH_BUG, BUG, LOW)",
  )
  .option("--discovered-today", "Only findings whose most recent analysis was today (local time)")
  .option(
    "--since <iso>",
    "Only findings whose most recent analysis was on/after this ISO timestamp",
  )
  .option("--run-id <id>", "Only export findings produced by this run")
  .option("--only-true-positive", "Only findings revalidated as true-positive")
  .option(
    "--include-resolved",
    "Include findings revalidated as fixed / false-positive / accepted-risk (hidden by default)",
  )
  .option(
    "--exclude-false-positive",
    "Deprecated — false-positive is now hidden by default; this flag is a no-op",
  )
  .option("--only-slugs <csv>", "Only export findings with these vulnSlugs")
  .option("--skip-slugs <csv>", "Drop findings with these vulnSlugs")
  .option("--require-owner", "Drop findings that have no ownership data (no assignee, no teams)")
  .option(
    "--only-agent <type>",
    "Only export findings produced by this agent backend (e.g. codex, claude)",
  )
  .option(
    "--only-marker <n>",
    "Only export findings produced under this --reinvestigate wave marker",
  )
  .option(
    "--out <path>",
    "Output path. JSON/SARIF formats: file (default: stdout). md-dir format: directory (required).",
  )
  .action(exportCommand);

program
  .command("metrics")
  .description("Report findings metrics across all projects (or one project)")
  .option("--project-id <id>", "Project identifier (omit for all projects)")
  .option("--min-severity <sev>", "Minimum severity to include (default: LOW)")
  .action(metricsCommand);

const sandboxCmd = program
  .command("sandbox <command>")
  .description(
    "Run a deepsec command on Vercel Sandbox microVMs. Sandbox-level options (--sandboxes, --vcpus, --detach, etc.) are parsed; all other options are passed through to the subcommand.",
  )
  .allowUnknownOption()
  .allowExcessArguments(true)
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--sandboxes <n>", "Number of parallel sandboxes (default: 1)", parseInt)
  .option("--vcpus <n>", "vCPUs per sandbox (default: 2, max: 8)", parseInt)
  .option("--detach", "Launch sandboxes and exit immediately (collect results later)")
  .option("--run-id <id>", "Run ID for status/collect commands")
  .option("--snapshot-id <id>", "Restore from existing snapshot")
  .option("--save-snapshot", "Snapshot after setup for future reuse")
  .option("--keep-alive", "Don't stop sandboxes after completion")
  .option("--timeout <ms>", "Sandbox timeout in ms (default: 5 hours)", parseInt)
  .action((subcommand: string, opts: Record<string, unknown>) => {
    // Commander puts unknown options into .args on the Command object
    const unknownArgs = sandboxCmd.args.slice(1); // skip the subcommand itself
    return sandboxCommand(subcommand, { ...opts, args: unknownArgs } as Parameters<
      typeof sandboxCommand
    >[1]);
  });

const sandboxAllCmd = program
  .command("sandbox-all <command>")
  .description(
    "Run a deepsec command across ALL projects on Vercel Sandbox microVMs, allocating sandboxes proportionally",
  )
  .allowUnknownOption()
  .allowExcessArguments(true)
  .option("--sandboxes <n>", "Total sandboxes to distribute (default: 10)", parseInt)
  .option("--vcpus <n>", "vCPUs per sandbox (default: auto from concurrency, max: 8)", parseInt)
  .option("--timeout <ms>", "Sandbox timeout in ms (default: 5 hours)", parseInt)
  .action((subcommand: string, opts: Record<string, unknown>) => {
    const unknownArgs = sandboxAllCmd.args.slice(1);
    return sandboxAllCommand(subcommand, { ...opts, args: unknownArgs } as Parameters<
      typeof sandboxAllCommand
    >[1]);
  });

/**
 * Surface error messages cleanly. Stack traces are noise for user-facing
 * failures (bad input, missing config, network errors). Set
 * `DEEPSEC_DEBUG=1` to see them when debugging.
 */
function printFatal(err: unknown): never {
  const verbose = process.env.DEEPSEC_DEBUG === "1";
  console.error(`\n${err instanceof Error ? err.message : err}`);
  if (verbose && err instanceof Error && err.stack) {
    console.error(err.stack);
  } else if (!verbose) {
    console.error("\n(set DEEPSEC_DEBUG=1 for a stack trace)");
  }
  process.exit(1);
}

process.on("unhandledRejection", printFatal);
process.on("uncaughtException", printFatal);

async function main() {
  // Expand AI_GATEWAY_API_KEY (or fall back to a Vercel OIDC token) into
  // the per-SDK env vars before any command handler instantiates an agent.
  // Must run before loadConfig in case the user's deepsec.config.ts reads
  // these vars at module load.
  await applyAiGatewayDefaults();
  await loadConfig();
  // Plugins may register their own subcommands.
  for (const register of getRegistry().commands) {
    register(program);
  }
  await program.parseAsync();
}

main();
