# Local gVisor Explore

`deepsec explore` is a local CLI harness for Mythos-style security exploration:

1. rank production-relevant files from 1 to 5,
2. run one focused agent attempt per selected file,
3. execute all dynamic repro commands inside a local gVisor container,
4. validate any reported bug,
5. write artifacts under `data/<projectId>/explore/<runId>`, and
6. merge analyzed file records into the existing `report` and `export` surfaces.

Existing `scan`, `process`, and `revalidate` behavior is unchanged.

## Requirements

- Docker with the `runsc` runtime registered.
- Local image `ubuntu:22.04`.
- Local image `deepsec-explore-java11-gradle:local`, built by setup.
- A host Gradle cache with `~/.gradle/caches/modules-2` and `~/.gradle/wrapper/dists`.
- `OPENROUTER_API_KEY` for direct OpenRouter Responses API calls.

`explore` does not use Vercel AI Gateway. Set `OPENROUTER_BASE_URL` only when using an OpenRouter-compatible endpoint; it defaults to `https://openrouter.ai/api/v1`.

Useful OpenRouter knobs:

```sh
export OPENROUTER_API_KEY=...
export OPENROUTER_MAX_OUTPUT_TOKENS=4096
export OPENROUTER_TIMEOUT_MS=240000
```

For expensive models such as `anthropic/claude-opus-4.8`, reduce `OPENROUTER_MAX_OUTPUT_TOKENS` if OpenRouter reports credit reservation failures.

DeepSec asks OpenRouter for structured JSON responses: strict JSON Schema for file ranking and JSON-object mode for focused agent/validation turns. If a provider rejects `response_format`, DeepSec retries that request without it and relies on the canonical JSON prompt plus local parser validation/repair.

## Contributor Harness Script

Contributors can run the local setup, preflight, exploration, CI artifact
generation, manifest creation, and evidence-bundle verification through the
repo script:

```sh
PROJECT_ID=prowide-core \
TARGET_ROOT=../lib-testing/prowide-core \
  ./scripts/explore-harness.sh
```

The same flow is available through Make:

```sh
make explore-harness PROJECT_ID=prowide-core TARGET_ROOT=../lib-testing/prowide-core
```

Run these commands from the `deepsec/` repo root so `.env.local` or `.env`
is loaded by the CLI. Use `STUB_MODEL=1` or `--stub-model` to test the harness
without OpenRouter model calls. The script reuses an existing local explore
image by default; pass `FORCE_SETUP=1` or `--force-setup` when you need to
rebuild it.

For repeated runs, the default path keeps preflight and packaging compact:
`doctor` checks host prerequisites without the target-root container preflight,
the portable bundle omits raw attempt transcripts, and `bundle` performs the
manifest verification internally before copying artifacts. Use
`FULL_DOCTOR=1`, `INCLUDE_ATTEMPTS=1`, or `VERIFY_MANIFEST=1` when you need
those extra checks or forensic artifacts.

The script uses `packages/deepsec/dist/cli.mjs` when it exists. If the bundle
is missing, it falls back to `pnpm deepsec`, so fresh checkouts should run
`corepack enable`, `pnpm install`, and `pnpm bundle` first. This repo expects
Node 22 or newer and `pnpm@8.15.9`.

By default, the wrapper writes CI artifacts without failing on accepted
findings. Use `FAIL_ON_ACCEPTED_FINDINGS=1` with Make or `--fail-on-findings`
with the script when the harness run should fail on validated findings at or
above `MIN_SEVERITY`.

## Setup

Build the local Java/Gradle explore image:

```sh
pnpm deepsec explore setup --profile java11-gradle
```

The setup command builds `deepsec-explore-java11-gradle:local` from local `ubuntu:22.04` and downloads Temurin/OpenJDK 11 and 17 during setup. Exploration itself runs with no network in the target container.

## Doctor

Run the preflight without spending model tokens:

```sh
pnpm deepsec explore doctor \
  --project-id prowide-core \
  --root ../lib-testing/prowide-core \
  --profile java11-gradle \
  --runtime runsc
```

With `--root`, doctor creates a throwaway gVisor container, verifies Docker reports `runtime=runsc` and `network=none`, copies the target tree into an isolated temp directory, mounts a seeded per-run Gradle cache, and runs the offline Gradle preflight.

To verify the selected OpenRouter model before a long run, opt into a tiny paid API probe:

```sh
pnpm deepsec explore doctor \
  --project-id prowide-core \
  --root ../lib-testing/prowide-core \
  --profile java11-gradle \
  --runtime runsc \
  --model anthropic/claude-opus-4.8 \
  --rank-model anthropic/claude-opus-4.8 \
  --live-model-check
```

The live model check sends a 256-output-token JSON reachability request to each selected model. It is skipped unless `--live-model-check` is present.

## Stub Harness Test

To test the full local harness without OpenRouter credits, add `--stub-model`:

```sh
DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-stub \
pnpm deepsec explore \
  --project-id prowide-core \
  --root ../lib-testing/prowide-core \
  --profile java11-gradle \
  --runtime runsc \
  --stub-model \
  --limit 1 \
  --concurrency 1 \
  --max-turns 4
```

Stub mode still creates gVisor containers, verifies `runsc` and `network=none`,
runs commands through `docker exec`, and writes rankings, attempts, file records,
reports, and exports. It does not perform real security analysis.

## Run

```sh
DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-$(openssl rand -hex 4) \
pnpm deepsec explore \
  --project-id prowide-core \
  --root ../lib-testing/prowide-core \
  --profile java11-gradle \
  --runtime runsc \
  --model anthropic/claude-opus-4.8 \
  --rank-model anthropic/claude-opus-4.8 \
  --max-tokens 200000 \
  --max-cost-usd 25 \
  --limit 3 \
  --concurrency 1 \
  --max-turns 40
```

Every focused attempt starts a fresh container with:

- `--runtime=runsc`
- `--network=none`
- read-only container root filesystem
- `no-new-privileges`
- all Linux capabilities dropped
- pids, memory, and CPU limits
- no Docker socket
- no host source mount; source is copied into a temp tree
- common credential files and secret directories are excluded from that copy (`.env*`, SSH/AWS/GPG dirs, private key/cert/keystore files, token/credential-named files)
- sanitized environment
- bounded command timeout and output capture

The model API runs on the host. All file reads, builds, tests, debug edits, and local repro commands requested by the model run through `docker exec` inside the gVisor container. If a focused attempt reports a bug, `explore` starts a second fresh `runsc` container for validation and only merges findings that the validator marks reproducible and interesting.

Before the focused container is destroyed, DeepSec compares the copied `/workspace/target` tree against the original project root and writes `workspace-changes.json` for added, modified, or deleted source-relevant files. Captured previews are redacted and build outputs are ignored. This preserves local repro/debug edits without modifying the real project tree.

During each focused attempt, the CLI prints turn-level progress without dumping command output. The same bounded metadata is written to `data/<projectId>/explore/<runId>/attempts/<nn>/events.jsonl`, including model-request/model-response markers, provider-reported token/cost usage when available, command start/result status, final outcomes, durations, and output byte counts. Validation runs write the same bounded metadata to `validation-events.jsonl`. Full command output remains in `attempt.json`.

Ranking previews, model-requested command strings, and command outputs are redacted for common secret shapes before they are sent back to the model or written to artifacts. This protects accidental local output, but the target should still not intentionally print credentials during exploration.

Each completed run writes `integrity-manifest.json` with SHA-256 hashes for the run artifacts. `deepsec explore status` verifies that manifest and reports missing, changed, or unexpected artifacts.

For long Opus runs, pass `--max-tokens <n>` and/or `--max-cost-usd <n>`. Provider usage is only known after a response returns, so these caps stop the next model request after reported usage reaches the limit. The current attempt records budget exhaustion as an `attempt-error.json` failure and the run artifacts remain inspectable.

## Report and Export

Use the printed `runId` from explore:

```sh
DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore list --project-id prowide-core --json

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore status --project-id prowide-core --run-id <runId>

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore status --project-id prowide-core --run-id <runId> --fail-on-accepted-findings

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore status --project-id prowide-core --run-id <runId> --fail-on-accepted-findings --min-severity MEDIUM

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore attempt 01 --project-id prowide-core --run-id <runId>

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore findings --project-id prowide-core --run-id <runId> --json

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore artifacts --project-id prowide-core --run-id <runId> --json

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore audit --project-id prowide-core --run-id <runId> --json

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore manifest --project-id prowide-core --run-id <runId> --out /tmp/prowide-manifest.json

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore verify-manifest /tmp/prowide-manifest.json

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore evidence /tmp/prowide-manifest.json --out /tmp/prowide-evidence.md

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore bundle /tmp/prowide-manifest.json --out-dir /tmp/prowide-evidence-bundle --include-attempts

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore verify-bundle /tmp/prowide-evidence-bundle

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore ci --project-id prowide-core --run-id <runId> --min-severity MEDIUM

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec explore retry --project-id prowide-core --run-id <runId>

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec report --project-id prowide-core --run-id <runId>

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec export --project-id prowide-core --run-id <runId> --out /tmp/prowide-findings.json

DEEPSEC_DATA_ROOT=/tmp/deepsec-explore-prowide-... \
pnpm deepsec export --project-id prowide-core --run-id <runId> --format sarif --out /tmp/prowide-findings.sarif
```

`report --run-id` and `export --run-id` are finding-scoped. They keep the explored file surface for that run, but only include findings produced by the selected run.

`explore list` summarizes saved runs for a project, newest first. Add `--json`
for automation, and `--limit <n>` to cap output. Each entry includes status,
attempt counts, accepted findings, token/cost totals when present, and any
artifact problems found by the same validator used by `explore status`.

`explore status` verifies the run artifacts themselves: metadata consistency, ranking container runtime/network/hardening, ranking score validity, attempt count, per-attempt runtime/network/hardening, validation-container runtime/network/hardening for bug reports, source-copy exclusion counts, workspace-change capture, event logs, final outcomes, accepted finding title/severity/slug summaries, summary counters, integrity hashes, provider-reported usage totals, and consistency between ranking, attempt, and total usage buckets. Add `--json` for machine-readable CI output. Add `--fail-on-accepted-findings` to exit `2` when artifact checks pass but validated accepted findings are present. Pair it with `--min-severity <sev>` to fail only for accepted findings at or above that threshold. Artifact problems still exit `1`. `summary.json` stores ranking, attempt, and total usage buckets when OpenRouter returns token/cost metadata.

`explore attempt <attempt>` inspects one focused attempt by index (`1`) or
directory name (`01`). The human view shows the report, validation verdict,
workspace-change summary, and artifact paths without dumping full command
output. Add `--json` for structured output. Add `--transcript` with `--json`
only when a caller needs the full model/tool transcripts.

`explore findings` lists bug reports from one run. By default it includes only
accepted findings: validation verdict `true-positive`, reproducible, and
interesting. Add `--all` to include non-accepted bug reports, `--min-severity
<sev>` to filter by severity, and `--json` for automation.

`explore artifacts` is a read-only artifact index for scripts. It lists the
explore run files, per-attempt JSON/JSONL files, report paths, and default CI
output paths. Add `--json` to get a machine-readable index with `exists`,
`bytes`, and `sha256` for current files. Add `--no-hashes` when a caller only
needs paths and existence checks.

`explore audit` is a read-only automation checklist for one completed run. It
uses the same validator as `explore status`, then reports named gates for
artifact status, ranking, focused attempts, gVisor isolation, validation,
provider usage accounting, accepted findings, report artifacts, and CI
artifacts. Missing report/CI artifacts are warnings by default because they may
not exist until after `explore ci`; add `--require-report`, `--require-ci`, or
`--fail-on-warnings` to make those warnings fail. Add
`--fail-on-accepted-findings --min-severity <sev>` to use the same accepted
finding gate as CI. Exit codes are `1` for artifact/check failures, `2` for
accepted findings when that gate is enabled, and `0` otherwise.

`explore manifest` writes or prints a compact JSON run manifest for archival or
handoff between jobs. It includes the status summary, audit checklist, all bug
report summaries, artifact paths/hashes, output path, and recommended next
commands. Use `--out <path>` to write the manifest, `--json` to also print it,
and the same gate flags as `explore audit` when the manifest command should set
CI-style exit codes.

`explore verify-manifest <path>` verifies a saved manifest later. It checks that
every artifact recorded in the manifest has the same existence state, byte
count, and SHA-256 hash. This catches report/export/attempt artifacts that were
deleted or changed after the manifest was produced. Add `--json` for structured
automation output. It exits `1` on missing, unexpected, or changed artifacts.

`explore evidence <manifest>` renders a reviewer-friendly evidence summary from
a saved manifest. It verifies the manifest first, then summarizes the run,
audit state, accepted and rejected bug reports, report artifacts, CI artifacts,
artifact integrity problems, and recommended next commands. By default it emits
Markdown; add `--out <path>` to write the summary or `--json` for structured
automation output.

`explore bundle <manifest>` creates a portable evidence directory from a saved
manifest. It verifies the manifest first, then writes `manifest.json`,
`evidence.md`, `evidence.json`, `provenance.json`, `bundle-index.json`,
`checksums.sha256`, and copies report/CI artifacts with hashes. Add
`--include-attempts` when a reviewer also needs raw run and per-attempt
artifacts. It refuses to write into a non-empty directory unless `--force` is
passed.

`explore verify-bundle <bundle-dir>` verifies a copied evidence bundle without
requiring the original DeepSec data root. It reads `bundle-index.json`, checks
the included manifest/evidence/provenance files, and verifies byte counts plus
SHA-256 hashes for every core file and copied artifact. It also validates
`checksums.sha256` when present so standard checksum tools have the same bundle
inventory. It exits `1` when any bundled file is missing or changed.

`explore ci` is the one-command automation path. It verifies explore artifacts first and fails closed before generating downstream output if integrity or isolation checks are broken. When artifacts are clean, it generates the normal run-scoped report plus `findings.json`, `findings.sarif`, and `junit.xml` under `data/<projectId>/ci/<runId>/` by default. It always writes `ci-summary.json` in the CI output directory with the status result, intended exit code, output paths, problems, accepted-finding gate counts, compact accepted-finding details, and SHA-256 metadata for generated report/export/JUnit artifacts. It exits `1` for artifact problems, `2` for accepted findings at or above `--min-severity`, and `0` otherwise. Use `--no-report`, `--no-export-json`, `--no-export-sarif`, `--no-junit`, or `--no-fail-on-accepted-findings` to narrow the CI job.

If all attempts return `no-bug`, the run still records analyzed file records with zero findings so reports can show the explored surface.

If one focused attempt fails after ranking has completed, the run records `attempt-error.json` for that focus file and continues with the remaining selected files. The final command exits nonzero when any focused attempt failed, but `summary.json`, `explore status`, report, and export artifacts remain available for the completed attempts.

Use `deepsec explore retry --run-id <runId>` to rerun only failed or missing attempts from the saved rankings. Add `--all` when you intentionally want to rerun every selected focus file in the existing run.

Retry merges are run-id idempotent for each focus file. When a retry replaces a
previous accepted report with `no-bug`, `false-positive`, or `uncertain`, the
old finding from that same explore run is removed from the shared report/export
records before the new attempt history is written.

## Failure Modes

`explore` fails closed when:

- Docker does not register `runsc`,
- the local explore image is missing,
- Docker inspect reports a runtime other than `runsc`,
- Docker inspect reports any network mode other than `none`,
- Gradle offline dependencies are missing,
- the model asks for denied host, credential, network, or privileged commands.

OpenRouter `402` errors mean the key lacks enough credits for the requested model/output cap. Add credits or lower `OPENROUTER_MAX_OUTPUT_TOKENS`.
