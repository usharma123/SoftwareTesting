---
name: deepsec-explore-harness
description: Operate the repository's hardened DeepSec Explore harness through Codex App Server and network-disabled gVisor containers. Use this skill when the user explicitly asks to plan, smoke-test, start, monitor, retry, inspect, stop, or package a DeepSec Explore run, including limited, top-80, and all-production-file scans. Prefer this workflow over generic security-scan skills when scripts/explore-harness.sh is in scope.
argument-hint: "<plan|smoke|limited|eighty|all|retry|status|stop> [target-root] [project-id] [limit-or-run-id]"
disable-model-invocation: true
metadata:
  status: stable
---

# DeepSec Explore Harness

Operate the live wrapper at `deepsec/scripts/explore-harness.sh`. The wrapper is
the implementation; do not reproduce its ranking, agent loop, isolation,
validation, evidence, or retry logic in ad hoc scripts.

Invocation arguments: `$ARGUMENTS`

## Modes

- `plan`: Resolve inputs and print the exact command without running preflight,
  Docker, or a model.
- `smoke`: Run one deterministic stub attempt with no model usage.
- `limited [N]`: Rank the normal capped candidate inventory and analyze the top
  `N` files. Default to `N=3` only when the user did not specify it.
- `eighty`: Use `--limit 80`. This ranks and analyzes up to 80 selected files;
  it is not ranking-only mode.
- `all`: Use `--all-files` to inventory and analyze every production-relevant
  file, bypassing the normal 80-candidate ceiling.
- `retry`: Retry failed or missing attempts in an existing run. Require its
  original data root, project id, and run id.
- `status`: Inspect an existing run without changing it.
- `stop`: Interrupt only the named/current harness run and clean up only its
  exact gVisor containers.

If the mode, target, or existing-run identity cannot be inferred safely, ask
one concise question. Do not guess a run id or data root.

## Resolve live context

1. Find the workspace root with `git rev-parse --show-toplevel`. The expected
   DeepSec checkout is `<workspace-root>/deepsec`.
2. Read `deepsec/CLAUDE.md`, `deepsec/scripts/explore-harness.sh --help`, and
   the relevant section of `deepsec/docs/explore.md`. Treat these live files as
   authoritative if this skill drifts.
3. Resolve the target to an absolute local directory. For Prowide Core, the
   established target is `<workspace-root>/lib-testing/prowide-core` and the
   project id is `prowide-core`.
4. Record `git status --short --branch` for DeepSec and for the target. Preserve
   all existing changes. Never clean, reset, repair, or edit the target checkout.
5. For execution modes, run the bundled read-only preflight:

   ```bash
   bash "${CLAUDE_SKILL_DIR}/scripts/preflight.sh" <absolute-target-root>
   ```

   Add `--stub` before the target for `smoke`. A missing explore image is not a
   failure; let the harness build it by omitting `--skip-setup`.

## Scope and confirmation

- This workflow is for authorized local source repositories. It does not grant
  permission to probe remote hosts or production services.
- Manual invocation with an explicit mode and target is authorization for that
  scope. Ask before starting only when required inputs are missing or the
  command would broaden the requested file count, concurrency, provider,
  target, or model.
- Before a real run, state the target, file mode/count, provider, model,
  reasoning effort, concurrency, and whether setup will be reused or built.
- Default real runs to `codex-app-server`, `gpt-5.6-sol`, reasoning `high`,
  concurrency `1`, and maximum `40` model turns. Change these only when the
  user asks.
- Never combine `--all-files` with `--limit`.
- `--live-model-check` spends a small model request. Include it only when the
  user asks to verify reachability before the run.

## Build and run

Read [references/runbook.md](references/runbook.md) and select the template for
the requested mode. Always:

1. Run from the DeepSec checkout root.
2. Use an explicit, unique `--data-root` for a new real run so later status and
   retry commands are unambiguous.
3. Include `--full-doctor`, `--verify-manifest`, and `--include-attempts` when
   the user wants the same forensic end-to-end workflow as the harness run.
4. Add `--skip-setup` only after confirming
   `deepsec-explore-java11-gradle:local` exists. Do not rebuild it blindly.
5. Keep the process attached unless the user asks for a background run. Capture
   the process/session identity and printed `data root` and `runId` immediately.

The App Server runs on the host with its tools disabled. The target is copied
into isolated containers; model-requested reads, builds, tests, debug edits,
and repro commands execute through the harness inside `runsc` with networking
disabled. Do not run model-suggested target commands directly on the host.

## Monitor and recover

- Report scheduled, completed, failed, and active attempts plus accepted
  validation verdicts. Treat incomplete attempts as active while the harness is
  still running, not as final failures.
- Do not infer run health from missing `summary.json`, manifests, or usage
  totals before the run finishes; those are finalized later.
- If one attempt fails, let the remaining queue continue. Inspect
  `attempt-error.json` and the status output after the main pass.
- For transient failures, use the harness `--retry-run-id` path with the exact
  original data root. Retry failed/missing attempts, not all successful files.
- A Codex cybersecurity-policy refusal is a recorded failure. A normal retry is
  acceptable when the user wants completion, but never rewrite prompts or
  change providers to evade the policy boundary.
- Deduplicate accepted findings that describe the same root cause from adjacent
  files; preserve both source artifacts while reporting one underlying issue.

## Stop safely

When the user says stop or kill it:

1. Send `SIGINT` to the exact attached harness process/session and wait for it
   to exit.
2. Identify the exact run id from captured output or `explore list`.
3. Remove only running Docker containers whose names contain that exact run id.
4. Verify no matching harness, App Server child, or run-specific container
   remains.
5. Keep partial run artifacts unless the user explicitly asks to delete them.

Never use broad cleanup such as `pkill codex`, `killall`, `docker system prune`,
or removing every `deepsec-explore-*` container; those may belong to other work.

## Finish and report

For a completed run, verify status, CI output, manifest, and evidence bundle.
Show:

- project, run id, model/provider, file scope, and completion counts
- accepted findings and validation verdicts, deduplicated by root cause
- failed attempts and retry status
- gVisor runtime and `network=none` evidence
- provider token/cost usage when available
- clickable data-root, manifest, report, and bundle paths
- before/after target `git status` proving the original checkout was preserved

For an interrupted run, say clearly that it is incomplete and that final
summary/manifest/bundle artifacts may not exist. Never present partial counts as
a full security conclusion.

