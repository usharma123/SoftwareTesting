# DeepSec Explore Runbook

Use the live harness help as the source of truth. These templates encode the
current App Server and gVisor defaults without bypassing the wrapper.

Set these shell variables first:

```bash
WORKSPACE_ROOT="$(git rev-parse --show-toplevel)"
DEEPSEC_ROOT="$WORKSPACE_ROOT/deepsec"
TARGET_ROOT="/absolute/path/to/authorized-target"
PROJECT_ID="target-project-id"
DATA_ROOT="$DEEPSEC_ROOT/.deepsec-explore-runs/${PROJECT_ID}-$(date -u +%Y%m%dT%H%M%SZ)"
cd "$DEEPSEC_ROOT"
```

If `deepsec-explore-java11-gradle:local` exists, add `--skip-setup` to a run.
Otherwise omit it so setup builds the image.

## Smoke: no model usage

```bash
./scripts/explore-harness.sh \
  --project-id "$PROJECT_ID" \
  --root "$TARGET_ROOT" \
  --stub-model \
  --limit 1 \
  --concurrency 1 \
  --max-turns 4 \
  --data-root "$DATA_ROOT" \
  --full-doctor \
  --verify-manifest \
  --include-attempts
```

## Limited real run

Replace `3` with the requested limit. `--limit 80` is the top-80 mode.

```bash
./scripts/explore-harness.sh \
  --project-id "$PROJECT_ID" \
  --root "$TARGET_ROOT" \
  --model-provider codex-app-server \
  --model gpt-5.6-sol \
  --reasoning-effort high \
  --limit 3 \
  --concurrency 1 \
  --max-turns 40 \
  --data-root "$DATA_ROOT" \
  --full-doctor \
  --verify-manifest \
  --include-attempts
```

## All production-relevant files

```bash
./scripts/explore-harness.sh \
  --project-id "$PROJECT_ID" \
  --root "$TARGET_ROOT" \
  --model-provider codex-app-server \
  --model gpt-5.6-sol \
  --reasoning-effort high \
  --all-files \
  --concurrency 1 \
  --max-turns 40 \
  --data-root "$DATA_ROOT" \
  --full-doctor \
  --verify-manifest \
  --include-attempts
```

## Status and findings

These are read-only. Use the same data root that created the run.

```bash
DEEPSEC_DATA_ROOT="$DATA_ROOT" pnpm deepsec explore status \
  --project-id "$PROJECT_ID" --run-id "$RUN_ID" --json

DEEPSEC_DATA_ROOT="$DATA_ROOT" pnpm deepsec explore findings \
  --project-id "$PROJECT_ID" --run-id "$RUN_ID" --json

DEEPSEC_DATA_ROOT="$DATA_ROOT" pnpm deepsec explore audit \
  --project-id "$PROJECT_ID" --run-id "$RUN_ID" --json
```

During an active run, missing final summary/manifest files are expected. Use
attempt outcomes and event logs for progress, then rerun status after exit.

## Retry failed or missing attempts

Retry through the wrapper so it refreshes status, CI outputs, manifest, and the
evidence bundle after successful attempts:

```bash
./scripts/explore-harness.sh \
  --project-id "$PROJECT_ID" \
  --root "$TARGET_ROOT" \
  --model-provider codex-app-server \
  --model gpt-5.6-sol \
  --reasoning-effort high \
  --concurrency 1 \
  --max-turns 40 \
  --data-root "$DATA_ROOT" \
  --retry-run-id "$RUN_ID" \
  --full-doctor \
  --verify-manifest \
  --include-attempts
```

Do not pass `--all` to the underlying retry command unless the user explicitly
wants every successful attempt rerun too.

## Prowide Core examples

From the DeepSec checkout, Prowide is normally:

```bash
TARGET_ROOT="$(cd ../lib-testing/prowide-core && pwd)"
PROJECT_ID="prowide-core"
```

Top 80 uses the limited template with `--limit 80`. Full length uses the all-file
template with `--all-files`.

## Interpreting exit codes

- `0`: requested workflow completed.
- `1`: artifact/preflight/attempt failure; inspect status and attempt errors.
- `2`: accepted findings met a requested `--fail-on-findings` severity gate.
- `130`: interrupted by `SIGINT`; retain partial artifacts and perform exact-run
  container cleanup.

