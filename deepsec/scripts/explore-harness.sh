#!/usr/bin/env bash
set -euo pipefail

# Finder, Shortcuts, and some GUI-launched terminals inherit a minimal PATH on
# macOS. Include the standard Homebrew and Docker Desktop locations so the
# harness and its Node child processes resolve docker/codex consistently.
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/Applications/Docker.app/Contents/Resources/bin:${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}"

ROOT_DIR="${DEEPSEC_HARNESS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
if [[ "${DEEPSEC_HARNESS_NO_CHDIR:-0}" != "1" ]]; then
  cd "$ROOT_DIR"
fi

PROJECT_ID="${PROJECT_ID:-}"
TARGET_ROOT="${TARGET_ROOT:-}"
PROFILE="${PROFILE:-java11-gradle}"
RUNTIME="${RUNTIME:-runsc}"
MODEL_PROVIDER="${MODEL_PROVIDER:-codex-app-server}"
MODEL="${MODEL:-gpt-5.6-sol}"
RANK_MODEL="${RANK_MODEL:-}"
REASONING_EFFORT="${REASONING_EFFORT:-high}"
LIMIT="${LIMIT:-14}"
ALL_FILES="${ALL_FILES:-0}"
CONCURRENCY="${CONCURRENCY:-2}"
MAX_TURNS="${MAX_TURNS:-40}"
MAX_TOKENS="${MAX_TOKENS:-}"
MAX_COST_USD="${MAX_COST_USD:-}"
MIN_SEVERITY="${MIN_SEVERITY:-MEDIUM}"
DATA_ROOT="${DEEPSEC_DATA_ROOT:-}"
OUT_DIR="${OUT_DIR:-}"
STUB_MODEL="${STUB_MODEL:-0}"
LIVE_MODEL_CHECK="${LIVE_MODEL_CHECK:-0}"
SKIP_SETUP="${SKIP_SETUP:-0}"
FORCE_SETUP="${FORCE_SETUP:-0}"
SKIP_DOCTOR="${SKIP_DOCTOR:-0}"
FULL_DOCTOR="${FULL_DOCTOR:-0}"
VERIFY_MANIFEST="${VERIFY_MANIFEST:-0}"
INCLUDE_ATTEMPTS="${INCLUDE_ATTEMPTS:-0}"
FAIL_ON_ACCEPTED_FINDINGS="${FAIL_ON_ACCEPTED_FINDINGS:-0}"
OPEN_REPORT="${OPEN_REPORT:-1}"
RETRY_RUN_ID="${RETRY_RUN_ID:-}"
DEEPSEC_EVENT_STREAM="${DEEPSEC_EVENT_STREAM:-0}"
RANK_MODEL_EXPLICIT=0
CURRENT_PHASE="initialization"

usage() {
  cat <<'EOF'
Run the local DeepSec gVisor explore harness end to end.

Usage:
  scripts/explore-harness.sh --project-id <id> --root <target-root> [options]
  make explore-harness PROJECT_ID=<id> TARGET_ROOT=<target-root>

Options:
  --project-id <id>          DeepSec project id. Optional when config has one project.
  --root <path>              Target repository root for doctor/explore.
  --profile <name>           Explore profile. Default: java11-gradle
  --runtime <name>           Docker runtime. Default: runsc
  --model-provider <name>    Model transport. Default: codex-app-server
  --model <name>             Focused-attempt model. Default: gpt-5.6-sol
  --rank-model <name>        Ranking model. Default: --model value
  --reasoning-effort <name>  Codex reasoning effort. Default: high
  --limit <n>                Ranked files to explore. Default: 14
  --all-files                Explore every production-relevant file.
  --concurrency <n>          Focused attempts in parallel. Default: 2
  --max-turns <n>            Max model turns per attempt. Default: 40
  --max-tokens <n>           Optional stop-before-next-call token budget.
  --max-cost-usd <n>         Optional stop-before-next-call reported-cost budget.
  --min-severity <sev>       CI/finding gate severity. Default: MEDIUM
  --data-root <path>         Data root for this run. Default: .deepsec-explore-runs/<project>-<timestamp>
  --out-dir <path>           CI/evidence output dir. Default: <data-root>/<project>/ci/<runId>
  --stub-model               Use deterministic local model responses for harness testing.
  --live-model-check         Let doctor spend a tiny selected-model probe.
  --skip-setup               Do not rebuild the local explore image.
  --force-setup              Rebuild the local explore image even if it exists.
  --skip-doctor              Do not run preflight checks before explore.
  --full-doctor              Include target-root container preflight before explore.
  --verify-manifest          Run standalone manifest verification before bundling.
  --include-attempts         Copy raw run/attempt artifacts into the evidence bundle.
  --no-include-attempts      Keep the evidence bundle compact. This is the default.
  --fail-on-findings         Exit non-zero when accepted findings at --min-severity are present.
  --open-report              Open the generated markdown report. This is the default.
  --no-open-report           Do not open the generated markdown report.
  --retry-run-id <id>        Retry failed/missing attempts for an existing run, then refresh evidence.
  -h, --help                 Show this help.

Environment variables with matching names also work, for example:
  PROJECT_ID=prowide-core TARGET_ROOT=../lib-testing/prowide-core scripts/explore-harness.sh
EOF
}

emit_phase() {
  if [[ "$DEEPSEC_EVENT_STREAM" != "1" ]]; then
    return
  fi
  node -e '
    const [phase, status, detail] = process.argv.slice(1);
    const event = { kind: "harness-phase", at: new Date().toISOString(), phase, status };
    if (detail) event.detail = detail;
    process.stdout.write(`@@deepsec:event@@${JSON.stringify(event)}\n`);
  ' "$1" "$2" "${3:-}"
}

emit_harness_complete() {
  if [[ "$DEEPSEC_EVENT_STREAM" != "1" ]]; then
    return
  fi
  node -e '
    const [status, exitCode, detail, projectId, runId, dataRoot, manifest, bundle] = process.argv.slice(1);
    const event = {
      kind: "harness-complete",
      at: new Date().toISOString(),
      status,
      exitCode: Number(exitCode),
    };
    for (const [key, value] of Object.entries({ detail, projectId, runId, dataRoot, manifest, bundle })) {
      if (value) event[key] = value;
    }
    process.stdout.write(`@@deepsec:event@@${JSON.stringify(event)}\n`);
  ' "$1" "$2" "${3:-}" "${4:-}" "${5:-}" "${6:-}" "${7:-}" "${8:-}"
}

on_harness_exit() {
  local exit_code=$?
  if [[ "$exit_code" != "0" ]]; then
    emit_phase "$CURRENT_PHASE" "failed" "harness exited with code $exit_code"
    emit_harness_complete "failed" "$exit_code" "failed during $CURRENT_PHASE"
  fi
}
trap on_harness_exit EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-id)
      PROJECT_ID="${2:?missing value for --project-id}"
      shift 2
      ;;
    --root|--target-root)
      TARGET_ROOT="${2:?missing value for --root}"
      shift 2
      ;;
    --profile)
      PROFILE="${2:?missing value for --profile}"
      shift 2
      ;;
    --runtime)
      RUNTIME="${2:?missing value for --runtime}"
      shift 2
      ;;
    --model)
      MODEL="${2:?missing value for --model}"
      if [[ "$RANK_MODEL_EXPLICIT" == "0" ]]; then
        RANK_MODEL=""
      fi
      shift 2
      ;;
    --model-provider)
      MODEL_PROVIDER="${2:?missing value for --model-provider}"
      shift 2
      ;;
    --rank-model)
      RANK_MODEL="${2:?missing value for --rank-model}"
      RANK_MODEL_EXPLICIT=1
      shift 2
      ;;
    --reasoning-effort)
      REASONING_EFFORT="${2:?missing value for --reasoning-effort}"
      shift 2
      ;;
    --limit)
      LIMIT="${2:?missing value for --limit}"
      shift 2
      ;;
    --all-files)
      ALL_FILES=1
      shift
      ;;
    --concurrency)
      CONCURRENCY="${2:?missing value for --concurrency}"
      shift 2
      ;;
    --max-turns)
      MAX_TURNS="${2:?missing value for --max-turns}"
      shift 2
      ;;
    --max-tokens)
      MAX_TOKENS="${2:?missing value for --max-tokens}"
      shift 2
      ;;
    --max-cost-usd)
      MAX_COST_USD="${2:?missing value for --max-cost-usd}"
      shift 2
      ;;
    --min-severity)
      MIN_SEVERITY="${2:?missing value for --min-severity}"
      shift 2
      ;;
    --data-root)
      DATA_ROOT="${2:?missing value for --data-root}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:?missing value for --out-dir}"
      shift 2
      ;;
    --stub-model)
      STUB_MODEL=1
      shift
      ;;
    --live-model-check)
      LIVE_MODEL_CHECK=1
      shift
      ;;
    --skip-setup)
      SKIP_SETUP=1
      shift
      ;;
    --force-setup)
      FORCE_SETUP=1
      shift
      ;;
    --skip-doctor)
      SKIP_DOCTOR=1
      shift
      ;;
    --full-doctor)
      FULL_DOCTOR=1
      shift
      ;;
    --verify-manifest)
      VERIFY_MANIFEST=1
      shift
      ;;
    --include-attempts)
      INCLUDE_ATTEMPTS=1
      shift
      ;;
    --no-include-attempts)
      INCLUDE_ATTEMPTS=0
      shift
      ;;
    --fail-on-findings)
      FAIL_ON_ACCEPTED_FINDINGS=1
      shift
      ;;
    --open-report)
      OPEN_REPORT=1
      shift
      ;;
    --no-open-report)
      OPEN_REPORT=0
      shift
      ;;
    --retry-run-id)
      RETRY_RUN_ID="${2:?missing value for --retry-run-id}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "$RETRY_RUN_ID" && -z "$PROJECT_ID" ]]; then
  echo "--retry-run-id requires --project-id." >&2
  exit 2
fi

if [[ -z "$RANK_MODEL" ]]; then
  RANK_MODEL="$MODEL"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker CLI was not found." >&2
  echo "Install or start Docker Desktop, then rerun this script." >&2
  echo "Checked PATH: $PATH" >&2
  exit 1
fi

if [[ "$MODEL_PROVIDER" == "codex-app-server" && "$STUB_MODEL" != "1" ]] && ! command -v codex >/dev/null 2>&1; then
  echo "Codex CLI was not found, but --model-provider codex-app-server is selected." >&2
  echo "Install/login to Codex, or select another model provider." >&2
  echo "Checked PATH: $PATH" >&2
  exit 1
fi

# Direct runs without a config derive the same stable project id as the CLI.
# Doing it before the run also lets the harness address that project for the
# later list, status, CI, manifest, and bundle commands.
if [[ -z "$PROJECT_ID" && -n "$TARGET_ROOT" ]]; then
  PROJECT_ID="$(basename "${TARGET_ROOT%/}")"
  PROJECT_ID="${PROJECT_ID//[^a-zA-Z0-9_.-]/-}"
  PROJECT_ID="${PROJECT_ID:0:64}"
  while [[ -n "$PROJECT_ID" && "${PROJECT_ID:0:1}" != [a-zA-Z0-9] ]]; do
    PROJECT_ID="${PROJECT_ID:1}"
  done
  PROJECT_ID="${PROJECT_ID:-deepsec-target}"
fi

slug="${PROJECT_ID:-deepsec}"
slug="${slug//[^a-zA-Z0-9_.-]/-}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

if [[ -z "$DATA_ROOT" ]]; then
  DATA_ROOT="$ROOT_DIR/.deepsec-explore-runs/${slug}-${timestamp}"
fi
mkdir -p "$DATA_ROOT"

if [[ -n "${DEEPSEC_HARNESS_CLI:-}" ]]; then
  if [[ ! -f "$DEEPSEC_HARNESS_CLI" ]]; then
    echo "Packaged DeepSec CLI is missing: $DEEPSEC_HARNESS_CLI" >&2
    exit 1
  fi
  DEEPSEC_CLI=(node "$DEEPSEC_HARNESS_CLI")
elif [[ -f "$ROOT_DIR/packages/deepsec/dist/cli.mjs" ]]; then
  DEEPSEC_CLI=(node "$ROOT_DIR/packages/deepsec/dist/cli.mjs")
else
  if ! command -v pnpm >/dev/null 2>&1; then
    echo "packages/deepsec/dist/cli.mjs is missing and pnpm is not available." >&2
    echo "Run pnpm install && pnpm bundle, or install pnpm and re-run this script." >&2
    exit 1
  fi
  DEEPSEC_CLI=(pnpm --dir "$ROOT_DIR" deepsec)
fi

explore_image="deepsec-explore-${PROFILE}:local"

common_opts=()
if [[ -n "$PROJECT_ID" ]]; then
  common_opts+=(--project-id "$PROJECT_ID")
fi
if [[ -n "$TARGET_ROOT" ]]; then
  common_opts+=(--root "$TARGET_ROOT")
fi
common_opts+=(
  --profile "$PROFILE"
  --runtime "$RUNTIME"
  --model-provider "$MODEL_PROVIDER"
  --model "$MODEL"
  --rank-model "$RANK_MODEL"
  --reasoning-effort "$REASONING_EFFORT"
  --concurrency "$CONCURRENCY"
  --max-turns "$MAX_TURNS"
)
if [[ "$ALL_FILES" == "1" ]]; then
  common_opts+=(--all-files)
else
  common_opts+=(--limit "$LIMIT")
fi
if [[ -n "$MAX_TOKENS" ]]; then
  common_opts+=(--max-tokens "$MAX_TOKENS")
fi
if [[ -n "$MAX_COST_USD" ]]; then
  common_opts+=(--max-cost-usd "$MAX_COST_USD")
fi
if [[ "$STUB_MODEL" == "1" ]]; then
  common_opts+=(--stub-model)
fi

echo "DeepSec explore harness"
echo "  repo:      $ROOT_DIR"
echo "  project:   ${PROJECT_ID:-auto}"
echo "  root:      ${TARGET_ROOT:-config default}"
echo "  provider:  $MODEL_PROVIDER"
echo "  model:     $MODEL ($REASONING_EFFORT)"
echo "  files:     $([[ "$ALL_FILES" == "1" ]] && echo all || echo "$LIMIT")"
echo "  data root: $DATA_ROOT"
echo

CURRENT_PHASE="setup"
if [[ "$SKIP_SETUP" == "1" ]]; then
  echo "==> Skipping local explore image setup"
  emit_phase "setup" "skipped" "local image setup disabled"
elif [[ "$FORCE_SETUP" != "1" ]] && command -v docker >/dev/null 2>&1 && docker image inspect "$explore_image" >/dev/null 2>&1; then
  echo "==> Reusing local explore image $explore_image"
  emit_phase "setup" "complete" "reusing $explore_image"
else
  echo "==> Building local explore image $explore_image"
  emit_phase "setup" "start" "building $explore_image"
  DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore setup --profile "$PROFILE"
  emit_phase "setup" "complete" "built $explore_image"
fi

CURRENT_PHASE="doctor"
if [[ "$SKIP_DOCTOR" != "1" ]]; then
  doctor_opts=(
    --profile "$PROFILE"
    --runtime "$RUNTIME"
    --model-provider "$MODEL_PROVIDER"
    --model "$MODEL"
    --rank-model "$RANK_MODEL"
    --reasoning-effort "$REASONING_EFFORT"
  )
  if [[ "$STUB_MODEL" == "1" ]]; then
    doctor_opts+=(--stub-model)
  fi
  if [[ "$ALL_FILES" == "1" ]]; then
    doctor_opts+=(--all-files)
  fi
  if [[ "$FULL_DOCTOR" == "1" ]]; then
    if [[ -n "$PROJECT_ID" ]]; then
      doctor_opts+=(--project-id "$PROJECT_ID")
    fi
    if [[ -n "$TARGET_ROOT" ]]; then
      doctor_opts+=(--root "$TARGET_ROOT")
    fi
  fi
  if [[ "$LIVE_MODEL_CHECK" == "1" ]]; then
    doctor_opts+=(--live-model-check)
  fi
  echo "==> Running preflight"
  emit_phase "doctor" "start" "checking runtime, image, cache, and model"
  DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore doctor "${doctor_opts[@]}"
  emit_phase "doctor" "complete" "preflight passed"
else
  emit_phase "doctor" "skipped" "preflight disabled"
fi

CURRENT_PHASE="exploration"
emit_phase "exploration" "start" "$([[ -n "$RETRY_RUN_ID" ]] && echo retrying failed attempts || echo ranking and exploring selected files)"
if [[ -n "$RETRY_RUN_ID" ]]; then
  echo "==> Retrying failed exploration attempts"
  DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore retry \
    --project-id "$PROJECT_ID" \
    --run-id "$RETRY_RUN_ID" \
    "${common_opts[@]}"
  run_id="$RETRY_RUN_ID"
  project_id="$PROJECT_ID"
else
  echo "==> Running focused exploration"
  DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore run "${common_opts[@]}"

  list_opts=(--json)
  if [[ -n "$PROJECT_ID" ]]; then
    list_opts+=(--project-id "$PROJECT_ID")
  fi
  list_json="$(DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore list "${list_opts[@]}")"
  run_id="$(node -e 'const fs=require("node:fs"); const list=JSON.parse(fs.readFileSync(0,"utf8")); const run=list.runs && list.runs[0]; if (!run || !run.runId) process.exit(1); process.stdout.write(run.runId);' <<<"$list_json")"
  project_id="$(node -e 'const fs=require("node:fs"); const list=JSON.parse(fs.readFileSync(0,"utf8")); if (!list.projectId) process.exit(1); process.stdout.write(list.projectId);' <<<"$list_json")"
fi
emit_phase "exploration" "complete" "run $run_id"

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$DATA_ROOT/$project_id/ci/$run_id"
fi
manifest_path="$OUT_DIR/manifest.json"
bundle_dir="$OUT_DIR/evidence-bundle"

echo "==> Verifying run artifacts"
CURRENT_PHASE="verification"
emit_phase "verification" "start" "checking run artifacts and isolation metadata"
DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore status \
  --project-id "$project_id" \
  --run-id "$run_id"
emit_phase "verification" "complete" "run artifacts verified"

echo "==> Writing CI artifacts"
CURRENT_PHASE="ci"
emit_phase "ci" "start" "writing report, JSON, SARIF, and JUnit outputs"
ci_opts=(--project-id "$project_id" --run-id "$run_id" --min-severity "$MIN_SEVERITY" --out-dir "$OUT_DIR")
if [[ "$FAIL_ON_ACCEPTED_FINDINGS" != "1" ]]; then
  ci_opts+=(--no-fail-on-accepted-findings)
fi
if [[ "$OPEN_REPORT" == "1" ]]; then
  ci_opts+=(--open-report)
fi
DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore ci "${ci_opts[@]}"
emit_phase "ci" "complete" "CI outputs written"

echo "==> Writing evidence manifest"
CURRENT_PHASE="manifest"
emit_phase "manifest" "start" "hashing evidence manifest"
manifest_opts=(--project-id "$project_id" --run-id "$run_id" --out "$manifest_path" --require-report --require-ci)
if [[ "$FAIL_ON_ACCEPTED_FINDINGS" == "1" ]]; then
  manifest_opts+=(--fail-on-accepted-findings --min-severity "$MIN_SEVERITY")
fi
DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore manifest "${manifest_opts[@]}"
emit_phase "manifest" "complete" "$manifest_path"
if [[ "$VERIFY_MANIFEST" == "1" ]]; then
  echo "==> Verifying evidence manifest"
  emit_phase "manifest" "start" "verifying evidence manifest"
  DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore verify-manifest "$manifest_path"
  emit_phase "manifest" "complete" "evidence manifest verified"
fi

echo "==> Creating and verifying portable evidence bundle"
CURRENT_PHASE="bundle"
emit_phase "bundle" "start" "creating portable evidence bundle"
bundle_opts=(--out-dir "$bundle_dir" --force)
if [[ "$INCLUDE_ATTEMPTS" == "1" ]]; then
  bundle_opts+=(--include-attempts)
fi
DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore bundle "$manifest_path" "${bundle_opts[@]}"
DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore verify-bundle "$bundle_dir"
emit_phase "bundle" "complete" "$bundle_dir"

cat <<EOF

DeepSec explore harness complete.
  project:   $project_id
  runId:     $run_id
  data root: $DATA_ROOT
  report:    $DATA_ROOT/$project_id/reports/report-$run_id.md
  manifest:  $manifest_path
  bundle:    $bundle_dir
EOF
CURRENT_PHASE="complete"
emit_harness_complete "complete" "0" "DeepSec explore harness complete" "$project_id" "$run_id" "$DATA_ROOT" "$manifest_path" "$bundle_dir"
