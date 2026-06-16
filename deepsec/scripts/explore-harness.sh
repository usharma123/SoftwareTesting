#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PROJECT_ID="${PROJECT_ID:-}"
TARGET_ROOT="${TARGET_ROOT:-}"
PROFILE="${PROFILE:-java11-gradle}"
RUNTIME="${RUNTIME:-runsc}"
MODEL="${MODEL:-anthropic/claude-opus-4.8}"
RANK_MODEL="${RANK_MODEL:-}"
LIMIT="${LIMIT:-3}"
CONCURRENCY="${CONCURRENCY:-1}"
MAX_TURNS="${MAX_TURNS:-40}"
MAX_TOKENS="${MAX_TOKENS:-200000}"
MAX_COST_USD="${MAX_COST_USD:-25}"
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
RANK_MODEL_EXPLICIT=0

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
  --model <name>             OpenRouter focused-attempt model.
  --rank-model <name>        OpenRouter ranking model. Default: --model value
  --limit <n>                Ranked files to explore. Default: 3
  --concurrency <n>          Focused attempts in parallel. Default: 1
  --max-turns <n>            Max model turns per attempt. Default: 40
  --max-tokens <n>           Stop before next model call after this token count.
  --max-cost-usd <n>         Stop before next model call after this reported cost.
  --min-severity <sev>       CI/finding gate severity. Default: MEDIUM
  --data-root <path>         Data root for this run. Default: .deepsec-explore-runs/<project>-<timestamp>
  --out-dir <path>           CI/evidence output dir. Default: <data-root>/<project>/ci/<runId>
  --stub-model               Use deterministic local model responses for harness testing.
  --live-model-check         Let doctor spend a tiny OpenRouter model probe.
  --skip-setup               Do not rebuild the local explore image.
  --force-setup              Rebuild the local explore image even if it exists.
  --skip-doctor              Do not run preflight checks before explore.
  --full-doctor              Include target-root container preflight before explore.
  --verify-manifest          Run standalone manifest verification before bundling.
  --include-attempts         Copy raw run/attempt artifacts into the evidence bundle.
  --no-include-attempts      Keep the evidence bundle compact. This is the default.
  --fail-on-findings         Exit non-zero when accepted findings at --min-severity are present.
  -h, --help                 Show this help.

Environment variables with matching names also work, for example:
  PROJECT_ID=prowide-core TARGET_ROOT=../lib-testing/prowide-core scripts/explore-harness.sh
EOF
}

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
    --rank-model)
      RANK_MODEL="${2:?missing value for --rank-model}"
      RANK_MODEL_EXPLICIT=1
      shift 2
      ;;
    --limit)
      LIMIT="${2:?missing value for --limit}"
      shift 2
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

if [[ -z "$RANK_MODEL" ]]; then
  RANK_MODEL="$MODEL"
fi

slug="${PROJECT_ID:-deepsec}"
slug="${slug//[^a-zA-Z0-9_.-]/-}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

if [[ -z "$DATA_ROOT" ]]; then
  DATA_ROOT="$ROOT_DIR/.deepsec-explore-runs/${slug}-${timestamp}"
fi
mkdir -p "$DATA_ROOT"

if [[ -f "$ROOT_DIR/packages/deepsec/dist/cli.mjs" ]]; then
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
  --model "$MODEL"
  --rank-model "$RANK_MODEL"
  --limit "$LIMIT"
  --concurrency "$CONCURRENCY"
  --max-turns "$MAX_TURNS"
  --max-tokens "$MAX_TOKENS"
  --max-cost-usd "$MAX_COST_USD"
)
if [[ "$STUB_MODEL" == "1" ]]; then
  common_opts+=(--stub-model)
fi

echo "DeepSec explore harness"
echo "  repo:      $ROOT_DIR"
echo "  project:   ${PROJECT_ID:-auto}"
echo "  root:      ${TARGET_ROOT:-config default}"
echo "  data root: $DATA_ROOT"
echo

if [[ "$SKIP_SETUP" == "1" ]]; then
  echo "==> Skipping local explore image setup"
elif [[ "$FORCE_SETUP" != "1" ]] && command -v docker >/dev/null 2>&1 && docker image inspect "$explore_image" >/dev/null 2>&1; then
  echo "==> Reusing local explore image $explore_image"
else
  echo "==> Building local explore image $explore_image"
  DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore setup --profile "$PROFILE"
fi

if [[ "$SKIP_DOCTOR" != "1" ]]; then
  doctor_opts=(
    --profile "$PROFILE"
    --runtime "$RUNTIME"
    --model "$MODEL"
    --rank-model "$RANK_MODEL"
  )
  if [[ "$STUB_MODEL" == "1" ]]; then
    doctor_opts+=(--stub-model)
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
  DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore doctor "${doctor_opts[@]}"
fi

echo "==> Running focused exploration"
DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore run "${common_opts[@]}"

list_opts=(--json)
if [[ -n "$PROJECT_ID" ]]; then
  list_opts+=(--project-id "$PROJECT_ID")
fi
list_json="$(DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore list "${list_opts[@]}")"
run_id="$(node -e 'const fs=require("node:fs"); const list=JSON.parse(fs.readFileSync(0,"utf8")); const run=list.runs && list.runs[0]; if (!run || !run.runId) process.exit(1); process.stdout.write(run.runId);' <<<"$list_json")"
project_id="$(node -e 'const fs=require("node:fs"); const list=JSON.parse(fs.readFileSync(0,"utf8")); if (!list.projectId) process.exit(1); process.stdout.write(list.projectId);' <<<"$list_json")"

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$DATA_ROOT/$project_id/ci/$run_id"
fi
manifest_path="$OUT_DIR/manifest.json"
bundle_dir="$OUT_DIR/evidence-bundle"

echo "==> Verifying run artifacts"
DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore status \
  --project-id "$project_id" \
  --run-id "$run_id"

echo "==> Writing CI artifacts"
ci_opts=(--project-id "$project_id" --run-id "$run_id" --min-severity "$MIN_SEVERITY" --out-dir "$OUT_DIR")
if [[ "$FAIL_ON_ACCEPTED_FINDINGS" != "1" ]]; then
  ci_opts+=(--no-fail-on-accepted-findings)
fi
DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore ci "${ci_opts[@]}"

echo "==> Writing evidence manifest"
manifest_opts=(--project-id "$project_id" --run-id "$run_id" --out "$manifest_path" --require-report --require-ci)
if [[ "$FAIL_ON_ACCEPTED_FINDINGS" == "1" ]]; then
  manifest_opts+=(--fail-on-accepted-findings --min-severity "$MIN_SEVERITY")
fi
DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore manifest "${manifest_opts[@]}"
if [[ "$VERIFY_MANIFEST" == "1" ]]; then
  echo "==> Verifying evidence manifest"
  DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore verify-manifest "$manifest_path"
fi

echo "==> Creating and verifying portable evidence bundle"
bundle_opts=(--out-dir "$bundle_dir" --force)
if [[ "$INCLUDE_ATTEMPTS" == "1" ]]; then
  bundle_opts+=(--include-attempts)
fi
DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore bundle "$manifest_path" "${bundle_opts[@]}"
DEEPSEC_DATA_ROOT="$DATA_ROOT" "${DEEPSEC_CLI[@]}" explore verify-bundle "$bundle_dir"

cat <<EOF

DeepSec explore harness complete.
  project:   $project_id
  runId:     $run_id
  data root: $DATA_ROOT
  manifest:  $manifest_path
  bundle:    $bundle_dir
EOF
