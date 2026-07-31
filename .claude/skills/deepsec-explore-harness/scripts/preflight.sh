#!/usr/bin/env bash
set -euo pipefail

stub=0
if [[ "${1:-}" == "--stub" ]]; then
  stub=1
  shift
fi

if [[ $# -ne 1 ]]; then
  echo "usage: preflight.sh [--stub] <target-root>" >&2
  exit 2
fi

skill_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace_root="$(git -C "$skill_dir" rev-parse --show-toplevel)"
deepsec_root="$workspace_root/deepsec"
target_root="$1"

if [[ "$target_root" != /* ]]; then
  if [[ -d "$PWD/$target_root" ]]; then
    target_root="$PWD/$target_root"
  elif [[ -d "$deepsec_root/$target_root" ]]; then
    target_root="$deepsec_root/$target_root"
  elif [[ -d "$workspace_root/$target_root" ]]; then
    target_root="$workspace_root/$target_root"
  fi
fi

if [[ ! -d "$target_root" ]]; then
  echo "target root is not a directory: $target_root" >&2
  exit 1
fi
target_root="$(cd "$target_root" && pwd)"

harness="$deepsec_root/scripts/explore-harness.sh"
if [[ ! -x "$harness" ]]; then
  echo "DeepSec harness is missing or not executable: $harness" >&2
  exit 1
fi

help="$($harness --help)"
required_flags=(
  --model-provider
  --model
  --reasoning-effort
  --limit
  --all-files
  --full-doctor
  --retry-run-id
)
for flag in "${required_flags[@]}"; do
  if ! grep -Fq -- "$flag" <<<"$help"; then
    echo "harness interface drift: missing $flag" >&2
    exit 1
  fi
done

if ! command -v node >/dev/null 2>&1; then
  echo "node is required" >&2
  exit 1
fi
node_major="$(node -p 'Number(process.versions.node.split(".")[0])')"
if (( node_major < 22 )); then
  echo "Node 22 or newer is required; found $(node --version)" >&2
  exit 1
fi

if [[ ! -f "$deepsec_root/packages/deepsec/dist/cli.mjs" ]] && ! command -v pnpm >/dev/null 2>&1; then
  echo "the bundled CLI is missing and pnpm is unavailable" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "the Docker daemon is not reachable" >&2
  exit 1
fi
if ! docker info --format '{{json .Runtimes}}' | grep -Fq '"runsc"'; then
  echo "Docker runtime runsc is not registered" >&2
  exit 1
fi

if [[ "$stub" != "1" ]]; then
  if ! command -v codex >/dev/null 2>&1; then
    echo "codex is required for the app-server backend" >&2
    exit 1
  fi
  if ! codex login status >/dev/null 2>&1; then
    echo "Codex is not logged in; run: codex login" >&2
    exit 1
  fi
fi

image_status="missing; the harness will build it"
if docker image inspect deepsec-explore-java11-gradle:local >/dev/null 2>&1; then
  image_status="present; --skip-setup is safe"
fi

printf 'workspace_root=%s\n' "$workspace_root"
printf 'deepsec_root=%s\n' "$deepsec_root"
printf 'target_root=%s\n' "$target_root"
printf 'node=%s\n' "$(node --version)"
printf 'provider=%s\n' "$([[ "$stub" == "1" ]] && echo stub || echo codex-app-server)"
printf 'runsc=registered\n'
printf 'explore_image=%s\n' "$image_status"

