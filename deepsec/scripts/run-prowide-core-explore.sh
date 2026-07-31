#!/usr/bin/env bash
set -euo pipefail

DEEPSEC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ROOT="$DEEPSEC_ROOT/../lib-testing/prowide-core"

if [[ ! -d "$TARGET_ROOT" ]]; then
  echo "Target repository not found: $TARGET_ROOT" >&2
  exit 1
fi

# The Codex app-server provider reuses the local `codex` login, so this
# launcher needs no separate model API key.
exec "$DEEPSEC_ROOT/scripts/explore-harness.sh" \
  --project-id prowide-core \
  --root "$TARGET_ROOT" \
  --model-provider codex-app-server \
  --runtime runsc \
  --model gpt-5.6-sol \
  --reasoning-effort high \
  --limit 14 \
  --concurrency 2 \
  --max-turns 40 \
  --skip-setup \
  --verify-manifest \
  --include-attempts \
  "$@"
