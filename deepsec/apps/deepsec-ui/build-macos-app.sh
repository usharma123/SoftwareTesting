#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$APP_ROOT/../.." && pwd)"
PROFILE="release"
if [[ "${1:-}" == "--debug" ]]; then
  PROFILE="debug"
fi

pnpm --dir "$REPO_ROOT" --filter deepsec bundle

cargo_args=(build --manifest-path "$APP_ROOT/Cargo.toml")
if [[ "$PROFILE" == "release" ]]; then
  cargo_args+=(--release)
fi
cargo "${cargo_args[@]}"

APP_DIR="$APP_ROOT/dist/DeepSec Mission Control.app"
CONTENTS="$APP_DIR/Contents"
rm -rf "$APP_DIR"
mkdir -p "$CONTENTS/MacOS"
mkdir -p "$CONTENTS/Resources/deepsec-cli"
cp "$APP_ROOT/target/$PROFILE/deepsec-ui" "$CONTENTS/MacOS/deepsec-ui"
cp "$APP_ROOT/macos/Info.plist" "$CONTENTS/Info.plist"
cp "$REPO_ROOT/packages/deepsec/dist/explore-ui-cli.mjs" \
  "$CONTENTS/Resources/deepsec-cli/cli.mjs"
cp "$REPO_ROOT/packages/deepsec/package.json" \
  "$CONTENTS/Resources/deepsec-cli/package.json"
codesign --force --deep --sign - "$APP_DIR"

echo "$APP_DIR"
