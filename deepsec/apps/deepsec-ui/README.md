# DeepSec Mission Control

A macOS-first GPUI companion for `scripts/explore-harness.sh`. The app launches
the real harness, visualizes its outer phases and per-attempt model/tool events,
and preserves the shell entrypoint as the source of truth for CI.

## Run locally

```bash
cargo run --manifest-path apps/deepsec-ui/Cargo.toml
```

The start button stays disabled until a target repository is selected.
Simulation mode is the default: it uses DeepSec's deterministic stub model, so
opening the app cannot accidentally spend model credits. The Docker/gVisor
runtime is still exercised.

To produce a standard macOS app bundle:

```bash
apps/deepsec-ui/build-macos-app.sh
open "apps/deepsec-ui/dist/DeepSec Mission Control.app"
```

Pass `--debug` to the build script for a faster local bundle.
The build embeds a focused, self-contained DeepSec explore CLI inside the app,
so Finder launch does not depend on macOS granting helper processes access to
the source checkout under Documents.

## Architecture

- The shell harness remains usable exactly as before.
- The macOS bundle uses its packaged CLI while the development command falls
  back to the checkout's normal `packages/deepsec/dist/cli.mjs` entrypoint.
- `DEEPSEC_EVENT_STREAM=1` adds prefixed JSON records alongside its normal
  human-readable output.
- A bounded background channel reads process output away from GPUI's main
  thread. The UI drains up to 256 records and redraws at most every 33ms.
- Activity history and raw output use bounded ring buffers. The visible log is
  rendered with GPUI's `uniform_list`, so long runs do not create a view per
  historical row.
- Cancelling sends `SIGTERM` to the harness process group, followed by a bounded
  `SIGKILL` fallback. This also stops child model and Docker commands.
- Failed or missing attempts can be retried through the same harness; CI,
  manifest, and evidence-bundle outputs are refreshed afterward.

GPUI is pinned to Zed revision
`969a67fcfbf799e68ab00854028228274be847e8`. Runtime Metal shader compilation
is enabled so local development works with Command Line Tools alone; a full
Xcode install is not required just to compile this prototype.
