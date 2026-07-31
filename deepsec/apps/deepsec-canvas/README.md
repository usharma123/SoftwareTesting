# DeepSec Live Canvas

An offline tldraw mission-control view for the DeepSec gVisor explore harness.
The browser receives only sanitized structured events from a loopback-only
bridge. It never receives raw commands, transcripts, command output, prompts,
credentials, or full attempt artifacts.

## Architecture

```text
explore-harness.sh -> sanitized Node bridge -> local SSE -> tldraw
                              |
                              +-> canvas-events.jsonl + recording.json
```

The bridge—not an AI agent—owns the event transport. A supervisor can poll
`/api/status` every 10–15 seconds without becoming a dependency of the run or
canvas.

## Commands

Run from the `deepsec` checkout:

```sh
corepack pnpm --filter @deepsec/canvas build
corepack pnpm --filter @deepsec/canvas test
corepack pnpm --filter @deepsec/canvas simulate
```

Start the established 18-file live profile:

```sh
corepack pnpm --filter @deepsec/canvas live -- \
  --target-root /absolute/path/to/prowide-core \
  --project-id prowide-core \
  --limit 18 \
  --concurrency 2 \
  --max-turns 40 \
  --skip-setup \
  --verify-manifest \
  --include-attempts
```

The process prints `DEEPSEC_CANVAS_READY` with a tokenized local URL. The live
scan starts immediately, while opening the URL attaches or reattaches the
visualizer. Replays never launch DeepSec or a model:

```sh
corepack pnpm --filter @deepsec/canvas replay
```

## Offline and safety properties

- Server binding and browser requests are restricted to `127.0.0.1`.
- tldraw code, CSS, fonts, icons, and translations are bundled by Vite through
  `@tldraw/assets/imports.vite`; there is no tldraw sync or CDN fallback.
- tldraw is pinned exactly. Without `VITE_TLDRAW_LICENSE_KEY`, the SDK's
  standard attribution remains visible.
- Mutating API calls require both the random launch token and exact same-origin
  browser origin.
- Commands are reduced to a command category plus bounded result metadata.
- Stop targets only the exact harness process group and containers belonging to
  the current run ID.
- Failed attempts remain visible; the bridge never retries automatically.

Recordings are written under
`.deepsec-explore-runs/canvas/<session-id>/`. The browser can export a `.tldr`
document and a 2× PNG overview, while IndexedDB keeps a local canvas snapshot.
