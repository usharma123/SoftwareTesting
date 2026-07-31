# DeepSec Canvas local bridge

This dependency-free Node bridge runs only on `127.0.0.1`. It launches the
canonical `scripts/explore-harness.sh`, parses its structured event stream,
redacts command content, hydrates allowlisted finding metadata from run
artifacts, and broadcasts the reduced records over server-sent events.

## Start

```sh
node apps/deepsec-canvas/server/index.mjs
```

The bridge prints one `DEEPSEC_CANVAS_READY` JSON record containing the random
launch token and local URL. The built UI is served from
`apps/deepsec-canvas/dist` when present.

For an offline deterministic demo:

```sh
node apps/deepsec-canvas/server/index.mjs --simulate
```

Run the bridge smoke test with:

```sh
node apps/deepsec-canvas/server/scripts/smoke.mjs
```

## API

- `GET /api/status?token=...`
- `GET /api/events?token=...` — SSE records named `canvas-event`
- `GET /api/recordings?token=...`
- `POST /api/start` — `{ "mode": "live"|"simulation", "options": { ... } }`
- `POST /api/stop`
- `POST /api/replay/start` — `{ "sessionId": "...", "speed": 1 }`
- `POST /api/replay/pause`
- `POST /api/replay/resume`
- `POST /api/replay/seek` — `{ "index": 10 }` or `{ "position": 0.5 }`
- `POST /api/replay/stop`

Mutation requests require both `X-DeepSec-Canvas-Token` and an `Origin` exactly
matching the bridge origin. Live runs default to 18 files, concurrency 2, 40
turns, skipped image setup, and no report launch. The bridge never retries an
attempt automatically.

The UI starts live runs with the same API. For a manual launch, copy `origin`
and `token` from the ready record:

```sh
curl -X POST "$origin/api/start" \
  -H "Origin: $origin" \
  -H "Content-Type: application/json" \
  -H "X-DeepSec-Canvas-Token: $token" \
  --data '{"mode":"live","options":{"root":"/absolute/target","projectId":"target","limit":18,"concurrency":2,"maxTurns":40}}'
```

Every SSE data record has this shape:

```json
{
  "seq": 1,
  "source": "live",
  "receivedAt": "2026-07-23T12:00:00.000Z",
  "event": { "kind": "run-start" }
}
```

The recording stores the same sanitized envelopes in
`canvas-events.jsonl`. Raw transcripts and command arguments are never written
to the canvas recording.
