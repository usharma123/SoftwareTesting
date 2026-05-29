# Dynamic analysis (DAST)

DAST sends traffic to a running application. It is intrusive and dual-use.
**Do not proceed past the gate below until every condition is satisfied.**

## Authorization & rules-of-engagement gate (hard stop)

Confirm, explicitly, all of:

1. The user owns the target or has **written authorization** to test it.
2. The **exact in-scope host(s)/URL(s)** — scans never wander off this list.
3. It is **not** production or a third party without sign-off (prefer staging
   or a local instance).
4. Agreed **rate limits / time window** so the scan does not cause an outage.

If any is missing or ambiguous: stop, report the static findings, and state
that DAST was skipped pending authorization. Never "test gently to check" —
the gate is binary.

Throughout: passive/baseline before active, capture evidence (request/response,
screenshots), **never auto-exploit, never exfiltrate data, never pivot**, and
respect the agreed window.

## OWASP ZAP — primary

Use the **Automation Framework** (YAML plan), not the legacy `zap-baseline.py`
script. Minimal flow:

1. Passive baseline first — spider + passive rules only, no attacks.
2. Escalate to an active scan **only** after the gate, scoped to in-scope URLs.
3. For APIs, import the contract so coverage is real:
   `-addoninstall openapi` then add an `openapi` / `graphql` / `soap` job
   pointing at the spec.
4. For authenticated areas, configure session/script authentication in the
   plan (context with auth + logged-in/out indicators) so the scanner stays
   logged in.

Run via the stable Docker image and emit SARIF + HTML:

```
docker run --rm -v "$PWD:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/zap-plan.yaml
```

The plan's `report` job should write SARIF (for merge) and HTML (for humans).

## Supporting tools

| Tool | Use | Invocation | Install |
|---|---|---|---|
| nuclei | Template-based known-CVE/misconfig checks | `nuclei -u <in-scope-url> -rl 50 -severity low,medium,high,critical -sarif-export nuclei.sarif` | `brew install nuclei` |
| nikto | Web server config / outdated components | `nikto -h <in-scope-url> -Format json -o nikto.json` | `brew install nikto` |
| sqlmap | **Only** an explicitly authorized parameter | `sqlmap -u '<url>' --batch --level 1 --risk 1 --technique=B` | `pipx install sqlmap` |

Rules:
- nuclei: rate-limit (`-rl`), keep templates updated, no intrusive fuzzing
  templates without explicit OK.
- sqlmap is opt-in per parameter, lowest `--level/--risk`, document exactly
  what was run and why; never dump data beyond a boolean/PoC confirmation.

Feed SARIF/JSON outputs into [prioritization.md](prioritization.md) with the
static results.
