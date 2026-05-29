# Static analysis: SAST + IaC + container + secrets

Run the tools that match the detected stack. Always request machine-readable
output (SARIF preferred, JSON otherwise) and write results to a temp dir for
the prioritize/merge step. Scope every scan to the project; exclude
`node_modules/`, `vendor/`, `.git/`, build/dist, and fixtures unless the scan
*is* of those. If a tool is not installed, say so and print the install line —
do not silently drop that coverage.

## SAST

| Stack | Tool | Invocation | Install |
|---|---|---|---|
| Any / multi | Semgrep | `semgrep scan --config auto --sarif -o semgrep.sarif` (CI: `--config p/ci`) | `pipx install semgrep` |
| Python | Bandit | `bandit -r . -f sarif -o bandit.sarif` | `pipx install bandit` |
| Go | gosec | `gosec -fmt=sarif -out=gosec.sarif ./...` | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| JS/TS | njsscan | `njsscan --sarif -o njsscan.sarif .` | `pipx install njsscan` |
| JS/TS | ESLint security | `eslint . -f @microsoft/sarif -o eslint.sarif` with `eslint-plugin-security` | project devDeps |
| Ruby/Rails | Brakeman | `brakeman -f sarif -o brakeman.sarif` | `gem install brakeman` |
| Java/Kotlin | Semgrep | use the multi-language row | — |

Notes:
- Semgrep `--config auto` covers many languages; the per-language tools find
  ecosystem-specific issues Semgrep's free rules miss — run both when present.
- Java/Kotlin deep analysis would use SpotBugs + FindSecBugs; it needs a build.
  Mention it as optional rather than blocking on a Gradle/Maven build.
- `govulncheck` is dependency-side (call-graph reachable) — covered in
  [supply-chain.md](supply-chain.md), not here.

## Infrastructure as code

| Target | Tool | Invocation | Install |
|---|---|---|---|
| Terraform / K8s / CFN / Helm / ARM | Checkov | `checkov -d . -o sarif --output-file-path checkov.sarif` | `pipx install checkov` |
| Same (alt/complement) | Trivy config | `trivy config --format sarif -o trivy-config.sarif .` | `brew install trivy` |
| Dockerfile | hadolint | `hadolint -f sarif Dockerfile > hadolint.sarif` | `brew install hadolint` |

Checkov and Trivy config overlap; running both improves rule coverage — the
prioritize step dedupes by (file, line, rule/CWE).

## Container images

Only if an image is built/available (`docker images`, a registry ref, or a tar):

| Tool | Invocation | Install |
|---|---|---|
| Trivy | `trivy image --format sarif -o trivy-image.sarif <ref>` | `brew install trivy` |
| grype | `grype <ref> -o sarif > grype-image.sarif` | `brew install grype` |

These scan OS packages **and** language layers — they overlap with SCA; keep
findings but dedupe by package+CVE during prioritization.

## Secrets

| Tool | Invocation | Install | Notes |
|---|---|---|---|
| gitleaks | `gitleaks dir . --report-format sarif --report-path gitleaks.sarif` ; also `gitleaks git .` for history | `brew install gitleaks` | Primary. History scan catches removed-but-committed secrets. |
| TruffleHog | `trufflehog filesystem . --results=verified --json` (or `git file://.`) | `brew install trufflehog` | `--results=verified` actively validates that a credential is live — treat verified hits as Critical/confirmed. |

Run gitleaks for breadth and TruffleHog verified mode for confirmed live
credentials. A verified secret is an incident, not a finding — surface it at
the top of the report regardless of other ranking.
