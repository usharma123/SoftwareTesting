# Supply chain: SCA + reachability + SBOM + malicious packages

Goal: know what dependencies are present, which have known vulnerabilities,
which of those are actually reachable, and whether any package is malicious or
typosquatted. Prefer OSV.dev/GHSA-backed tools — NVD enrichment lags, so
NVD-only tools miss or under-describe recent advisories.

## SCA (known vulnerable dependencies)

| Scope | Tool | Invocation | Install |
|---|---|---|---|
| Any (lockfile-aware, OSV/GHSA) | osv-scanner | `osv-scanner scan source --format sarif --output osv.sarif .` | `brew install osv-scanner` |
| Any (filesystem) | Trivy fs | `trivy fs --scanners vuln --format sarif -o trivy-fs.sarif .` | `brew install trivy` |
| Any (SBOM-driven) | grype | `grype sbom:sbom.cdx.json -o sarif > grype.sarif` | `brew install grype` |
| npm | `npm audit` | `npm audit --json` | bundled |
| Python | pip-audit | `pip-audit -f json` | `pipx install pip-audit` |
| Rust | cargo-audit | `cargo audit --json` | `cargo install cargo-audit` |
| Ruby | bundler-audit | `bundle audit --update` | `gem install bundler-audit` |

Run osv-scanner as the primary cross-ecosystem pass; add the native tool for
each detected ecosystem (they sometimes carry advisories OSV hasn't ingested).

## Reachability

A present CVE in an unimported/uncalled path is lower risk than a reachable
one. Capture **reachable vs merely present** and feed it into prioritization.

- Go: `govulncheck ./...` — call-graph analysis, reports only vulnerabilities
  in code paths the binary actually reaches. Strongly prefer its verdict for Go.
- Other ecosystems: note whether the vulnerable package is a direct dependency
  and whether the vulnerable symbol/module is imported. Semgrep Supply Chain
  (if licensed) does this; without it, do a quick import/usage grep and record
  the assessment as best-effort.

## SBOM (deliverable)

Generate a Software Bill of Materials — it is itself a current-standard
artifact (NTIA minimum elements / EO 14028) and lets others re-scan later.

```
syft scan dir:. -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json
```

Install: `brew install syft`. Re-scan the SBOM with grype (table above) so the
vuln view and the inventory come from the same component set. Reference the
SBOM path in the final report.

## Malicious / typosquatted packages

Known-vulnerable ≠ malicious. Modern supply-chain attacks ship install-time
malware and typosquats that no CVE covers.

- `guarddog <ecosystem> scan .` (e.g. `pypi`, `npm`) — heuristics for install
  scripts, exfiltration, obfuscation, typosquatting. Install: `pipx install guarddog`.
- osv-scanner also surfaces OSV "malicious package" advisories — keep those.

Treat any confirmed malicious package, install-script exfiltration, or strong
typosquat match as **Critical** and surface it at the top of the report, ahead
of CVSS-ranked items.

## Advisory & license notes

- Record GHSA/CVE IDs, affected range, and **fixed version** for every finding
  — remediation is "upgrade to X", which the report must state.
- Flag license risk where the tooling reports it (e.g. GPL in a proprietary
  distribution); note it as informational unless the user asked for compliance.
