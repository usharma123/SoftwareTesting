# Prioritize & report

Raw tool output is noisy and CVSS-only ranking is outdated. Merge, dedupe,
rank by *exploitability and reachability*, map to standards, then report.

## 1. Merge & dedupe

- Collect every tool's SARIF/JSON. SARIF is the common schema — normalize the
  rest into the same shape (rule id, message, location `file:line` or
  `package@version`, severity, CWE/CVE).
- Dedupe by `(location, CWE)` for code findings and `(package, CVE)` for
  dependency/image findings. The same CVE from Trivy + grype + osv is **one**
  finding with merged sources.

## 2. Rank (exploit-aware, not CVSS-alone)

For each finding compute priority from, in order of weight:

1. **Confirmed/active** — TruffleHog-verified secret, confirmed malicious
   package, or a working PoC → top of report, above everything.
2. **CISA KEV** — CVE in the [Known Exploited Vulnerabilities] catalog →
   treat as Critical regardless of CVSS.
3. **EPSS** — exploit probability ≥ ~0.5 (or top-percentile) lifts priority;
   very low EPSS on a high-CVSS issue lowers urgency.
4. **Reachability** — reachable (govulncheck / imported & called) outranks
   "present but unreachable". Unreachable, low-EPSS, non-KEV → Low/triage.
5. **CVSS base + exposure** — tiebreaker and base severity (internet-facing
   beats internal-only).

Output buckets: **Critical / High / Medium / Low / Informational**, with the
ranking rationale stated per finding (e.g. "CVSS 7.5 but **KEV + reachable** →
Critical").

## 3. Map to standards

Tag every finding with:
- **OWASP Top 10 2021** (web) and/or **OWASP API Security Top 10 2023** (APIs).
- **CWE** id; flag if it is in the **CWE Top 25**.
- **OWASP ASVS** level/section where the user is working to ASVS.

Most tools emit CWE already; carry it through and add the OWASP category.

## 4. False positives & reachability triage

Down-rank or exclude with a stated reason: test fixtures/sample code, generated
or vendored code, demonstrably dead code, dependency CVEs proven unreachable.
Never silently delete — list excluded items with the rationale so the triage is
auditable.

## 5. CI / diff mode (opt-in only)

Engage **only if the user asks** for CI/PR/diff behavior; default audits report
everything.

- Establish a **baseline** (prior results or the base branch); report only
  **new** findings introduced by the diff.
- Emit merged **SARIF** so it uploads to GitHub code scanning / equivalent.
- Document **fail gates** (recommend: fail on any new KEV, any verified secret
  or malicious package, or any new High+). Make the gate explicit, don't just
  exit nonzero silently.
- Honor suppression files (`.semgrepignore`, gitleaks allowlist,
  `.trivyignore`, osv-scanner config); list what was suppressed.

## 6. Report template

```markdown
# Security Scan — <target> — <date>

## Summary
- Scope: <repo / commit / host>   Mode: <audit | CI-diff>
- Tools run: <list>   Not installed (coverage gaps): <list + install cmds>
- Findings: Crit <n> · High <n> · Med <n> · Low <n> · Info <n>
- Headline risks: <verified secrets / KEV / malicious pkgs, if any>
- SBOM: <path to sbom.cdx.json / sbom.spdx.json>

## Findings
### [CRITICAL] <title>
- Severity & rationale: <CVSS / EPSS / KEV / reachable → bucket>
- Standards: OWASP <Axxxx> · CWE-<n><(Top 25)> · <CVE/GHSA>
- Location: `path:line` or `pkg@version`
- Evidence: <snippet / request-response / tool ref>
- Impact: <what an attacker gains>
- Remediation: <fix / upgrade to vX.Y.Z>
- References: <advisory links>

(repeat by descending priority)

## Triaged out (false positive / unreachable)
- <finding> — <reason>

## Residual risk & recommendations
<gaps from uninstalled tools, unauthorized DAST, next steps>
```

End every report with the coverage gaps and residual-risk note — a scan that
hides what it could not check is worse than one that admits it.
