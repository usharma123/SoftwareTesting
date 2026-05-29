---
name: security-scan
description: Runs a modern application-security sweep on a codebase or authorized running app — SAST (Semgrep, Bandit, gosec, Brakeman, njsscan), dependency/SCA scanning with reachability, SBOM generation, secrets detection, infrastructure-as-code and container/Dockerfile scanning, and optional DAST. Prioritizes findings by CISA KEV, EPSS, CVSS and reachability, maps them to OWASP Top 10 / API Top 10 / CWE, and emits a SARIF-backed report with an optional diff-aware CI mode. Use when the user asks to run a security scan, vulnerability scan, or security audit; SAST/DAST; check dependencies for CVEs; scan for secrets; generate or scan an SBOM / check the supply chain; scan IaC or container images; or pentest an app they own. The dynamic (DAST) phase and any dual-use tooling require explicit ownership/authorization.
metadata:
  status: stable
---

# Security Scan

Run a layered AppSec scan (SAST + supply chain + secrets + IaC/container, plus
optional DAST), then prioritize and report findings the way a current security
program expects: exploit-aware, standards-mapped, SARIF-backed.

## Operating rules

- **Never bundle or auto-install scanners.** Detect what is installed, run it,
  and for anything missing state it explicitly and give the install command —
  no silent skips. A scan that ran 3 of 6 tools must say so.
- **Static analysis is always safe to run** on code the user has open.
- **The dynamic phase and any dual-use tool are gated** (step 1). Without
  explicit authorization, do the static work and stop before DAST.
- Prefer **SARIF/JSON** output from every tool so results merge cleanly.

## Procedure

1. **Authorization & scope gate.** Confirm the user owns or is authorized to
   test the code. Before any DAST or dual-use tool (ZAP active scan, nuclei
   fuzzing, sqlmap): require explicit confirmation of ownership/written
   authorization, the exact in-scope host(s), and agreed rate limits (rules of
   engagement). No production or third-party targets without sign-off. If unmet,
   run static phases only and say why DAST was skipped.
2. **Detect the stack.** Identify languages, package manifests + lockfiles, IaC
   (Terraform/K8s/CloudFormation/Helm), Dockerfiles/images, and whether a
   runnable app or URL exists. This selects which scanners apply.
3. **Static phase.** Run SAST + IaC + container/Dockerfile + secrets scanning
   for the detected ecosystems. See
   [references/static-analysis.md](references/static-analysis.md).
4. **Supply-chain phase.** Run SCA with reachability where available, generate
   an SBOM, and check for malicious/typosquatted packages. See
   [references/supply-chain.md](references/supply-chain.md).
5. **Dynamic phase (optional, gated by step 1).** Only with a running,
   in-scope, authorized target. See [references/dast.md](references/dast.md).
6. **Prioritize & report.** Dedupe across tools, rank by CISA KEV / EPSS /
   CVSS / reachability, map to OWASP & CWE, drop false positives, and emit the
   report. Engage CI/diff mode only if the user asks for it. See
   [references/prioritization.md](references/prioritization.md).
