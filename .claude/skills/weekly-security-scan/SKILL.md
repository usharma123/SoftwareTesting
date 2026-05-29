---
name: weekly-security-scan
description: Automated weekly security workflow — checks git history to identify changed components, creates a JIRA parent ticket, runs SAST/DAST via the security-scan skill, creates sub-tickets per vulnerability type, spawns fix agents per sub-ticket (each writes code + unit tests + PR), and monitors PRs for review feedback to re-trigger fixes. Use when asked to run the weekly security scan, automate vulnerability remediation, or set up the weekly AppSec pipeline.
metadata:
  status: stable
---

# Weekly Security Scan

End-to-end automated security pipeline: git history → JIRA ticket → SAST/DAST scan → sub-tickets per vuln type → parallel fix agents → PRs with evidence → PR feedback loop.

## Overview

```
git log (1 week)
  → changed components
    → JIRA parent ticket
      → /security-scan on changed components
        → one JIRA sub-ticket per vulnerability type
          → one fix agent per sub-ticket (code fix + unit tests)
            → evidence agent → GitHub PR linked to sub-ticket
              → human reviews PR
                → if concerns: re-launch fix agent with feedback
```

## Prerequisites

- JIRA MCP configured (the `mcp__jira__*` tools must be in scope, or a JIRA_URL + JIRA_TOKEN env var for REST fallback)
- `gh` CLI authenticated (`gh auth status`)
- Security scanners installed (checked at runtime — Semgrep recommended minimum)
- Sufficient permissions to create branches and PRs in the repo

---

## Step 0 — Preamble

Run the gstack preamble first. Then check prerequisite tools:

```bash
echo "=== Weekly Security Scan Bootstrap ==="
echo "DATE_RANGE: $(date -d '7 days ago' +%Y-%m-%d 2>/dev/null || date -v-7d +%Y-%m-%d) → $(date +%Y-%m-%d)"
echo "REPO: $(basename $(git rev-parse --show-toplevel 2>/dev/null))"
echo "BRANCH: $(git branch --show-current)"
echo "GH_AUTH: $(gh auth status 2>&1 | grep -c 'Logged in' || echo 0)"
echo "SEMGREP: $(command -v semgrep >/dev/null 2>&1 && semgrep --version 2>/dev/null | head -1 || echo NOT_INSTALLED)"
echo "BANDIT: $(command -v bandit >/dev/null 2>&1 && bandit --version 2>/dev/null | head -1 || echo NOT_INSTALLED)"
echo "JIRA_MCP: $(echo ${JIRA_URL:-NOT_SET})"
```

If `GH_AUTH` is 0, stop and tell the user to run `gh auth login`.

---

## Step 1 — Identify changed components from git history

```bash
WEEK_AGO=$(date -d '7 days ago' +%Y-%m-%d 2>/dev/null || date -v-7d +%Y-%m-%d)
git log --since="$WEEK_AGO" --name-only --format="" | sort -u | grep -v '^$'
```

From the file list, derive **components** (top-level directories or logical groupings):

```bash
git log --since="$WEEK_AGO" --name-only --format="" \
  | sort -u \
  | grep -v '^$' \
  | awk -F/ '{print $1}' \
  | sort -u
```

Also capture the commit range for the JIRA ticket description:

```bash
FIRST_COMMIT=$(git log --since="$WEEK_AGO" --format="%H" | tail -1)
LAST_COMMIT=$(git log --since="$WEEK_AGO" --format="%H" | head -1)
COMMIT_COUNT=$(git log --since="$WEEK_AGO" --format="%H" | wc -l | tr -d ' ')
AUTHORS=$(git log --since="$WEEK_AGO" --format="%aN" | sort -u | tr '\n' ', ' | sed 's/, $//')
echo "COMMITS: $COMMIT_COUNT | AUTHORS: $AUTHORS | RANGE: ${FIRST_COMMIT:0:8}..${LAST_COMMIT:0:8}"
```

If `COMMIT_COUNT` is 0, report "No commits in the past 7 days. Nothing to scan." and stop.

---

## Step 2 — Create JIRA parent ticket

Using the JIRA MCP (prefer `mcp__jira__create_issue`) or REST fallback, create the parent ticket:

**Title:** `[Security] Weekly Scan — <repo-name> — week of <WEEK_AGO>`

**Description:**
```
Automated weekly security scan for <repo-name>.

Scope: Components changed in the past 7 days
  - Components: <comma-separated component list>
  - Commits: <COMMIT_COUNT> commits by <AUTHORS>
  - Range: <FIRST_COMMIT_SHORT>..<LAST_COMMIT_SHORT>

This ticket is the parent for all vulnerability sub-tickets found this week.
Sub-tickets will be created after the SAST/DAST scan completes.

Triggered by: /weekly-security-scan on <DATE>
```

**Type:** Task (or Story if Task unavailable)
**Labels:** `security`, `automated`, `weekly-scan`
**Priority:** Medium

Capture the parent ticket key (e.g., `SEC-123`). If JIRA MCP is unavailable, print the ticket details and ask the user to create it manually, then ask for the ticket key before continuing.

---

## Step 3 — Run SAST/DAST scan on changed components

Invoke the `/security-scan` skill scoped to the identified components. Pass the component paths explicitly so the scan is focused:

```bash
SCAN_PATHS="<space-separated list of changed component directories>"
echo "Scanning: $SCAN_PATHS"
```

Run `/security-scan` (via the Skill tool) with the args set to the changed component paths. The scan should:
- Run SAST (Semgrep, Bandit/gosec/njsscan as appropriate for the language)
- Run SCA/dependency scan
- Run secrets detection
- Skip DAST unless the user explicitly authorized it in the invocation arguments

Collect the findings. Group them by **vulnerability type** (CWE category or OWASP Top 10 category). For example:
- `A01:2021 – Broken Access Control`
- `A03:2021 – Injection (SQLi/XSS/CMDi)`
- `A05:2021 – Security Misconfiguration`
- `A06:2021 – Vulnerable and Outdated Components`
- `A07:2021 – Identification and Authentication Failures`
- `CWE-798 – Hard-coded Credentials`

Deduplicate: one sub-ticket per **vulnerability type**, not per individual finding. List all findings of that type in the sub-ticket.

If the scan finds no vulnerabilities, update the parent JIRA ticket: "Scan complete — no vulnerabilities found in changed components." and stop.

---

## Step 4 — Create JIRA sub-tickets per vulnerability type

For each vulnerability type group found, create a sub-ticket linked to the parent (`SEC-123`):

**Title:** `[<VULN_TYPE>] <repo-name> — <short description>`

**Description:**
```
Parent: <PARENT_TICKET_KEY>
Vulnerability type: <VULN_TYPE> (<CWE or OWASP reference>)
Severity: <Critical/High/Medium/Low>

Findings in this group:
<list each finding: file:line — rule — description>

Remediation target:
Fix all <N> instances of <VULN_TYPE> listed above, add unit tests
confirming the fix, and open a PR linked to this ticket.

Auto-generated by /weekly-security-scan on <DATE>
```

**Type:** Sub-task (linked to parent)
**Labels:** `security`, `automated`, `<vuln-type-slug>`
**Priority:** Map severity → priority (Critical/High → High, Medium → Medium, Low → Low)

Collect all sub-ticket keys (e.g., `SEC-124`, `SEC-125`, ...).

---

## Step 5 — Spawn a fix agent per sub-ticket (parallel)

For each sub-ticket, spawn a separate Agent instance (subagent_type: `claude`) to handle the full fix lifecycle. Run all fix agents **in parallel** (one Agent tool call per sub-ticket in a single message).

Each fix agent receives this prompt template (fill in the specifics):

```
You are a security fix agent. Your job:

JIRA ticket: <SUB_TICKET_KEY>
Vulnerability type: <VULN_TYPE>
Severity: <SEVERITY>

Findings to fix:
<list of file:line — rule — description>

Steps:
1. Read each affected file.
2. Apply the minimal correct fix for each finding. Do not refactor beyond the fix.
3. For each fix, write or update unit tests that:
   - Confirm the vulnerability no longer exists (e.g., input that used to trigger SQLi now safely returns an error)
   - Confirm existing behavior is preserved
4. Run the existing test suite: `<test command>`. All tests must pass.
5. Stage and commit changes on a new branch named: fix/<SUB_TICKET_KEY>-<vuln-type-slug>
   Commit message: "fix(<SUB_TICKET_KEY>): remediate <VULN_TYPE>\n\nFixes: <list of files fixed>"
6. Report back:
   - List of files changed
   - List of tests added/modified
   - Test run output (pass/fail)
   - Branch name
   - Any finding you could NOT fix (and why)

Do not open a PR — the evidence agent handles that.
Do not modify files outside the scope of the listed findings.
```

Collect the results from all fix agents. For any agent that reported it could not fix a finding, note it in the parent JIRA ticket as a manual action item.

---

## Step 6 — Invoke evidence agent per sub-ticket (parallel)

For each sub-ticket where the fix agent succeeded, spawn an evidence agent (subagent_type: `claude`). Run all evidence agents **in parallel**.

Each evidence agent receives this prompt template:

```
You are a security evidence agent. Your job:

JIRA ticket: <SUB_TICKET_KEY>
Branch: fix/<SUB_TICKET_KEY>-<vuln-type-slug>
Fix summary from the fix agent:
<paste fix agent output>

Steps:
1. Check out branch: fix/<SUB_TICKET_KEY>-<vuln-type-slug>
2. Run the full test suite. Capture the output.
3. Run the security scanner (semgrep) scoped to the fixed files. Confirm the findings are gone.
4. Compose evidence:
   - Before: list of findings that existed
   - After: semgrep output showing 0 findings for those rules
   - Tests: full test output (pass count, any failures)
5. Create a GitHub PR:
   - Title: "fix(<SUB_TICKET_KEY>): remediate <VULN_TYPE>"
   - Body:
     ## Summary
     Fixes <N> instances of <VULN_TYPE> found in the weekly security scan.
     JIRA: <SUB_TICKET_KEY> (linked to parent <PARENT_TICKET_KEY>)

     ## Changes
     <list of files changed and what was fixed>

     ## Evidence
     ### Before (scan findings)
     <semgrep output before fix — from fix agent report>

     ### After (scan clean)
     <semgrep output after fix — 0 findings>

     ### Test Results
     <test run output>

     ## Test Coverage
     <list new/modified tests and what they assert>

     🤖 Generated by /weekly-security-scan
   - Base: main (or default branch)
   - Head: fix/<SUB_TICKET_KEY>-<vuln-type-slug>
6. Report back the PR URL and PR number.
```

After all evidence agents complete, update each JIRA sub-ticket with the PR URL and status "In Review".

---

## Step 7 — PR review feedback loop

After PRs are created, present a summary to the human:

```
Weekly Security Scan Complete
==============================
Parent ticket: <PARENT_TICKET_KEY>
Scan date: <DATE>
Components scanned: <list>

Vulnerabilities found: <N types, M total findings>
PRs created:
  <SUB_TICKET_KEY> — <VULN_TYPE> — <PR_URL>
  <SUB_TICKET_KEY> — <VULN_TYPE> — <PR_URL>
  ...

Unfixed (manual action required):
  <list any findings the fix agent could not handle>

Next step: Review the PRs above. If a PR has concerns or requested
changes, run: /weekly-security-scan review <PR_NUMBER>
```

### Handling PR review feedback (`/weekly-security-scan review <PR_NUMBER>`)

When invoked with the `review` subcommand and a PR number:

1. Fetch the PR review comments:
   ```bash
   gh pr view <PR_NUMBER> --json reviews,comments,reviewRequests
   gh pr review-comments <PR_NUMBER>
   ```

2. Identify the JIRA sub-ticket from the PR body (look for the `JIRA:` line).

3. Spawn a new fix agent with the original fix context PLUS the review feedback:
   ```
   You are re-running a security fix based on PR review feedback.

   PR: <PR_URL>
   JIRA: <SUB_TICKET_KEY>
   Branch: fix/<SUB_TICKET_KEY>-<vuln-type-slug>
   Original fix summary: <paste original fix agent output>

   Review feedback to address:
   <paste all review comments verbatim>

   Steps:
   1. Read the review comments carefully.
   2. Apply changes to address each concern on the existing branch.
   3. Run the full test suite. All tests must pass.
   4. Push the updated branch.
   5. Report: what you changed in response to each comment.
   ```

4. After the re-fix agent completes, push the branch and respond to review comments on the PR summarizing what was addressed.

5. Update the JIRA sub-ticket: "PR updated per review feedback on <DATE>."

---

## Scheduling

To run this skill weekly automatically, use the `/schedule` skill:

```
/schedule weekly-security-scan every Monday at 9am
```

This creates a cron routine via the `schedule` skill that fires `/weekly-security-scan` on the configured cadence.

---

## Subcommands

| Invocation | Behavior |
|---|---|
| `/weekly-security-scan` | Full pipeline: git history → JIRA → scan → fix → PRs |
| `/weekly-security-scan review <PR#>` | Re-run fix agent on a PR with review feedback |
| `/weekly-security-scan scan-only` | Stop after Step 3 (scan + report, no JIRA/PRs) |
| `/weekly-security-scan status` | Show open sub-tickets and PR statuses for current week |

---

## Error handling

- **JIRA unavailable:** Run the scan anyway. Print ticket specs to console and ask the user to create them manually before continuing to Step 5.
- **Fix agent fails (tests don't pass):** Mark the sub-ticket as "Blocked — auto-fix failed". Include the test failure output. Skip the evidence agent for that ticket. Add it to the manual action list in the summary.
- **No scanners installed:** Print install commands for Semgrep (`pip install semgrep`) and stop. Do not proceed with an incomplete scan.
- **PR already exists for branch:** Skip PR creation, fetch the existing PR URL, and continue.

---

## Notes

- Fix agents run in parallel — total wall-clock time is bounded by the slowest single fix, not the sum.
- Each fix agent operates on an isolated branch. Failures are isolated.
- The skill intentionally does NOT auto-merge PRs. Human review is the gate between automated fixes and production.
- DAST is disabled by default. Add `--dast` to the invocation args to enable it (requires explicit ownership authorization per the security-scan skill rules).
