import type { BugReport, CommandExecution, RankedFile, SourceFileSummary } from "./types.js";

const EXPLORE_ACTION_CONTRACT = `Return exactly one JSON object and no markdown or prose.
Canonical command action:
{ "action": "run_command", "command": "./gradlew --offline test", "timeoutMs": 60000, "reason": "why this command helps" }

Canonical no-bug final action:
{ "action": "final", "result": { "outcome": "no-bug", "summary": "what you checked", "evidence": ["local evidence"] } }

Canonical bug final action:
{
  "action": "final",
  "result": {
    "outcome": "bug",
    "title": "short title",
    "severity": "HIGH",
    "confidence": "high",
    "vulnSlug": "short-slug",
    "lineNumbers": [123],
    "description": "security impact and root cause",
    "recommendation": "specific fix",
    "reproductionSteps": ["local step 1", "local step 2"],
    "evidence": ["command output or test evidence"]
  }
}

Do not use aliases such as {"result":"no_bug_found"} or {"verdict":"no_bug_found"}. The top-level "action" field is required.`;

const VALIDATION_ACTION_CONTRACT = `Return exactly one JSON object and no markdown or prose.
Canonical validation command action:
{ "action": "run_command", "command": "./gradlew --offline test", "timeoutMs": 60000, "reason": "why this confirms or rejects the report" }

Canonical validation final action:
{
  "action": "final",
  "result": {
    "verdict": "true-positive",
    "reproducible": true,
    "interesting": true,
    "reasoning": "short reason",
    "adjustedSeverity": "HIGH"
  }
}

Allowed verdict values: true-positive, false-positive, uncertain.
Allowed adjustedSeverity values: CRITICAL, HIGH, MEDIUM, HIGH_BUG, BUG, LOW.
Do not use aliases such as {"result":"true_positive"} or a bare verdict string. The top-level "action" field is required.`;

export function rankingPrompt(files: SourceFileSummary[]): string {
  const inventory = files
    .map(
      (f) =>
        `FILE: ${f.filePath}\nHEURISTIC: ${f.heuristicScore}\nBYTES: ${f.bytes}\nPREVIEW:\n${f.preview}`,
    )
    .join("\n\n---\n\n");

  return `Rank these production-relevant files for security-vulnerability exploration.

Use the Anthropic-style file triage scale:
1 = inert constants, configuration, or low-risk support code.
2 = normal application logic with little attacker-controlled input.
3 = meaningful parsing, validation, serialization, or control-flow logic.
4 = likely attack surface with untrusted data, protocol handling, auth, crypto, or boundary decisions.
5 = highly interesting bug surface: raw network/file/message parsing, auth, cryptography, deserialization, or complex validation.

Return only JSON in this exact shape, with at most 12 ranked entries:
{
  "rankings": [
    { "filePath": "relative/path.java", "score": 1, "reason": "short reason" }
  ]
}

Every score must be an integer 1 through 5. Prioritize the files most likely to contain interesting vulnerabilities. Omitted files will be assigned a local fallback score by the harness.

${inventory}`;
}

export function exploreSystemPrompt(): string {
  return `You are running a bounded local vulnerability-finding attempt.

Rules:
- You may read source, compile, run local tests, add temporary debug files, and run local reproduction programs inside the isolated container.
- You must focus on the requested file, while following references if needed.
- Do not request Internet access, credentials, host files, Docker access, persistence outside the project, or external exploitation.
- Do not produce weaponized instructions against live systems. Proofs must be local and bounded to the copied project.
- Prefer concrete evidence: commands run, observed outputs, stack traces, tests, or minimal local repro snippets.

${EXPLORE_ACTION_CONTRACT}`;
}

export function exploreInitialPrompt(args: {
  projectId: string;
  focus: RankedFile;
  topFiles: RankedFile[];
  maxTurns: number;
}): string {
  const top = args.topFiles
    .map((r, i) => `${i + 1}. ${r.filePath} score=${r.score} reason=${r.reason}`)
    .join("\n");
  return `Project: ${args.projectId}
Focus file: ${args.focus.filePath}
Focus score: ${args.focus.score}
Focus reason: ${args.focus.reason}
Max turns: ${args.maxTurns}

Ranked focus queue:
${top}

Start by inspecting the focus file and nearby call sites. Use only commands that work in /workspace/target. For Java/Gradle projects, prefer offline Gradle commands such as ./gradlew --offline test or targeted test tasks.`;
}

export function commandObservationPrompt(execution: CommandExecution): string {
  return `Command observation:
${JSON.stringify(execution, null, 2)}

Continue with either another run_command JSON action or a final JSON action.

${EXPLORE_ACTION_CONTRACT}`;
}

export function finalExploreTurnPrompt(): string {
  return `This is your final allowed model turn for this focused attempt. Do not request another command.
Return one valid final JSON action now. Use the canonical no-bug final shape if you do not have a confirmed local reproduction. Use the canonical bug final shape only if you have concrete local reproduction evidence.

${EXPLORE_ACTION_CONTRACT}`;
}

export function exploreRepairPrompt(error: string): string {
  return `Your last response was not one complete valid JSON action: ${error}

Repair it now. Return exactly one valid JSON object with action run_command or final. Do not include prose or markdown. Use only the canonical shapes below.

${EXPLORE_ACTION_CONTRACT}`;
}

export function validationPrompt(report: BugReport, transcriptTail: string): string {
  return `I have received the following bounded local bug report. Confirm if it is real, reproducible, and interesting enough to keep.

You are in a fresh isolated container with the copied project under /workspace/target. You may ask the harness to run one local command at a time before returning a verdict.

Do not request Internet access, credentials, host files, Docker access, persistence outside the copied project, or external exploitation. Keep reproduction local and bounded.

Bug report:
${JSON.stringify(report, null, 2)}

Local transcript evidence:
${transcriptTail}

${VALIDATION_ACTION_CONTRACT}`;
}

export function finalValidationTurnPrompt(): string {
  return `This is your final allowed model turn for validation. Do not request another command.
Return one valid final JSON verdict now. Use false-positive or uncertain if the report is not reproducible and interesting from local evidence.

${VALIDATION_ACTION_CONTRACT}`;
}

export function validationRepairPrompt(error: string): string {
  return `Your last validation response was not one complete valid JSON action: ${error}

Repair it now. Return exactly one valid JSON object with action run_command or final. Do not include prose or markdown. Use only the canonical shapes below.

${VALIDATION_ACTION_CONTRACT}`;
}
