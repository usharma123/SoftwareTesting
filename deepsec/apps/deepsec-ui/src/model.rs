use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    time::{Duration, Instant},
};

use serde_json::Value;

pub const EVENT_PREFIX: &str = "@@deepsec:event@@";
const MAX_ACTIVITY_ITEMS: usize = 5_000;
const MAX_CONSOLE_LINES: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunStatus {
    Idle,
    Running,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
}

impl RunStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "Ready",
            Self::Running => "Running",
            Self::Cancelling => "Stopping",
            Self::Succeeded => "Complete",
            Self::Failed => "Needs attention",
            Self::Cancelled => "Cancelled",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::Cancelling)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageId {
    Setup,
    Preflight,
    Inventory,
    Ranking,
    Exploration,
    Verification,
    Ci,
    Manifest,
    Bundle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageStatus {
    Pending,
    Active,
    Complete,
    Skipped,
    Failed,
}

#[derive(Clone, Debug)]
pub struct Stage {
    pub id: StageId,
    pub label: &'static str,
    pub description: &'static str,
    pub status: StageStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptStatus {
    Queued,
    Running,
    Validating,
    Complete,
    Failed,
}

impl AttemptStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Running => "Exploring",
            Self::Validating => "Validating",
            Self::Complete => "Complete",
            Self::Failed => "Failed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AttemptState {
    pub index: usize,
    pub focus_file: String,
    pub status: AttemptStatus,
    pub turn: usize,
    pub max_turns: usize,
    pub last_action: String,
    pub outcome: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
}

impl AttemptState {
    fn new(index: usize, focus_file: String) -> Self {
        Self {
            index,
            focus_file,
            status: AttemptStatus::Queued,
            turn: 0,
            max_turns: 0,
            last_action: "Waiting for an execution slot".into(),
            outcome: None,
            input_tokens: 0,
            output_tokens: 0,
            cost_usd: 0.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityTone {
    Neutral,
    Accent,
    Success,
    Warning,
    Danger,
}

#[derive(Clone, Debug)]
pub struct Activity {
    pub at: String,
    pub label: String,
    pub detail: String,
    pub attempt_index: Option<usize>,
    pub tone: ActivityTone,
}

pub struct RunState {
    pub status: RunStatus,
    pub stages: Vec<Stage>,
    pub attempts: BTreeMap<usize, AttemptState>,
    pub selected_attempt: Option<usize>,
    pub activities: VecDeque<Activity>,
    pub console: VecDeque<String>,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub data_root: Option<PathBuf>,
    pub manifest_path: Option<PathBuf>,
    pub bundle_path: Option<PathBuf>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    pub started_at: Option<Instant>,
    pub finished_after: Option<Duration>,
    pub last_error: Option<String>,
}

impl Default for RunState {
    fn default() -> Self {
        Self {
            status: RunStatus::Idle,
            stages: fresh_stages(),
            attempts: BTreeMap::new(),
            selected_attempt: None,
            activities: VecDeque::new(),
            console: VecDeque::new(),
            project_id: None,
            run_id: None,
            data_root: None,
            manifest_path: None,
            bundle_path: None,
            input_tokens: 0,
            output_tokens: 0,
            cost_usd: 0.0,
            started_at: None,
            finished_after: None,
            last_error: None,
        }
    }
}

impl RunState {
    pub fn begin(&mut self, retry: bool) {
        let retained_project = retry.then(|| self.project_id.clone()).flatten();
        let retained_run = retry.then(|| self.run_id.clone()).flatten();
        let retained_data_root = retry.then(|| self.data_root.clone()).flatten();
        *self = Self::default();
        self.project_id = retained_project;
        self.run_id = retained_run;
        self.data_root = retained_data_root;
        self.status = RunStatus::Running;
        self.started_at = Some(Instant::now());
        self.push_activity(Activity {
            at: now_label(),
            label: if retry {
                "Retry requested".into()
            } else {
                "Harness requested".into()
            },
            detail: if retry {
                "Retrying failed or missing focused attempts".into()
            } else {
                "Preparing the local DeepSec execution pipeline".into()
            },
            attempt_index: None,
            tone: ActivityTone::Accent,
        });
    }

    pub fn request_cancel(&mut self) {
        if self.status == RunStatus::Running {
            self.status = RunStatus::Cancelling;
            self.push_activity(Activity {
                at: now_label(),
                label: "Stop requested".into(),
                detail: "Waiting for the harness process group to terminate".into(),
                attempt_index: None,
                tone: ActivityTone::Warning,
            });
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.finished_after
            .or_else(|| self.started_at.map(|started| started.elapsed()))
            .unwrap_or_default()
    }

    pub fn failed_attempts(&self) -> usize {
        self.attempts
            .values()
            .filter(|attempt| attempt.status == AttemptStatus::Failed)
            .count()
    }

    pub fn push_console(&mut self, line: String) {
        push_capped(&mut self.console, line, MAX_CONSOLE_LINES);
    }

    pub fn apply_event(&mut self, event: Value) {
        let kind = string(&event, "kind").unwrap_or("unknown");
        match kind {
            "harness-phase" => self.apply_harness_phase(&event),
            "harness-complete" => self.apply_harness_complete(&event),
            "run-start" => {
                self.project_id = owned_string(&event, "projectId").or(self.project_id.take());
                self.run_id = owned_string(&event, "runId").or(self.run_id.take());
                self.add_event_activity(
                    &event,
                    "Explore run started",
                    detail(&event, "Starting the bounded exploration run"),
                    None,
                    ActivityTone::Accent,
                );
            }
            "ranking" => self.apply_ranking_event(&event),
            "ranking-done" => {
                self.set_stage(StageId::Inventory, StageStatus::Complete);
                self.set_stage(StageId::Ranking, StageStatus::Complete);
                self.set_stage(StageId::Exploration, StageStatus::Active);
                self.add_event_activity(
                    &event,
                    "Ranking complete",
                    detail(&event, "Focused attempts selected"),
                    None,
                    ActivityTone::Success,
                );
            }
            "attempt-queued" => self.apply_attempt_lifecycle(&event, AttemptStatus::Queued),
            "attempt-start" => self.apply_attempt_lifecycle(&event, AttemptStatus::Running),
            "attempt-finish" => self.apply_attempt_lifecycle(&event, AttemptStatus::Complete),
            "attempt-fail" => self.apply_attempt_lifecycle(&event, AttemptStatus::Failed),
            "progress" => self.apply_progress(&event),
            "run-complete" => {
                self.set_stage(StageId::Exploration, StageStatus::Complete);
                self.add_event_activity(
                    &event,
                    "Exploration complete",
                    detail(&event, "All focused attempts returned"),
                    None,
                    ActivityTone::Success,
                );
            }
            _ => self.add_event_activity(
                &event,
                "Harness event",
                format!("Unrecognized event kind: {kind}"),
                None,
                ActivityTone::Neutral,
            ),
        }
    }

    pub fn apply_exit(&mut self, exit_code: i32, cancelled: bool) {
        if self.started_at.is_some() && self.finished_after.is_none() {
            self.finished_after = Some(self.elapsed());
        }
        if cancelled || self.status == RunStatus::Cancelling {
            self.status = RunStatus::Cancelled;
            self.mark_active_stage_failed();
            self.push_activity(Activity {
                at: now_label(),
                label: "Harness cancelled".into(),
                detail: "The process group was stopped safely".into(),
                attempt_index: None,
                tone: ActivityTone::Warning,
            });
        } else if exit_code == 0 {
            if self.status.is_active() {
                self.status = RunStatus::Succeeded;
            }
        } else {
            self.status = RunStatus::Failed;
            self.mark_active_stage_failed();
            if self.last_error.is_none() {
                self.last_error = Some(format!("Harness exited with code {exit_code}"));
            }
        }
    }

    fn apply_harness_phase(&mut self, event: &Value) {
        let Some(phase) = string(event, "phase") else {
            return;
        };
        let Some(stage) = stage_for_phase(phase) else {
            return;
        };
        let status = match string(event, "status") {
            Some("start") => StageStatus::Active,
            Some("complete") => StageStatus::Complete,
            Some("skipped") => StageStatus::Skipped,
            Some("failed") => StageStatus::Failed,
            _ => StageStatus::Pending,
        };
        self.set_stage(stage, status);
        let tone = match status {
            StageStatus::Active => ActivityTone::Accent,
            StageStatus::Complete => ActivityTone::Success,
            StageStatus::Skipped => ActivityTone::Neutral,
            StageStatus::Failed => ActivityTone::Danger,
            StageStatus::Pending => ActivityTone::Neutral,
        };
        self.add_event_activity(
            event,
            format!("{} {}", stage_label(stage), status_label(status)),
            detail(event, "Harness phase updated"),
            None,
            tone,
        );
    }

    fn apply_harness_complete(&mut self, event: &Value) {
        self.project_id = owned_string(event, "projectId").or(self.project_id.take());
        self.run_id = owned_string(event, "runId").or(self.run_id.take());
        self.data_root = owned_string(event, "dataRoot")
            .map(PathBuf::from)
            .or(self.data_root.take());
        self.manifest_path = owned_string(event, "manifest").map(PathBuf::from);
        self.bundle_path = owned_string(event, "bundle").map(PathBuf::from);
        self.finished_after = Some(self.elapsed());

        if string(event, "status") == Some("complete") {
            self.status = RunStatus::Succeeded;
            for stage in &mut self.stages {
                if stage.status == StageStatus::Active {
                    stage.status = StageStatus::Complete;
                }
            }
            self.add_event_activity(
                event,
                "Evidence ready",
                detail(event, "The run and portable evidence bundle are complete"),
                None,
                ActivityTone::Success,
            );
        } else {
            self.status = RunStatus::Failed;
            self.mark_active_stage_failed();
            self.last_error = Some(detail(event, "The harness did not complete"));
            self.add_event_activity(
                event,
                "Harness stopped",
                detail(event, "The harness did not complete"),
                None,
                ActivityTone::Danger,
            );
        }
    }

    fn apply_ranking_event(&mut self, event: &Value) {
        let event_detail = detail(event, "Preparing ranked files");
        if event_detail.contains("inventory") {
            self.set_stage(StageId::Inventory, StageStatus::Active);
            self.add_event_activity(
                event,
                "Building inventory",
                event_detail,
                None,
                ActivityTone::Accent,
            );
        } else {
            self.set_stage(StageId::Inventory, StageStatus::Complete);
            self.set_stage(StageId::Ranking, StageStatus::Active);
            self.add_event_activity(
                event,
                "Ranking candidates",
                event_detail,
                None,
                ActivityTone::Accent,
            );
        }
    }

    fn apply_attempt_lifecycle(&mut self, event: &Value, status: AttemptStatus) {
        let index = usize_value(event, "attemptIndex").unwrap_or(0);
        let focus_file = owned_string(event, "focusFile").unwrap_or_else(|| "Unknown file".into());
        let outcome = owned_string(event, "outcome");
        let event_detail = detail(event, status.label());
        let attempt = self
            .attempts
            .entry(index)
            .or_insert_with(|| AttemptState::new(index, focus_file.clone()));
        attempt.focus_file = focus_file.clone();
        attempt.status = status;
        attempt.last_action = event_detail.clone();
        if outcome.is_some() {
            attempt.outcome = outcome;
        }
        if self.selected_attempt.is_none() {
            self.selected_attempt = Some(index);
        }
        let tone = match status {
            AttemptStatus::Complete => ActivityTone::Success,
            AttemptStatus::Failed => ActivityTone::Danger,
            AttemptStatus::Running | AttemptStatus::Validating => ActivityTone::Accent,
            AttemptStatus::Queued => ActivityTone::Neutral,
        };
        self.add_event_activity(
            event,
            format!("Attempt {:02} {}", index + 1, status.label().to_lowercase()),
            focus_file,
            Some(index),
            tone,
        );
    }

    fn apply_progress(&mut self, event: &Value) {
        let index = usize_value(event, "attemptIndex").unwrap_or(0);
        let focus_file = owned_string(event, "focusFile").unwrap_or_else(|| "Unknown file".into());
        let phase = string(event, "phase").unwrap_or("explore");
        let nested = event.get("event").unwrap_or(&Value::Null);
        let event_type = string(nested, "type").unwrap_or("progress");
        let turn = usize_value(nested, "turn").unwrap_or(0);
        let max_turns = usize_value(nested, "maxTurns").unwrap_or(0);

        let (label, event_detail, tone) = match event_type {
            "model-request" => (
                if phase == "validate" {
                    "Validation model request"
                } else {
                    "Model request"
                },
                format!("Turn {turn}/{max_turns}"),
                ActivityTone::Accent,
            ),
            "model-response" => {
                let chars = u64_value(nested, "responseChars").unwrap_or(0);
                (
                    "Model response",
                    format!("Turn {turn}/{max_turns} · {chars} characters"),
                    ActivityTone::Neutral,
                )
            }
            "action" => (
                "Running bounded command",
                owned_string(nested, "reason")
                    .unwrap_or_else(|| "Collecting local evidence".into()),
                ActivityTone::Accent,
            ),
            "command-result" => {
                let code = i64_value(nested, "exitCode").unwrap_or(-1);
                let duration = u64_value(nested, "durationMs").unwrap_or(0);
                (
                    "Command returned",
                    format!(
                        "Exit {code} · {}",
                        format_duration(Duration::from_millis(duration))
                    ),
                    if code == 0 {
                        ActivityTone::Neutral
                    } else {
                        ActivityTone::Warning
                    },
                )
            }
            "repair" => (
                "Repairing model response",
                owned_string(nested, "error")
                    .unwrap_or_else(|| "Malformed structured response".into()),
                ActivityTone::Warning,
            ),
            "final" => (
                "Attempt reached a verdict",
                owned_string(nested, "outcome").unwrap_or_else(|| "Complete".into()),
                ActivityTone::Success,
            ),
            "final-turn-command-denied" => (
                "Final command denied",
                "The bounded turn budget requires a final report".into(),
                ActivityTone::Warning,
            ),
            _ => (
                "Attempt progress",
                event_type.to_string(),
                ActivityTone::Neutral,
            ),
        };

        let (input_tokens, output_tokens, cost_usd) = nested
            .get("usage")
            .map(|usage| {
                (
                    u64_value(usage, "inputTokens").unwrap_or(0),
                    u64_value(usage, "outputTokens").unwrap_or(0),
                    f64_value(usage, "costUsd").unwrap_or(0.0),
                )
            })
            .unwrap_or_default();
        self.input_tokens += input_tokens;
        self.output_tokens += output_tokens;
        self.cost_usd += cost_usd;

        let attempt = self
            .attempts
            .entry(index)
            .or_insert_with(|| AttemptState::new(index, focus_file));
        attempt.status = if phase == "validate" {
            AttemptStatus::Validating
        } else {
            AttemptStatus::Running
        };
        attempt.turn = turn;
        attempt.max_turns = max_turns;
        attempt.last_action = event_detail.clone();
        attempt.input_tokens += input_tokens;
        attempt.output_tokens += output_tokens;
        attempt.cost_usd += cost_usd;
        if self.selected_attempt.is_none() {
            self.selected_attempt = Some(index);
        }

        self.add_event_activity(event, label, event_detail, Some(index), tone);
    }

    fn add_event_activity(
        &mut self,
        event: &Value,
        label: impl Into<String>,
        detail: impl Into<String>,
        attempt_index: Option<usize>,
        tone: ActivityTone,
    ) {
        self.push_activity(Activity {
            at: time_fragment(string(event, "at")).unwrap_or_else(now_label),
            label: label.into(),
            detail: detail.into(),
            attempt_index,
            tone,
        });
    }

    fn push_activity(&mut self, activity: Activity) {
        push_capped(&mut self.activities, activity, MAX_ACTIVITY_ITEMS);
    }

    fn set_stage(&mut self, id: StageId, status: StageStatus) {
        if let Some(stage) = self.stages.iter_mut().find(|stage| stage.id == id) {
            stage.status = status;
        }
    }

    fn mark_active_stage_failed(&mut self) {
        if let Some(stage) = self
            .stages
            .iter_mut()
            .rev()
            .find(|stage| stage.status == StageStatus::Active)
        {
            stage.status = StageStatus::Failed;
        }
    }
}

pub fn parse_protocol_line(line: &str) -> Option<Result<Value, serde_json::Error>> {
    line.strip_prefix(EVENT_PREFIX).map(serde_json::from_str)
}

pub fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 3_600 {
        format!("{}h {:02}m", seconds / 3_600, (seconds % 3_600) / 60)
    } else if seconds >= 60 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else if seconds > 0 {
        format!("{seconds}s")
    } else {
        format!("{}ms", duration.as_millis())
    }
}

fn fresh_stages() -> Vec<Stage> {
    vec![
        Stage {
            id: StageId::Setup,
            label: "Runtime setup",
            description: "Local gVisor image",
            status: StageStatus::Pending,
        },
        Stage {
            id: StageId::Preflight,
            label: "Preflight",
            description: "Runtime, cache, model",
            status: StageStatus::Pending,
        },
        Stage {
            id: StageId::Inventory,
            label: "Inventory",
            description: "Production surface",
            status: StageStatus::Pending,
        },
        Stage {
            id: StageId::Ranking,
            label: "Ranking",
            description: "Bounded model pass",
            status: StageStatus::Pending,
        },
        Stage {
            id: StageId::Exploration,
            label: "Exploration",
            description: "Isolated attempts",
            status: StageStatus::Pending,
        },
        Stage {
            id: StageId::Verification,
            label: "Verification",
            description: "Artifacts and isolation",
            status: StageStatus::Pending,
        },
        Stage {
            id: StageId::Ci,
            label: "CI outputs",
            description: "JSON, SARIF, JUnit",
            status: StageStatus::Pending,
        },
        Stage {
            id: StageId::Manifest,
            label: "Manifest",
            description: "Hashed evidence",
            status: StageStatus::Pending,
        },
        Stage {
            id: StageId::Bundle,
            label: "Bundle",
            description: "Portable reviewer pack",
            status: StageStatus::Pending,
        },
    ]
}

fn stage_for_phase(phase: &str) -> Option<StageId> {
    match phase {
        "setup" => Some(StageId::Setup),
        "doctor" => Some(StageId::Preflight),
        "exploration" => Some(StageId::Exploration),
        "verification" => Some(StageId::Verification),
        "ci" => Some(StageId::Ci),
        "manifest" => Some(StageId::Manifest),
        "bundle" => Some(StageId::Bundle),
        _ => None,
    }
}

fn stage_label(stage: StageId) -> &'static str {
    match stage {
        StageId::Setup => "Runtime setup",
        StageId::Preflight => "Preflight",
        StageId::Inventory => "Inventory",
        StageId::Ranking => "Ranking",
        StageId::Exploration => "Exploration",
        StageId::Verification => "Verification",
        StageId::Ci => "CI outputs",
        StageId::Manifest => "Manifest",
        StageId::Bundle => "Bundle",
    }
}

fn status_label(status: StageStatus) -> &'static str {
    match status {
        StageStatus::Pending => "pending",
        StageStatus::Active => "started",
        StageStatus::Complete => "complete",
        StageStatus::Skipped => "skipped",
        StageStatus::Failed => "failed",
    }
}

fn detail(event: &Value, fallback: &str) -> String {
    owned_string(event, "detail").unwrap_or_else(|| fallback.into())
}

fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key)?.as_str()
}

fn owned_string(value: &Value, key: &str) -> Option<String> {
    string(value, key).map(ToOwned::to_owned)
}

fn usize_value(value: &Value, key: &str) -> Option<usize> {
    u64_value(value, key).and_then(|value| usize::try_from(value).ok())
}

fn u64_value(value: &Value, key: &str) -> Option<u64> {
    value.get(key)?.as_u64()
}

fn i64_value(value: &Value, key: &str) -> Option<i64> {
    value.get(key)?.as_i64()
}

fn f64_value(value: &Value, key: &str) -> Option<f64> {
    value.get(key)?.as_f64()
}

fn time_fragment(value: Option<&str>) -> Option<String> {
    let value = value?;
    let fragment = value.split('T').nth(1)?.trim_end_matches('Z');
    Some(fragment.get(..8).unwrap_or(fragment).to_string())
}

fn now_label() -> String {
    // Avoid a heavyweight date dependency; elapsed timing is monotonic and the
    // event protocol supplies wall-clock timestamps for all harness activity.
    "now".into()
}

fn push_capped<T>(items: &mut VecDeque<T>, item: T, capacity: usize) {
    if items.len() == capacity {
        items.pop_front();
    }
    items.push_back(item);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_only_prefixed_protocol_records() {
        assert!(parse_protocol_line("normal harness output").is_none());
        let event =
            parse_protocol_line("@@deepsec:event@@{\"kind\":\"run-start\",\"runId\":\"run-1\"}")
                .unwrap()
                .unwrap();
        assert_eq!(event["runId"], "run-1");
    }

    #[test]
    fn reduces_progress_into_attempt_and_usage_state() {
        let mut state = RunState::default();
        state.begin(false);
        state.apply_event(json!({
            "kind": "progress",
            "attemptIndex": 1,
            "focusFile": "src/auth.ts",
            "phase": "explore",
            "event": {
                "type": "model-response",
                "at": "2026-07-14T14:30:00Z",
                "turn": 2,
                "maxTurns": 8,
                "responseChars": 420,
                "usage": { "inputTokens": 100, "outputTokens": 20, "costUsd": 0.01 }
            }
        }));

        let attempt = state.attempts.get(&1).unwrap();
        assert_eq!(attempt.turn, 2);
        assert_eq!(attempt.input_tokens, 100);
        assert_eq!(state.output_tokens, 20);
        assert_eq!(state.selected_attempt, Some(1));
    }

    #[test]
    fn records_completion_artifact_paths() {
        let mut state = RunState::default();
        state.begin(false);
        state.apply_event(json!({
            "kind": "harness-complete",
            "status": "complete",
            "projectId": "demo",
            "runId": "run-1",
            "manifest": "/tmp/manifest.json",
            "bundle": "/tmp/bundle"
        }));
        assert_eq!(state.status, RunStatus::Succeeded);
        assert_eq!(state.project_id.as_deref(), Some("demo"));
        assert_eq!(state.bundle_path, Some(PathBuf::from("/tmp/bundle")));
    }
}
