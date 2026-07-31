#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

mod model;
mod process;

use std::{path::Path, process::Command, time::Duration};

use async_channel::TryRecvError;
use gpui::{
    App, Bounds, Context, Div, ElementId, Hsla, SharedString, Stateful, Window, WindowBounds,
    WindowOptions, div, prelude::*, px, rgb, size, uniform_list,
};
use gpui_platform::application;
use model::{
    Activity, ActivityTone, AttemptState, AttemptStatus, RunState, RunStatus, Stage, StageStatus,
    format_duration,
};
use process::{LaunchConfig, RunControl, WorkerMessage, spawn_harness};

const WINDOW_WIDTH: f32 = 1_440.0;
const WINDOW_HEIGHT: f32 = 900.0;

struct DeepSecDashboard {
    state: RunState,
    config: LaunchConfig,
    show_raw_output: bool,
    target_selected: bool,
    run_control: Option<RunControl>,
    generation: u64,
}

impl DeepSecDashboard {
    fn new() -> Self {
        Self {
            state: RunState::default(),
            config: LaunchConfig::initial(),
            show_raw_output: false,
            target_selected: false,
            run_control: None,
            generation: 0,
        }
    }

    fn choose_target(&mut self, cx: &mut Context<Self>) {
        if self.state.status.is_active() {
            return;
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Choose a repository for DeepSec")
            .set_directory(&self.config.target_root)
            .pick_folder()
        {
            self.config.target_root = path;
            self.target_selected = true;
            self.state.last_error = None;
            cx.notify();
        }
    }

    fn start_run(&mut self, retry: bool, cx: &mut Context<Self>) {
        if self.state.status.is_active() {
            return;
        }
        if !retry && !self.target_selected {
            self.state.last_error = Some("Choose a target repository before starting.".into());
            cx.notify();
            return;
        }

        let mut config = self.config.clone();
        if retry {
            config.project_id = self.state.project_id.clone();
            config.run_id = self.state.run_id.clone();
            config.data_root = self.state.data_root.clone();
        }
        let (control, receiver) = match spawn_harness(config, retry) {
            Ok(worker) => worker,
            Err(error) => {
                self.state.status = RunStatus::Failed;
                self.state.last_error = Some(error.to_string());
                self.state
                    .push_console(format!("Could not start harness: {error}"));
                cx.notify();
                return;
            }
        };

        self.state.begin(retry);
        self.run_control = Some(control);
        self.generation += 1;
        let generation = self.generation;

        cx.spawn(async move |this, cx| {
            let mut done = false;
            let mut redraw_ticks = 0usize;
            while !done {
                cx.background_executor()
                    .timer(Duration::from_millis(33))
                    .await;

                let mut messages = Vec::with_capacity(64);
                let mut channel_closed = false;
                while messages.len() < 256 {
                    match receiver.try_recv() {
                        Ok(message) => messages.push(message),
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Closed) => {
                            channel_closed = true;
                            break;
                        }
                    }
                }
                done = messages.iter().any(|message| {
                    matches!(
                        message,
                        WorkerMessage::Exited { .. } | WorkerMessage::StartFailed(_)
                    )
                });
                redraw_ticks += 1;
                let tick_elapsed_time = redraw_ticks >= 30;
                let had_messages = !messages.is_empty();
                if tick_elapsed_time {
                    redraw_ticks = 0;
                }

                if had_messages || tick_elapsed_time {
                    let _ = this.update(cx, |dashboard, cx| {
                        if dashboard.generation != generation {
                            return;
                        }
                        for message in messages {
                            dashboard.apply_worker_message(message);
                        }
                        cx.notify();
                    });
                }
                if channel_closed && !had_messages {
                    break;
                }
            }
        })
        .detach();
        cx.notify();
    }

    fn apply_worker_message(&mut self, message: WorkerMessage) {
        match message {
            WorkerMessage::Event(event) => self.state.apply_event(event),
            WorkerMessage::Console(line) => self.state.push_console(line),
            WorkerMessage::Started(pid) => {
                self.state
                    .push_console(format!("Harness process started · pid {pid}"));
            }
            WorkerMessage::StartFailed(error) => {
                self.state.status = RunStatus::Failed;
                self.state.last_error = Some(error.clone());
                self.state
                    .push_console(format!("Harness could not start · {error}"));
                self.run_control = None;
            }
            WorkerMessage::Exited { code, cancelled } => {
                self.state.apply_exit(code, cancelled);
                self.run_control = None;
            }
        }
    }

    fn cancel_run(&mut self, cx: &mut Context<Self>) {
        if let Some(control) = &self.run_control {
            self.state.request_cancel();
            control.cancel();
            cx.notify();
        }
    }

    fn render_header(&self) -> Div {
        let status_color = run_status_color(self.state.status);
        div()
            .h(px(74.0))
            .flex_none()
            .px_6()
            .flex()
            .items_center()
            .justify_between()
            .border_b_1()
            .border_color(border())
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .size(px(34.0))
                            .rounded_lg()
                            .bg(accent())
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_color(background())
                            .text_lg()
                            .child("D"),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_0p5()
                            .child(
                                div()
                                    .text_base()
                                    .text_color(text_primary())
                                    .child("DeepSec Mission Control"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(text_muted())
                                    .child("LOCAL · GVISOR · BOUNDED EXPLORATION"),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_6()
                    .child(metric("ELAPSED", format_duration(self.state.elapsed())))
                    .child(metric(
                        "TOKENS",
                        compact_number(self.state.input_tokens + self.state.output_tokens),
                    ))
                    .child(metric(
                        "COST",
                        if self.state.cost_usd > 0.0 {
                            format!("${:.4}", self.state.cost_usd)
                        } else {
                            "—".into()
                        },
                    ))
                    .child(
                        div()
                            .px_3()
                            .py_1()
                            .rounded_full()
                            .border_1()
                            .border_color(status_color.opacity(0.5))
                            .bg(status_color.opacity(0.12))
                            .text_xs()
                            .text_color(status_color)
                            .child(self.state.status.label()),
                    ),
            )
    }

    fn render_controls(&self, cx: &mut Context<Self>) -> Div {
        let active = self.state.status.is_active();
        let can_retry = !active
            && self.state.failed_attempts() > 0
            && self.state.project_id.is_some()
            && self.state.run_id.is_some()
            && self.state.data_root.is_some();
        let target_name = if self.target_selected {
            self.config
                .target_root
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("Selected repository")
                .to_string()
        } else {
            "No target selected".into()
        };
        let target_path = if self.target_selected {
            self.config.target_root.display().to_string()
        } else {
            "Choose a local repository to begin".into()
        };

        div()
            .h(px(82.0))
            .flex_none()
            .px_6()
            .flex()
            .items_center()
            .justify_between()
            .border_b_1()
            .border_color(border())
            .bg(surface())
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        control_button("choose-target", "Choose target", ButtonStyle::Secondary)
                            .when(!active, |button| {
                                button.on_click(cx.listener(|this, _, _, cx| {
                                    this.choose_target(cx);
                                }))
                            })
                            .when(active, |button| button.opacity(0.45)),
                    )
                    .child(
                        div()
                            .w(px(270.0))
                            .flex()
                            .flex_col()
                            .gap_0p5()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(text_primary())
                                    .truncate()
                                    .child(target_name),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(text_muted())
                                    .truncate()
                                    .child(target_path),
                            ),
                    )
                    .child(vertical_rule())
                    .child(stepper(
                        "FILES",
                        self.config.limit,
                        ("files-minus", "files-plus"),
                        active,
                        cx,
                        |this| this.config.limit = this.config.limit.saturating_sub(1).max(1),
                        |this| this.config.limit = (this.config.limit + 1).min(12),
                    ))
                    .child(stepper(
                        "PARALLEL",
                        self.config.concurrency,
                        ("concurrency-minus", "concurrency-plus"),
                        active,
                        cx,
                        |this| {
                            this.config.concurrency =
                                this.config.concurrency.saturating_sub(1).max(1)
                        },
                        |this| this.config.concurrency = (this.config.concurrency + 1).min(6),
                    ))
                    .child(
                        control_button(
                            "simulation-toggle",
                            if self.config.simulation {
                                "Simulation"
                            } else {
                                "Live model"
                            },
                            if self.config.simulation {
                                ButtonStyle::Selected
                            } else {
                                ButtonStyle::Secondary
                            },
                        )
                        .when(!active, |button| {
                            button.on_click(cx.listener(|this, _, _, cx| {
                                this.config.simulation = !this.config.simulation;
                                cx.notify();
                            }))
                        })
                        .when(active, |button| button.opacity(0.45)),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .when(can_retry, |row| {
                        row.child(
                            control_button(
                                "retry-failed",
                                format!("Retry {} failed", self.state.failed_attempts()),
                                ButtonStyle::Secondary,
                            )
                            .on_click(cx.listener(|this, _, _, cx| this.start_run(true, cx))),
                        )
                    })
                    .when(active, |row| {
                        row.child(
                            control_button("cancel-run", "Stop safely", ButtonStyle::Danger)
                                .on_click(cx.listener(|this, _, _, cx| this.cancel_run(cx))),
                        )
                    })
                    .when(!active, |row| {
                        row.child(
                            control_button(
                                "start-run",
                                if self.config.simulation {
                                    "Run simulation"
                                } else {
                                    "Start live run"
                                },
                                ButtonStyle::Primary,
                            )
                            .when(self.target_selected, |button| {
                                button.on_click(
                                    cx.listener(|this, _, _, cx| this.start_run(false, cx)),
                                )
                            })
                            .when(!self.target_selected, |button| button.opacity(0.4)),
                        )
                    }),
            )
    }

    fn render_stage_rail(&self) -> Div {
        div()
            .w(px(224.0))
            .h_full()
            .flex_none()
            .p_5()
            .border_r_1()
            .border_color(border())
            .bg(surface())
            .flex()
            .flex_col()
            .gap_4()
            .child(section_label("PIPELINE"))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .children(self.state.stages.iter().map(render_stage)),
            )
            .child(div().flex_1())
            .child(
                div()
                    .p_3()
                    .rounded_lg()
                    .bg(background())
                    .border_1()
                    .border_color(border())
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_xs()
                            .text_color(text_muted())
                            .child("EXECUTION POLICY"),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(text_secondary())
                            .child("Read-only root · no network · capped turns"),
                    ),
            )
    }

    fn render_attempts(&self, cx: &mut Context<Self>) -> Div {
        let attempts = self.state.attempts.values().cloned().collect::<Vec<_>>();
        div()
            .h(px(218.0))
            .flex_none()
            .p_5()
            .border_b_1()
            .border_color(border())
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(section_label("FOCUSED ATTEMPTS"))
                    .child(
                        div()
                            .text_xs()
                            .text_color(text_muted())
                            .child(format!("{} scheduled", attempts.len())),
                    ),
            )
            .child(
                div()
                    .id("attempt-strip")
                    .flex_1()
                    .flex()
                    .gap_3()
                    .overflow_x_scroll()
                    .when(attempts.is_empty(), |row| {
                        row.child(
                            div()
                                .w_full()
                                .h_full()
                                .rounded_lg()
                                .border_1()
                                .border_color(border())
                                .bg(surface_raised())
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_color(text_muted())
                                .child("Attempts will appear after file ranking"),
                        )
                    })
                    .children(attempts.into_iter().map(|attempt| {
                        let index = attempt.index;
                        let selected = self.state.selected_attempt == Some(index);
                        render_attempt_card(attempt, selected).on_click(cx.listener(
                            move |this, _, _, cx| {
                                this.state.selected_attempt = Some(index);
                                cx.notify();
                            },
                        ))
                    })),
            )
    }

    fn render_activity(&self, cx: &mut Context<Self>) -> Div {
        let show_raw = self.show_raw_output;
        let count = if show_raw {
            self.state.console.len()
        } else {
            self.state.activities.len()
        };
        div()
            .flex_1()
            .min_h(px(180.0))
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .overflow_hidden()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(section_label(if show_raw {
                                "RAW OUTPUT"
                            } else {
                                "LIVE ACTIVITY"
                            }))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(text_muted())
                                    .child("Newest first"),
                            ),
                    )
                    .child(
                        control_button(
                            "raw-output-toggle",
                            if show_raw {
                                "Show summary"
                            } else {
                                "Show raw output"
                            },
                            if show_raw {
                                ButtonStyle::Selected
                            } else {
                                ButtonStyle::Ghost
                            },
                        )
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.show_raw_output = !this.show_raw_output;
                            cx.notify();
                        })),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .rounded_lg()
                    .border_1()
                    .border_color(border())
                    .bg(surface_raised())
                    .overflow_hidden()
                    .when(count == 0, |panel| {
                        panel.child(
                            div()
                                .size_full()
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_color(text_muted())
                                .child(if show_raw {
                                    "Raw process output will appear here"
                                } else {
                                    "Start a run to see live harness activity"
                                }),
                        )
                    })
                    .when(count > 0, |panel| {
                        panel.child(
                            uniform_list(
                                "activity-list",
                                count,
                                cx.processor(
                                    move |this, range: std::ops::Range<usize>, _window, _cx| {
                                        range
                                            .map(|visible_index| {
                                                let source_index = count - visible_index - 1;
                                                if show_raw {
                                                    render_console_row(
                                                        this.state
                                                            .console
                                                            .get(source_index)
                                                            .map(String::as_str)
                                                            .unwrap_or_default(),
                                                    )
                                                } else {
                                                    render_activity_row(
                                                        this.state.activities.get(source_index),
                                                    )
                                                }
                                            })
                                            .collect::<Vec<_>>()
                                    },
                                ),
                            )
                            .h_full(),
                        )
                    }),
            )
    }

    fn render_inspector(&self) -> Div {
        let selected = self
            .state
            .selected_attempt
            .and_then(|index| self.state.attempts.get(&index))
            .cloned();
        let manifest = self.state.manifest_path.clone();
        let bundle = self.state.bundle_path.clone();
        let data_root = self.state.data_root.clone();

        div()
            .w(px(304.0))
            .h_full()
            .flex_none()
            .p_5()
            .border_l_1()
            .border_color(border())
            .bg(surface())
            .flex()
            .flex_col()
            .gap_4()
            .child(section_label("INSPECTOR"))
            .child(match selected {
                Some(attempt) => render_attempt_inspector(attempt).into_any_element(),
                None => render_run_inspector(&self.state).into_any_element(),
            })
            .child(div().flex_1())
            .when(self.state.last_error.is_some(), |panel| {
                panel.child(
                    div()
                        .p_3()
                        .rounded_lg()
                        .border_1()
                        .border_color(danger().opacity(0.45))
                        .bg(danger().opacity(0.08))
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .text_xs()
                                .text_color(danger())
                                .child("NEEDS ATTENTION"),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(text_secondary())
                                .child(self.state.last_error.clone().unwrap_or_default()),
                        ),
                )
            })
            .when(
                manifest.is_some() || bundle.is_some() || data_root.is_some(),
                |panel| {
                    panel.child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(section_label("ARTIFACTS"))
                            .when_some(bundle, |column, path| {
                                column.child(
                                    artifact_button("open-bundle", "Open evidence bundle")
                                        .on_click(move |_, _, _| open_path(&path)),
                                )
                            })
                            .when_some(manifest, |column, path| {
                                column.child(
                                    artifact_button("open-manifest", "Open manifest")
                                        .on_click(move |_, _, _| open_path(&path)),
                                )
                            })
                            .when_some(data_root, |column, path| {
                                column.child(
                                    artifact_button("open-data-root", "Reveal run data")
                                        .on_click(move |_, _, _| open_path(&path)),
                                )
                            }),
                    )
                },
            )
            .child(div().text_xs().text_color(text_muted()).child(
                "Raw commands and stdout stay hidden until explicitly opened in Live Activity.",
            ))
    }
}

impl Render for DeepSecDashboard {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .bg(background())
            .text_color(text_primary())
            .font_family("SF Pro Text")
            .text_sm()
            .flex()
            .flex_col()
            .overflow_hidden()
            .child(self.render_header())
            .child(self.render_controls(cx))
            .child(
                div()
                    .flex_1()
                    .flex()
                    .overflow_hidden()
                    .child(self.render_stage_rail())
                    .child(
                        div()
                            .flex_1()
                            .h_full()
                            .flex()
                            .flex_col()
                            .overflow_hidden()
                            .child(self.render_attempts(cx))
                            .child(self.render_activity(cx)),
                    )
                    .child(self.render_inspector()),
            )
    }
}

#[derive(Clone, Copy)]
enum ButtonStyle {
    Primary,
    Secondary,
    Selected,
    Danger,
    Ghost,
}

fn control_button(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    style: ButtonStyle,
) -> Stateful<Div> {
    let (background_color, border_color, text_color) = match style {
        ButtonStyle::Primary => (accent(), accent(), background()),
        ButtonStyle::Secondary => (surface_raised(), border_strong(), text_primary()),
        ButtonStyle::Selected => (accent().opacity(0.12), accent().opacity(0.45), accent()),
        ButtonStyle::Danger => (danger().opacity(0.1), danger().opacity(0.45), danger()),
        ButtonStyle::Ghost => (surface(), border(), text_secondary()),
    };
    div()
        .id(id)
        .h(px(34.0))
        .px_3()
        .rounded_md()
        .border_1()
        .border_color(border_color)
        .bg(background_color)
        .flex()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .text_xs()
        .text_color(text_color)
        .hover(|button| button.border_color(accent().opacity(0.65)))
        .child(label.into())
}

fn artifact_button(id: &'static str, label: &'static str) -> Stateful<Div> {
    div()
        .id(id)
        .h(px(34.0))
        .px_3()
        .rounded_md()
        .border_1()
        .border_color(border())
        .bg(background())
        .flex()
        .items_center()
        .justify_between()
        .cursor_pointer()
        .text_xs()
        .text_color(text_secondary())
        .hover(|button| {
            button
                .border_color(accent().opacity(0.5))
                .text_color(text_primary())
        })
        .child(label)
        .child("↗")
}

fn stepper(
    label: &'static str,
    value: usize,
    ids: (&'static str, &'static str),
    disabled: bool,
    cx: &mut Context<DeepSecDashboard>,
    decrement: impl Fn(&mut DeepSecDashboard) + 'static,
    increment: impl Fn(&mut DeepSecDashboard) + 'static,
) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(div().text_xs().text_color(text_muted()).child(label))
        .child(
            div()
                .flex()
                .items_center()
                .gap_1()
                .child(
                    mini_button(ids.0, "−")
                        .when(!disabled, |button| {
                            button.on_click(cx.listener(move |this, _, _, cx| {
                                decrement(this);
                                cx.notify();
                            }))
                        })
                        .when(disabled, |button| button.opacity(0.4)),
                )
                .child(
                    div()
                        .w(px(32.0))
                        .text_center()
                        .text_color(text_primary())
                        .child(value.to_string()),
                )
                .child(
                    mini_button(ids.1, "+")
                        .when(!disabled, |button| {
                            button.on_click(cx.listener(move |this, _, _, cx| {
                                increment(this);
                                cx.notify();
                            }))
                        })
                        .when(disabled, |button| button.opacity(0.4)),
                ),
        )
}

fn mini_button(id: &'static str, label: &'static str) -> Stateful<Div> {
    div()
        .id(id)
        .size(px(26.0))
        .rounded_md()
        .border_1()
        .border_color(border())
        .bg(surface_raised())
        .flex()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .text_color(text_secondary())
        .hover(|button| {
            button
                .border_color(accent().opacity(0.5))
                .text_color(text_primary())
        })
        .child(label)
}

fn render_stage(stage: &Stage) -> Div {
    let color = stage_status_color(stage.status);
    div()
        .h(px(49.0))
        .px_2()
        .rounded_md()
        .flex()
        .items_center()
        .gap_3()
        .when(stage.status == StageStatus::Active, |row| {
            row.bg(accent().opacity(0.07))
        })
        .child(
            div()
                .size(px(10.0))
                .rounded_full()
                .border_1()
                .border_color(color)
                .bg(
                    if matches!(stage.status, StageStatus::Complete | StageStatus::Active) {
                        color
                    } else {
                        color.opacity(0.12)
                    },
                ),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_0p5()
                .child(
                    div()
                        .text_xs()
                        .text_color(if stage.status == StageStatus::Pending {
                            text_muted()
                        } else {
                            text_primary()
                        })
                        .child(stage.label),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(text_muted())
                        .child(stage.description),
                ),
        )
}

fn render_attempt_card(attempt: AttemptState, selected: bool) -> Stateful<Div> {
    let color = attempt_status_color(attempt.status);
    let progress = if attempt.max_turns > 0 {
        attempt.turn as f32 / attempt.max_turns as f32
    } else {
        0.0
    };
    let file_name = Path::new(&attempt.focus_file)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&attempt.focus_file)
        .to_string();
    div()
        .id(("attempt", attempt.index))
        .w(px(270.0))
        .h_full()
        .flex_none()
        .p_3()
        .rounded_lg()
        .border_1()
        .border_color(if selected {
            accent().opacity(0.75)
        } else {
            border()
        })
        .bg(if selected {
            accent().opacity(0.055)
        } else {
            surface_raised()
        })
        .cursor_pointer()
        .flex()
        .flex_col()
        .gap_2()
        .hover(|card| card.border_color(accent().opacity(0.5)))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .text_xs()
                        .text_color(text_muted())
                        .child(format!("ATTEMPT {:02}", attempt.index + 1)),
                )
                .child(
                    div()
                        .px_2()
                        .py_0p5()
                        .rounded_full()
                        .bg(color.opacity(0.12))
                        .text_xs()
                        .text_color(color)
                        .child(attempt.status.label()),
                ),
        )
        .child(
            div()
                .text_sm()
                .text_color(text_primary())
                .truncate()
                .child(file_name),
        )
        .child(
            div()
                .text_xs()
                .text_color(text_muted())
                .truncate()
                .child(attempt.focus_file.clone()),
        )
        .child(div().flex_1())
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .text_xs()
                .text_color(text_muted())
                .child(if attempt.max_turns > 0 {
                    format!("Turn {} / {}", attempt.turn, attempt.max_turns)
                } else {
                    "Waiting".into()
                })
                .child(compact_number(attempt.input_tokens + attempt.output_tokens)),
        )
        .child(
            div().h(px(3.0)).w_full().rounded_full().bg(border()).child(
                div()
                    .h_full()
                    .w(px((236.0 * progress).max(if progress > 0.0 {
                        4.0
                    } else {
                        0.0
                    })))
                    .rounded_full()
                    .bg(color),
            ),
        )
}

fn render_activity_row(activity: Option<&Activity>) -> Div {
    let Some(activity) = activity else {
        return div();
    };
    let color = activity_tone_color(activity.tone);
    div()
        .min_h(px(56.0))
        .px_4()
        .py_2()
        .border_b_1()
        .border_color(border())
        .flex()
        .items_start()
        .gap_3()
        .child(div().mt_1().size(px(7.0)).rounded_full().bg(color))
        .child(
            div()
                .w(px(62.0))
                .text_xs()
                .text_color(text_muted())
                .child(activity.at.clone()),
        )
        .child(
            div()
                .flex_1()
                .flex()
                .flex_col()
                .gap_0p5()
                .child(
                    div()
                        .text_xs()
                        .text_color(text_primary())
                        .child(activity.label.clone()),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(text_muted())
                        .truncate()
                        .child(activity.detail.clone()),
                ),
        )
        .when_some(activity.attempt_index, |row, index| {
            row.child(
                div()
                    .text_xs()
                    .text_color(text_muted())
                    .child(format!("#{:02}", index + 1)),
            )
        })
}

fn render_console_row(line: &str) -> Div {
    div()
        .min_h(px(28.0))
        .px_4()
        .py_1()
        .border_b_1()
        .border_color(border().opacity(0.65))
        .font_family("SF Mono")
        .text_xs()
        .text_color(if line.starts_with("stderr ·") {
            warning()
        } else {
            text_secondary()
        })
        .child(line.to_string())
}

fn render_attempt_inspector(attempt: AttemptState) -> Div {
    let token_total = attempt.input_tokens + attempt.output_tokens;
    div()
        .flex()
        .flex_col()
        .gap_4()
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_xs()
                        .text_color(text_muted())
                        .child(format!("ATTEMPT {:02}", attempt.index + 1)),
                )
                .child(
                    div()
                        .text_base()
                        .text_color(text_primary())
                        .child(attempt.focus_file),
                ),
        )
        .child(inspector_pair("STATUS", attempt.status.label()))
        .child(inspector_pair(
            "TURN",
            if attempt.max_turns > 0 {
                format!("{} of {}", attempt.turn, attempt.max_turns)
            } else {
                "Waiting".into()
            },
        ))
        .child(inspector_pair("TOKENS", compact_number(token_total)))
        .when(attempt.cost_usd > 0.0, |panel| {
            panel.child(inspector_pair("COST", format!("${:.4}", attempt.cost_usd)))
        })
        .when_some(attempt.outcome, |panel, outcome| {
            panel.child(inspector_pair("OUTCOME", outcome))
        })
        .child(
            div()
                .pt_3()
                .border_t_1()
                .border_color(border())
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_xs()
                        .text_color(text_muted())
                        .child("CURRENT ACTIVITY"),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(text_secondary())
                        .child(attempt.last_action),
                ),
        )
}

fn render_run_inspector(state: &RunState) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_4()
        .child(
            div()
                .text_base()
                .text_color(text_primary())
                .child("Run overview"),
        )
        .child(inspector_pair(
            "PROJECT",
            state.project_id.clone().unwrap_or_else(|| "Pending".into()),
        ))
        .child(inspector_pair(
            "RUN ID",
            state.run_id.clone().unwrap_or_else(|| "Pending".into()),
        ))
        .child(inspector_pair("ATTEMPTS", state.attempts.len().to_string()))
        .child(inspector_pair(
            "FAILED",
            state.failed_attempts().to_string(),
        ))
}

fn inspector_pair(label: &'static str, value: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(div().text_xs().text_color(text_muted()).child(label))
        .child(
            div()
                .text_xs()
                .text_color(text_secondary())
                .child(value.into()),
        )
}

fn metric(label: &'static str, value: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_col()
        .items_end()
        .gap_0p5()
        .child(div().text_xs().text_color(text_muted()).child(label))
        .child(
            div()
                .text_xs()
                .text_color(text_primary())
                .child(value.into()),
        )
}

fn section_label(label: &'static str) -> Div {
    div().text_xs().text_color(text_muted()).child(label)
}

fn vertical_rule() -> Div {
    div().w(px(1.0)).h(px(34.0)).mx_1().bg(border())
}

fn compact_number(value: u64) -> String {
    if value >= 1_000_000 {
        format!("{:.1}m", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.1}k", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
}

fn open_path(path: &Path) {
    let _ = Command::new("open").arg(path).spawn();
}

fn background() -> Hsla {
    rgb(0x0a0f14).into()
}
fn surface() -> Hsla {
    rgb(0x0f161e).into()
}
fn surface_raised() -> Hsla {
    rgb(0x141d27).into()
}
fn border() -> Hsla {
    rgb(0x24303d).into()
}
fn border_strong() -> Hsla {
    rgb(0x344354).into()
}
fn text_primary() -> Hsla {
    rgb(0xe8eef5).into()
}
fn text_secondary() -> Hsla {
    rgb(0xaebac7).into()
}
fn text_muted() -> Hsla {
    rgb(0x718092).into()
}
fn accent() -> Hsla {
    rgb(0x52e0c4).into()
}
fn success() -> Hsla {
    rgb(0x64d98b).into()
}
fn warning() -> Hsla {
    rgb(0xf0bd67).into()
}
fn danger() -> Hsla {
    rgb(0xf07178).into()
}

fn run_status_color(status: RunStatus) -> Hsla {
    match status {
        RunStatus::Idle => text_muted(),
        RunStatus::Running => accent(),
        RunStatus::Cancelling | RunStatus::Cancelled => warning(),
        RunStatus::Succeeded => success(),
        RunStatus::Failed => danger(),
    }
}

fn stage_status_color(status: StageStatus) -> Hsla {
    match status {
        StageStatus::Pending => border_strong(),
        StageStatus::Active => accent(),
        StageStatus::Complete => success(),
        StageStatus::Skipped => text_muted(),
        StageStatus::Failed => danger(),
    }
}

fn attempt_status_color(status: AttemptStatus) -> Hsla {
    match status {
        AttemptStatus::Queued => text_muted(),
        AttemptStatus::Running => accent(),
        AttemptStatus::Validating => warning(),
        AttemptStatus::Complete => success(),
        AttemptStatus::Failed => danger(),
    }
}

fn activity_tone_color(tone: ActivityTone) -> Hsla {
    match tone {
        ActivityTone::Neutral => text_muted(),
        ActivityTone::Accent => accent(),
        ActivityTone::Success => success(),
        ActivityTone::Warning => warning(),
        ActivityTone::Danger => danger(),
    }
}

#[cfg(target_os = "macos")]
fn main() {
    application().run(|cx: &mut App| {
        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();

        let bounds = Bounds::centered(None, size(px(WINDOW_WIDTH), px(WINDOW_HEIGHT)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |_, cx| cx.new(|_| DeepSecDashboard::new()),
        )
        .expect("could not open the DeepSec GPUI window");
        cx.activate(true);
    });
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("The DeepSec GPUI prototype currently supports macOS only.");
}
