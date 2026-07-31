use std::{
    io::{BufRead, BufReader},
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI32, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use async_channel::{Receiver, Sender};
use serde_json::Value;

use crate::model::parse_protocol_line;

// Bundle the reviewed harness with the UI so launching a run does not need to
// read the script from disk. DEEPSEC_HARNESS_ROOT still points the script at
// the checkout for the CLI, packages, fixtures, and output directories.
const HARNESS_SOURCE: &str = include_str!("../../../scripts/explore-harness.sh");

#[derive(Clone, Debug)]
pub struct LaunchConfig {
    pub repo_root: PathBuf,
    pub target_root: PathBuf,
    pub limit: usize,
    pub concurrency: usize,
    pub simulation: bool,
    pub include_attempts: bool,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub data_root: Option<PathBuf>,
}

impl LaunchConfig {
    pub fn initial() -> Self {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
        let target_root = repo_root.clone();
        Self {
            repo_root,
            target_root,
            limit: 3,
            concurrency: 1,
            simulation: true,
            include_attempts: false,
            project_id: None,
            run_id: None,
            data_root: None,
        }
    }

    fn command(&self, retry: bool) -> Result<Command> {
        let harness = self.repo_root.join("scripts/explore-harness.sh");
        if !harness.is_file() {
            bail!("DeepSec harness not found at {}", harness.display());
        }
        if !self.target_root.is_dir() {
            bail!(
                "Target folder does not exist: {}",
                self.target_root.display()
            );
        }
        let mut command = Command::new("/bin/bash");
        command
            .arg("-c")
            .arg(HARNESS_SOURCE)
            .arg(harness)
            .arg("--root")
            .arg(&self.target_root)
            .arg("--limit")
            .arg(self.limit.to_string())
            .arg("--concurrency")
            .arg(self.concurrency.to_string())
            .arg("--verify-manifest");

        if self.simulation {
            command.arg("--stub-model");
        }
        if self.include_attempts {
            command.arg("--include-attempts");
        }
        if retry {
            let project_id = self
                .project_id
                .as_deref()
                .context("Retry requires a project id from the previous run")?;
            let run_id = self
                .run_id
                .as_deref()
                .context("Retry requires a run id from the previous run")?;
            let data_root = self
                .data_root
                .as_ref()
                .context("Retry requires the data root from the previous run")?;
            command
                .arg("--project-id")
                .arg(project_id)
                .arg("--retry-run-id")
                .arg(run_id)
                .arg("--skip-setup")
                .env("DEEPSEC_DATA_ROOT", data_root);
        }

        command
            // A Finder-launched app can inherit an inaccessible working
            // directory under macOS privacy controls. Start bash from `/`;
            // the embedded harness changes to its explicit checkout root.
            .current_dir("/")
            .env("DEEPSEC_HARNESS_ROOT", &self.repo_root)
            .env("DEEPSEC_HARNESS_NO_CHDIR", "1")
            .env("DEEPSEC_EVENT_STREAM", "1")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        if let Some(cli) = packaged_cli() {
            command.env("DEEPSEC_HARNESS_CLI", cli);
        }
        Ok(command)
    }
}

fn packaged_cli() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let contents = executable.parent()?.parent()?;
    let cli = contents.join("Resources/deepsec-cli/cli.mjs");
    cli.is_file().then_some(cli)
}

#[derive(Debug)]
pub enum WorkerMessage {
    Event(Value),
    Console(String),
    Started(u32),
    StartFailed(String),
    Exited { code: i32, cancelled: bool },
}

#[derive(Clone)]
pub struct RunControl {
    process_group: Arc<AtomicI32>,
    cancelled: Arc<AtomicBool>,
}

impl RunControl {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let process_group = self.process_group.load(Ordering::Acquire);
        if process_group <= 0 {
            return;
        }
        // The harness owns Docker and model subprocesses, so cancellation is
        // intentionally sent to its whole process group rather than only bash.
        unsafe {
            libc::kill(-process_group, libc::SIGTERM);
        }
        let process_group_handle = self.process_group.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(2));
            if process_group_handle.load(Ordering::Acquire) == process_group {
                unsafe {
                    libc::kill(-process_group, libc::SIGKILL);
                }
            }
        });
    }
}

pub fn spawn_harness(
    config: LaunchConfig,
    retry: bool,
) -> Result<(RunControl, Receiver<WorkerMessage>)> {
    let (sender, receiver) = async_channel::bounded(2_048);
    let process_group = Arc::new(AtomicI32::new(0));
    let cancelled = Arc::new(AtomicBool::new(false));
    let control = RunControl {
        process_group: process_group.clone(),
        cancelled: cancelled.clone(),
    };

    thread::Builder::new()
        .name("deepsec-harness".into())
        .spawn(move || {
            // Command construction performs target validation. Keep it on the
            // worker along with all process and filesystem work so a slow
            // volume can never stall GPUI's main thread.
            let mut command = match config.command(retry) {
                Ok(command) => command,
                Err(error) => {
                    let _ = sender.send_blocking(WorkerMessage::StartFailed(error.to_string()));
                    return;
                }
            };
            mark_open_fds_close_on_exec();
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(error) => {
                    let _ = sender.send_blocking(WorkerMessage::StartFailed(error.to_string()));
                    return;
                }
            };
            let pid = child.id();
            process_group.store(pid as i32, Ordering::Release);
            let _ = sender.send_blocking(WorkerMessage::Started(pid));

            let stdout_reader = child.stdout.take().map(|stdout| {
                let sender = sender.clone();
                thread::Builder::new()
                    .name("deepsec-stdout".into())
                    .spawn(move || read_lines(BufReader::new(stdout), sender, false))
            });
            let stderr_reader = child.stderr.take().map(|stderr| {
                let sender = sender.clone();
                thread::Builder::new()
                    .name("deepsec-stderr".into())
                    .spawn(move || read_lines(BufReader::new(stderr), sender, true))
            });

            let exit_code = child
                .wait()
                .ok()
                .and_then(|status| status.code())
                .unwrap_or(1);
            if let Some(Ok(handle)) = stdout_reader {
                let _ = handle.join();
            }
            if let Some(Ok(handle)) = stderr_reader {
                let _ = handle.join();
            }
            process_group.store(0, Ordering::Release);
            let _ = sender.send_blocking(WorkerMessage::Exited {
                code: exit_code,
                cancelled: cancelled.load(Ordering::Acquire),
            });
        })
        .context("Could not start the DeepSec harness worker thread")?;

    Ok((control, receiver))
}

fn mark_open_fds_close_on_exec() {
    // Metal keeps a handful of cache descriptors open without FD_CLOEXEC.
    // They are valid in GPUI but should never leak into bash, Node, Docker,
    // or gVisor. Marking existing descriptors here preserves them in the app
    // while ensuring the harness gets a conventional 0/1/2-only process.
    for fd in 3..1_024 {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
}

fn read_lines<R: std::io::Read>(reader: BufReader<R>, sender: Sender<WorkerMessage>, stderr: bool) {
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                let _ = sender.send_blocking(WorkerMessage::Console(format!(
                    "Output stream error: {error}"
                )));
                break;
            }
        };
        if !stderr && let Some(parsed) = parse_protocol_line(&line) {
            match parsed {
                Ok(event) => {
                    if sender.send_blocking(WorkerMessage::Event(event)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    if sender
                        .send_blocking(WorkerMessage::Console(format!(
                            "Invalid event record: {error}"
                        )))
                        .is_err()
                    {
                        break;
                    }
                }
            }
            continue;
        }
        let line = if stderr {
            format!("stderr · {line}")
        } else {
            line
        };
        if sender.send_blocking(WorkerMessage::Console(line)).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_points_at_the_repo_harness() {
        let config = LaunchConfig::initial();
        assert!(
            config
                .repo_root
                .join("scripts/explore-harness.sh")
                .is_file()
        );
        assert!(config.command(false).is_ok());
    }
}
