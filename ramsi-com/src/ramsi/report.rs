mod pipe_client;
use std::sync::{
    LazyLock,
    atomic::{AtomicBool, Ordering},
};

use log::{debug, error};
pub use pipe_client::PipeClient;
use shared::{Command, SCHEMA_VERSION, ScanEvent};
use tokio::runtime::{Builder, Runtime};
use windows::Win32::System::{Antimalware::*, Threading::GetCurrentThreadId};

use super::{Ramsi_Impl, ScanResult};
use crate::{config::command_name, utils::dump};
// a worker thread per core in every reporting process is not needed for one
// pipe
static RUNTIME: LazyLock<Option<Runtime>> =
    LazyLock::new(|| Builder::new_current_thread().enable_all().build().ok());
// logged once per outage, a missing server would otherwise log on every scan
static CONNECT_FAILED: AtomicBool = AtomicBool::new(false);
impl Ramsi_Impl {
    pub fn report_script(
        &self,
        stream: &IAmsiStream,
        app_name: String,
        content_name: String,
        content: String,
        result: ScanResult,
        blocked: bool,
    ) {
        let process_info = &self.process_info;
        let mut amsi_event = ScanEvent {
            version: SCHEMA_VERSION,
            time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            pid: process_info.pid(),
            tid: unsafe { GetCurrentThreadId() },
            process: process_info.file_name().to_string(),
            cmd_line: process_info.cmd_line().to_string(),
            app_name,
            content_name,
            session: Self::u64_attribute::<u64>(stream, AMSI_ATTRIBUTE_SESSION),
            request_number: self.request_number.fetch_add(1, Ordering::AcqRel) + 1,
            status: result.status,
            reason: result.reason,
            blocked,
            content,
            content_truncated: false,
            // a command in a function or script block is tokenized again for each call
            commands: result.commands.iter().fold(Vec::new(), |mut commands, c| {
                let command = Command {
                    name: command_name(c.name()),
                    args: c.args().clone(),
                };
                if !commands.contains(&command) {
                    commands.push(command);
                }
                commands
            }),
            commands_truncated: false,
            parse_failed: result.parse_failed,
            process_created: None,
            user_sid: None,
            parent_pid: None,
            session_id: None,
        };

        debug!("{}", amsi_event);

        // the dump keeps the full content
        if self.config.dump
            && let Err(err) = dump(&amsi_event, &self.config.log_dir)
        {
            error!("Failed to dump event: {err}");
        }
        amsi_event.truncate_content(self.config.max_content);

        if let Some(runtime) = &*RUNTIME {
            runtime.block_on(async {
                if !self.pipe_client.read().await.active() {
                    match self.pipe_client.write().await.connect() {
                        Ok(()) => CONNECT_FAILED.store(false, Ordering::Relaxed),
                        Err(err) => {
                            if !CONNECT_FAILED.swap(true, Ordering::Relaxed) {
                                error!("{err}");
                            }
                            return;
                        },
                    }
                }

                let _ = self
                    .pipe_client
                    .write()
                    .await
                    .send(amsi_event)
                    .await
                    .inspect_err(|e| error!("{e}"));
            });
        }
    }
}
