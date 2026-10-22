mod pipe_client;
use std::sync::{LazyLock, atomic::Ordering};

use log::{debug, error};
pub use pipe_client::PipeClient;
use shared::ScanEvent;
use tokio::runtime::Runtime;
use windows::Win32::System::Antimalware::*;

use super::{Ramsi_Impl, ScanResult};
use crate::utils::dump;
static RUNTIME: LazyLock<Option<Runtime>> = LazyLock::new(|| Runtime::new().ok());
impl Ramsi_Impl {
    pub fn report_script(
        &self,
        stream: &IAmsiStream,
        content: String,
        result: ScanResult,
        blocked: bool,
    ) {
        let process_info = &self.process_info;
        let mut amsi_event = ScanEvent {
            time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            pid: process_info.pid(),
            tid: process_info.tid(),
            process: process_info.file_name().to_string(),
            cmd_line: process_info.cmd_line().to_string(),
            app_name: Self::string_attribute(stream, AMSI_ATTRIBUTE_APP_NAME),
            content_name: Self::string_attribute(stream, AMSI_ATTRIBUTE_CONTENT_NAME),
            session: Self::u64_attribute::<u64>(stream, AMSI_ATTRIBUTE_SESSION),
            request_number: self.request_number.fetch_add(1, Ordering::AcqRel) + 1,
            status: result.status,
            reason: result.reason,
            blocked,
            content,
            content_truncated: false,
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
                if !self.pipe_client.read().await.active()
                    && let Err(err) = self.pipe_client.write().await.connect()
                {
                    error!("{err}");
                    return;
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
