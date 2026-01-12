mod pipe_client;
use std::sync::{LazyLock, atomic::Ordering};

use log::{debug, error};
pub use pipe_client::PipeClient;
use shared::RamsiMessage;
use tokio::runtime::Runtime;
use windows::Win32::System::Antimalware::*;

use super::Ramsi_Impl;
use crate::utils::RamsiEvent;
static RUNTIME: LazyLock<Option<Runtime>> = LazyLock::new(|| Runtime::new().ok());
impl Ramsi_Impl {
    pub fn report_script(&self, stream: &IAmsiStream) {
        let app_name = Self::string_attribute(stream, AMSI_ATTRIBUTE_APP_NAME);
        let content_name = Self::string_attribute(stream, AMSI_ATTRIBUTE_CONTENT_NAME);
        let session = Self::u64_attribute::<u64>(stream, AMSI_ATTRIBUTE_SESSION);
        let content = Self::get_content(stream);
        let process_info = self.process_info.clone();

        let request_num = self.request_number.load(Ordering::Acquire) + 1;
        self.request_number.store(request_num, Ordering::Release);

        let amsi_event = RamsiEvent::new(
            process_info,
            app_name,
            content_name,
            content,
            session,
            request_num,
        );

        debug!("{}", amsi_event);

        // only for debug purpose
        #[cfg(debug_assertions)]
        let _ = amsi_event.dump();

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
                    .send(RamsiMessage::new(&amsi_event.to_string()))
                    .await
                    .inspect_err(|e| error!("{e}"));
            });
        }
    }
}
