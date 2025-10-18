use std::{env::current_exe, process};

use windows::Win32::System::Threading::GetCurrentThreadId;

#[derive(Default, Clone)]
pub(crate) struct ProcessInfo {
    pid: u32,
    tid: u32,
    file_name: Option<String>,
}

impl ProcessInfo {
    pub fn current() -> Self {
        let pid = process::id();
        let tid = unsafe { GetCurrentThreadId() as u32 };

        let file_name = current_exe().ok().map(|p| p.to_string_lossy().to_string());
        Self {
            pid,
            tid,
            file_name,
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn tid(&self) -> u32 {
        self.tid
    }

    pub fn file_name(&self) -> Option<String> {
        self.file_name.clone()
    }
}
