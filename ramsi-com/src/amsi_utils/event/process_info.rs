use std::{
    env::current_exe,
    path::{Path, PathBuf},
    process,
};

use windows::Win32::System::Threading::GetCurrentThreadId;

use crate::winapi::get_command_line_from_pid;

#[derive(Default, Clone)]
pub(crate) struct ProcessInfo {
    pid: u32,
    tid: u32,
    file_name: String,
    file_path: PathBuf,
    cmd_line: String,
}

impl ProcessInfo {
    pub fn current() -> Self {
        let pid = process::id();
        let tid = unsafe { GetCurrentThreadId() };

        let file_path = current_exe().ok().unwrap_or_default();
        let file_name = current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
            .unwrap_or_default();
        let cmd_line = get_command_line_from_pid(pid).unwrap_or_default();
        Self {
            pid,
            tid,
            file_name,
            file_path,
            cmd_line,
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn tid(&self) -> u32 {
        self.tid
    }

    #[allow(unused)]
    pub fn file_name(&self) -> &str {
        self.file_name.as_str()
    }

    #[allow(unused)]
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    pub fn cmd_line(&self) -> &str {
        &self.cmd_line
    }
}
