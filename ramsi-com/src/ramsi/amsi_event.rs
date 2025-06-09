use std::{fmt, fs};

#[derive(Default, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub tid: u32,
    pub process_file_name: String,
}

impl ProcessInfo {
    pub fn current() -> Self {
        let pid = std::process::id();
        let tid = unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() as u32 };
        let curr_path = std::env::current_exe().unwrap_or_default();
        let process_file_name = curr_path.to_string_lossy().to_string();

        Self {
            pid,
            tid,
            process_file_name,
        }
    }
}

#[derive(Default)]
pub struct AmsiEvent {
    pub process_info: ProcessInfo,
    pub app_name: String, // name, version, or GUID string of the calling application,
    pub content_name: String, // filename, URL, unique script ID, or similar of the content
    pub content: Vec<u8>, // content if it's already loaded to memory
    pub session: u64,     // session is used to associate different scan calls,
    // such as if the contents to be scanned belong to the sample original script
    pub request_number: u32, // number of call from one session
}

impl AmsiEvent {
    pub fn dump(&self) -> Result<(), Box<dyn std::error::Error>> {
        let dir = "C:\\ramsi";
        if !fs::exists(dir).unwrap_or_default() {
            fs::create_dir(dir)?;
        }

        let file_name = format!(
            "{}\\{}_{}_{}_{}",
            dir,
            self.process_info.pid,
            self.process_info.tid,
            self.request_number,
            self.content_name.replace("\\", "_").replace(":", "_")
        );
        let info_file_name = format!("{}.info", file_name.as_str());
        let dump_file_name = format!("{}.dmp", file_name.as_str());
        let script_file_name = format!("{}.txt", file_name.as_str());

        fs::write(
            info_file_name,
            format!(
                "exe_file_name: {}\r\napp_name: {}\r\ncontent_name: {}\r\nsession: {}",
                self.process_info.process_file_name, self.app_name, self.content_name, self.session
            ),
        )?;
        fs::write(dump_file_name, self.content.as_slice())?;
        fs::write(
            script_file_name,
            super::Ramsi_Impl::string_from_vec(self.content.clone()),
        )?;

        Ok(())
    }
}

impl fmt::Display for AmsiEvent {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            fmt,
            "AmsiEvent {{ request_number: {}, content_name: {}, app_name: {} }}",
            self.request_number, self.content_name, self.app_name,
        )
    }
}
