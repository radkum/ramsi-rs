mod process_info;

use std::{fmt, fs, path::PathBuf};

pub(crate) use process_info::ProcessInfo;

#[derive(Default)]
pub struct RamsiEvent {
    process_info: ProcessInfo,
    app_name: String, // name, version, or GUID string of the calling application,
    content_name: String, // filename, URL, unique script ID, or similar of the content
    content: String,  // content if it's already loaded to memory
    session: u64,     // session is used to associate different scan calls,
    // such as if the contents to be scanned belong to the sample original script
    request_number: u32, // number of call from one session
}

impl RamsiEvent {
    #[allow(dead_code)]
    pub fn dump(&self) -> Result<(), Box<dyn std::error::Error>> {
        let dir = "C:\\ramsi";
        if !fs::exists(dir).unwrap_or_default() {
            fs::create_dir(dir)?;
        }

        let file_name = format!(
            "{}\\{}_{}_{}_{}",
            dir,
            self.process_info.pid(),
            self.process_info.tid(),
            self.request_number,
            self.content_name.replace("\\", "_").replace(":", "_")
        );
        let info_file_name = format!("{}.info", file_name.as_str());
        let dump_file_name = format!("{}.dmp", file_name.as_str());
        let script_file_name = format!("{}.txt", file_name.as_str());

        fs::write(
            info_file_name,
            format!(
                "cmd_line: '{}'\r\napp_name: {}\r\ncontent_name: {}\r\nsession: {}",
                self.process_info.cmd_line(),
                self.app_name,
                self.content_name,
                self.session
            ),
        )?;
        fs::write(dump_file_name, &self.content)?;
        fs::write(script_file_name, &self.content)?;

        Ok(())
    }

    pub fn new(
        process_info: ProcessInfo,
        app_name: String,
        content_name: String,
        content: String,
        session: u64,
        request_number: u32,
    ) -> Self {
        Self {
            process_info,
            app_name,
            content_name,
            content,
            session,
            request_number,
        }
    }
}

impl fmt::Display for RamsiEvent {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let content_name = if self.content_name.is_empty() {
            "<empty>".to_string()
        } else {
            let path_content_name = PathBuf::from(&self.content_name);
            if path_content_name.is_file() {
                path_content_name
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            } else {
                self.content_name.clone()
            }
        };

        const POWERSHELL_APP_PREFIX: &str = "powershell_";
        const POWERSHELL_APP: &str = "PowerShell";
        let app_name = if self.app_name.is_empty() {
            "<empty>".to_string()
        } else if self
            .app_name
            .to_ascii_lowercase()
            .starts_with(POWERSHELL_APP_PREFIX)
        {
            POWERSHELL_APP.to_string()
        } else {
            self.app_name.clone()
        };

        write!(
            fmt,
            "AmsiEvent {{ request_number: {}, content_name: {}, app_name: {} }}",
            self.request_number, content_name, app_name,
        )
    }
}
