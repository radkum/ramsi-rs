mod process_info;

pub(crate) use process_info::ProcessInfo;

use std::{fmt, fs};

#[derive(Default)]
pub struct AmsiEvent {
    process_info: ProcessInfo,
    app_name: String, // name, version, or GUID string of the calling application,
    content_name: String, // filename, URL, unique script ID, or similar of the content
    content: Vec<u8>, // content if it's already loaded to memory
    session: u64,     // session is used to associate different scan calls,
    // such as if the contents to be scanned belong to the sample original script
    request_number: u32, // number of call from one session
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
                "exe_file_name: {:?}\r\napp_name: {}\r\ncontent_name: {}\r\nsession: {}",
                self.process_info.file_name(), self.app_name, self.content_name, self.session
            ),
        )?;
        fs::write(dump_file_name, self.content.as_slice())?;
        fs::write(
            script_file_name,
            super::Ramsi_Impl::string_from_vec(self.content.clone()),
        )?;

        Ok(())
    }

    pub fn content_name(&self) -> String {
        self.content_name.clone()
    }

    pub fn new(
        process_info: ProcessInfo,
        app_name: String,
        content_name: String,
        content: Vec<u8>,
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

impl fmt::Display for AmsiEvent {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            fmt,
            "AmsiEvent {{ request_number: {}, content_name: {}, app_name: {} }}",
            self.request_number, self.content_name, self.app_name,
        )
    }
}
