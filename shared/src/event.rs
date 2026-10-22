use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Clean,
    Detected,
    Suspicious,
    NotDetected,
}

// sent by the provider over the pipe as JSON
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanEvent {
    pub time: String,
    pub pid: u32,
    pub tid: u32,
    pub process: String,
    pub cmd_line: String,
    pub app_name: String,
    pub content_name: String,
    pub session: u64,
    pub request_number: u32,
    pub status: ScanStatus,
    pub reason: Option<String>,
    pub blocked: bool,
    pub content: String,
    pub content_truncated: bool,
}

impl ScanEvent {
    pub fn truncate_content(&mut self, max_len: usize) {
        if self.content.len() > max_len {
            self.content
                .truncate(self.content.floor_char_boundary(max_len));
            self.content_truncated = true;
        }
    }
}

impl std::fmt::Display for ScanEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let app_name = if self
            .app_name
            .to_ascii_lowercase()
            .starts_with("powershell_")
        {
            "PowerShell"
        } else {
            &self.app_name
        };
        write!(
            f,
            "{} {:?}{} pid: {}, app: {}, content: {}, reason: {}",
            self.time,
            self.status,
            if self.blocked { " (blocked)" } else { "" },
            self.pid,
            app_name,
            if self.content_name.is_empty() {
                "<command>"
            } else {
                &self.content_name
            },
            self.reason.as_deref().unwrap_or("-"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(content: &str) -> ScanEvent {
        ScanEvent {
            time: "2026-10-22T10:00:00Z".into(),
            pid: 1,
            tid: 2,
            process: "powershell.exe".into(),
            cmd_line: "powershell".into(),
            app_name: "PowerShell_C:\\powershell.exe_10.0".into(),
            content_name: String::new(),
            session: 3,
            request_number: 4,
            status: ScanStatus::Detected,
            reason: Some("keyword".into()),
            blocked: true,
            content: content.into(),
            content_truncated: false,
        }
    }

    #[test]
    fn truncates_on_char_boundary() {
        let mut e = event("ab\u{17c}c");
        e.truncate_content(3);
        assert_eq!(e.content, "ab");
        assert!(e.content_truncated);

        let mut e = event("abc");
        e.truncate_content(3);
        assert_eq!(e.content, "abc");
        assert!(!e.content_truncated);
    }

    #[test]
    fn json_round_trip() {
        let e = event("iex x");
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains(r#""status":"detected""#), "{json}");
        assert_eq!(serde_json::from_str::<ScanEvent>(&json).unwrap(), e);
    }

    #[test]
    fn display_is_one_line() {
        assert_eq!(
            event("x").to_string(),
            "2026-10-22T10:00:00Z Detected (blocked) pid: 1, app: PowerShell, content: <command>, \
             reason: keyword"
        );
    }
}
