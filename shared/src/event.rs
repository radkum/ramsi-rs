use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Clean,
    Detected,
    Suspicious,
    NotDetected,
}

// a configured command with its arguments as the parser evaluated them
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Command {
    pub name: String,
    pub args: Vec<String>,
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
    // older providers do not send these
    #[serde(default)]
    pub commands: Vec<Command>,
    #[serde(default)]
    pub commands_truncated: bool,
    // set by the trace server from the pipe client process, never by the provider
    pub process_created: Option<String>,
    pub user_sid: Option<String>,
}

impl ScanEvent {
    // commands and content share max_len, commands first
    pub fn truncate_content(&mut self, max_len: usize) {
        let mut left = max_len;
        let cut = &mut self.commands_truncated;
        self.commands.retain_mut(|command| {
            let Some(rest) = left.checked_sub(command.name.len()) else {
                *cut = true;
                return false;
            };
            left = rest;
            command.args.retain_mut(|arg| {
                let len = arg.len();
                arg.truncate(arg.floor_char_boundary(left));
                left -= arg.len();
                *cut |= arg.len() < len;
                !arg.is_empty() || len == 0
            });
            true
        });
        if self.content.len() > left {
            self.content
                .truncate(self.content.floor_char_boundary(left));
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
            commands: Vec::new(),
            commands_truncated: false,
            process_created: None,
            user_sid: None,
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
    fn commands_share_the_limit_with_content() {
        let mut e = event("abcdef");
        e.commands = vec![
            Command {
                name: "ab".into(),
                args: vec!["cd".into(), "efgh".into(), "ij".into()],
            },
            Command {
                name: "kl".into(),
                args: vec![],
            },
        ];
        e.truncate_content(6);
        assert_eq!(
            e.commands,
            [Command {
                name: "ab".into(),
                args: vec!["cd".into(), "ef".into()],
            }]
        );
        assert_eq!(e.content, "");
        assert!(e.commands_truncated && e.content_truncated);
    }

    #[test]
    fn commands_default_to_empty() {
        let mut json = serde_json::to_value(event("x")).unwrap();
        json.as_object_mut().unwrap().remove("commands");
        let e: ScanEvent = serde_json::from_value(json).unwrap();
        assert!(e.commands.is_empty());
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
