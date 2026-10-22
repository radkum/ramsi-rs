mod process_info;

use std::{fs, path::Path};

pub(crate) use process_info::ProcessInfo;
use shared::ScanEvent;

pub fn dump(event: &ScanEvent, dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file_name = format!(
        "{}\\{}_{}_{}_{}",
        dir.display(),
        event.pid,
        event.tid,
        event.request_number,
        sanitize_file_name(&event.content_name)
    );
    let info_file_name = format!("{}.info", file_name.as_str());
    let dump_file_name = format!("{}.dmp", file_name.as_str());
    let script_file_name = format!("{}.txt", file_name.as_str());

    fs::write(
        info_file_name,
        format!(
            "cmd_line: '{}'\r\napp_name: {}\r\ncontent_name: {}\r\nsession: {}",
            event.cmd_line, event.app_name, event.content_name, event.session
        ),
    )?;
    fs::write(dump_file_name, &event.content)?;
    fs::write(script_file_name, &event.content)?;

    Ok(())
}

// content_name may be any path or URL
fn sanitize_file_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .take(100)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitized_file_name_has_no_reserved_chars() {
        assert_eq!(
            sanitize_file_name("https://x/a?b=*|\"<>\0C:\\dir\\f.ps1"),
            "https___x_a_b=______C__dir_f.ps1"
        );
        assert_eq!(sanitize_file_name(&"a".repeat(300)).len(), 100);
    }
}
