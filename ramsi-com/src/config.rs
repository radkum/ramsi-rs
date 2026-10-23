use std::path::PathBuf;

use log::LevelFilter;
use shared::{
    PipeName,
    constants::{CONFIG_KEY, DEFAULT_LOG_DIR, MAX_CONTENT_LIMIT, RAMSI_PIPE_SUFFIX, config_value},
};
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};

use crate::ScanStatus;

#[derive(Debug, PartialEq)]
pub enum Mode {
    Monitor,
    Block,
}

#[derive(Debug, PartialEq)]
pub struct Config {
    pub mode: Mode,
    // the lowest status that is blocked in block mode
    pub block_on: ScanStatus,
    pub report: bool,
    // the lowest status that is reported, NotDetected reports every scan
    pub report_on: ScanStatus,
    // lowercase app name prefixes to scan, empty scans all
    pub apps: Vec<String>,
    // commands sent with their arguments, any of them is reported whatever the status
    pub commands: Vec<String>,
    pub log_level: LevelFilter,
    pub log_dir: PathBuf,
    pub dump: bool,
    // bytes of script content sent in an event
    pub max_content: usize,
    pub pipe_name: String,
    pub rules: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Monitor,
            block_on: ScanStatus::Detected,
            report: true,
            report_on: ScanStatus::Suspicious,
            apps: Vec::new(),
            commands: Vec::new(),
            log_level: LevelFilter::Info,
            log_dir: PathBuf::from(DEFAULT_LOG_DIR),
            dump: false,
            max_content: 64 * 1024,
            pipe_name: PipeName::from_suffix(RAMSI_PIPE_SUFFIX).to_string(),
            rules: None,
        }
    }
}

impl Config {
    // missing or invalid values fall back to defaults
    pub fn load() -> Self {
        match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(CONFIG_KEY) {
            Ok(key) => Self::from_key(&key),
            Err(_) => Self::default(),
        }
    }

    pub fn blocks(&self, status: ScanStatus) -> bool {
        self.mode == Mode::Block && reaches(status, self.block_on)
    }

    pub fn reports(&self, status: ScanStatus) -> bool {
        self.report && reaches(status, self.report_on)
    }

    pub fn reports_command(&self, name: &str) -> bool {
        // Module\Command calls the same command
        let name = name.rsplit('\\').next().unwrap_or(name);
        self.report && self.commands.iter().any(|c| c.eq_ignore_ascii_case(name))
    }

    pub fn scans_app(&self, app_name: &str) -> bool {
        self.apps.is_empty()
            || self.apps.iter().any(|app| {
                app_name
                    .get(..app.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(app))
            })
    }

    fn from_key(key: &RegKey) -> Self {
        let mut config = Self::default();
        match key.get_value::<String, _>(config_value::MODE).as_deref() {
            Ok("block") => config.mode = Mode::Block,
            Ok("monitor") | Err(_) => {},
            Ok(other) => log::warn!("Unknown mode: {other}"),
        }
        if let Ok("suspicious") = key
            .get_value::<String, _>(config_value::BLOCK_ON)
            .as_deref()
        {
            config.block_on = ScanStatus::Suspicious;
        }
        if let Ok(report) = key.get_value::<u32, _>(config_value::REPORT) {
            config.report = report != 0;
        }
        match key
            .get_value::<String, _>(config_value::REPORT_ON)
            .as_deref()
        {
            Ok("detected") => config.report_on = ScanStatus::Detected,
            Ok("all") => config.report_on = ScanStatus::NotDetected,
            Ok("suspicious") | Err(_) => {},
            Ok(other) => log::warn!("Unknown report_on: {other}"),
        }
        if let Ok(apps) = key.get_value::<String, _>(config_value::APPS) {
            config.apps = split_list(&apps);
        }
        if let Ok(commands) = key.get_value::<String, _>(config_value::COMMANDS) {
            config.commands = split_list(&commands);
        }
        if let Ok(level) = key.get_value::<String, _>(config_value::LOG_LEVEL)
            && let Ok(level) = level.parse()
        {
            config.log_level = level;
        }
        if let Ok(dir) = key.get_value::<String, _>(config_value::LOG_DIR) {
            config.log_dir = dir.into();
        }
        if let Ok(dump) = key.get_value::<u32, _>(config_value::DUMP) {
            config.dump = dump != 0;
        }
        if let Ok(max_content) = key.get_value::<u32, _>(config_value::MAX_CONTENT) {
            config.max_content = max_content.min(MAX_CONTENT_LIMIT) as usize;
        }
        if let Ok(suffix) = key.get_value::<String, _>(config_value::PIPE) {
            let pipe_name = PipeName::from_suffix(&suffix);
            if pipe_name.verify().is_ok() {
                config.pipe_name = pipe_name.to_string();
            }
        }
        if let Ok(rules) = key.get_value::<String, _>(config_value::RULES) {
            config.rules = Some(rules.into());
        }
        config
    }
}

// whether status is at least as severe as lowest, NotDetected being the least
fn reaches(status: ScanStatus, lowest: ScanStatus) -> bool {
    match status {
        ScanStatus::Detected => true,
        ScanStatus::Suspicious => lowest != ScanStatus::Detected,
        ScanStatus::Clean | ScanStatus::NotDetected => lowest == ScanStatus::NotDetected,
    }
}

// lowercase, ';'-separated, empty entries dropped
fn split_list(list: &str) -> Vec<String> {
    list.split(';')
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use winreg::enums::HKEY_CURRENT_USER;

    use super::*;

    struct TempKey(String, RegKey);

    impl TempKey {
        fn new(test: &str) -> Self {
            let path = format!("Software\\RamsiTest-{test}-{}", std::process::id());
            let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&path)
                .unwrap();
            Self(path, key)
        }
    }

    impl Drop for TempKey {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
        }
    }

    #[test]
    fn empty_key_gives_defaults() {
        let key = TempKey::new("empty");
        assert_eq!(Config::from_key(&key.1), Config::default());
    }

    #[test]
    fn values_are_read() {
        let key = TempKey::new("values");
        key.1.set_value(config_value::MODE, &"block").unwrap();
        key.1
            .set_value(config_value::BLOCK_ON, &"suspicious")
            .unwrap();
        key.1.set_value(config_value::REPORT, &0u32).unwrap();
        key.1.set_value(config_value::REPORT_ON, &"all").unwrap();
        key.1
            .set_value(config_value::APPS, &"PowerShell_; ;OtherApp")
            .unwrap();
        key.1
            .set_value(
                config_value::COMMANDS,
                &"Register-ScheduledTask; ;New-Service",
            )
            .unwrap();
        key.1.set_value(config_value::LOG_LEVEL, &"debug").unwrap();
        key.1.set_value(config_value::LOG_DIR, &"D:\\logs").unwrap();
        key.1.set_value(config_value::DUMP, &1u32).unwrap();
        key.1.set_value(config_value::MAX_CONTENT, &10u32).unwrap();
        key.1.set_value(config_value::PIPE, &"other").unwrap();
        key.1
            .set_value(config_value::RULES, &"C:\\rules.toml")
            .unwrap();

        let config = Config::from_key(&key.1);

        assert_eq!(config.mode, Mode::Block);
        assert_eq!(config.block_on, ScanStatus::Suspicious);
        assert!(!config.report);
        assert_eq!(config.report_on, ScanStatus::NotDetected);
        assert_eq!(config.apps, ["powershell_", "otherapp"]);
        assert_eq!(config.commands, ["register-scheduledtask", "new-service"]);
        assert_eq!(config.log_level, LevelFilter::Debug);
        assert_eq!(config.log_dir, PathBuf::from("D:\\logs"));
        assert!(config.dump);
        assert_eq!(config.max_content, 10);
        assert_eq!(config.pipe_name, r"\\.\pipe\other");
        assert_eq!(config.rules, Some(PathBuf::from("C:\\rules.toml")));
    }

    #[test]
    fn invalid_values_fall_back_to_defaults() {
        let key = TempKey::new("invalid");
        key.1.set_value(config_value::MODE, &"loud").unwrap();
        key.1.set_value(config_value::BLOCK_ON, &"loud").unwrap();
        key.1.set_value(config_value::REPORT_ON, &"loud").unwrap();
        key.1.set_value(config_value::LOG_LEVEL, &"loud").unwrap();
        key.1.set_value(config_value::PIPE, &"a|b").unwrap();

        assert_eq!(Config::from_key(&key.1), Config::default());
    }

    #[test]
    fn max_content_is_capped() {
        let key = TempKey::new("max-content");
        key.1
            .set_value(config_value::MAX_CONTENT, &u32::MAX)
            .unwrap();

        let config = Config::from_key(&key.1);

        assert_eq!(config.max_content, MAX_CONTENT_LIMIT as usize);
    }

    #[test]
    fn apps_filter_by_prefix() {
        assert!(Config::default().scans_app("anything"));

        let config = Config {
            apps: vec!["powershell_".into()],
            ..Config::default()
        };
        assert!(config.scans_app("PowerShell_C:\\Windows\\powershell.exe_10.0"));
        assert!(!config.scans_app("JScript"));
    }

    #[test]
    fn reports_from_report_on() {
        let default = Config::default();
        assert!(default.reports(ScanStatus::Detected));
        assert!(default.reports(ScanStatus::Suspicious));
        assert!(!default.reports(ScanStatus::NotDetected));

        let detected = Config {
            report_on: ScanStatus::Detected,
            ..Config::default()
        };
        assert!(!detected.reports(ScanStatus::Suspicious));

        let all = Config {
            report_on: ScanStatus::NotDetected,
            ..Config::default()
        };
        assert!(all.reports(ScanStatus::NotDetected));
        assert!(all.reports(ScanStatus::Clean));

        let off = Config {
            report: false,
            ..all
        };
        assert!(!off.reports(ScanStatus::Detected));
    }

    #[test]
    fn reports_configured_commands() {
        let config = Config {
            commands: vec!["register-scheduledtask".into()],
            ..Config::default()
        };
        assert!(config.reports_command("Register-ScheduledTask"));
        assert!(config.reports_command("ScheduledTasks\\Register-ScheduledTask"));
        assert!(!config.reports_command("Get-ScheduledTask"));

        let off = Config {
            report: false,
            ..config
        };
        assert!(!off.reports_command("Register-ScheduledTask"));
    }

    #[test]
    fn monitor_mode_never_blocks() {
        let config = Config {
            block_on: ScanStatus::Suspicious,
            ..Config::default()
        };
        assert!(!config.blocks(ScanStatus::Detected));
        assert!(!config.blocks(ScanStatus::Suspicious));
    }

    #[test]
    fn block_mode_blocks_from_block_on() {
        let detected = Config {
            mode: Mode::Block,
            ..Config::default()
        };
        assert!(detected.blocks(ScanStatus::Detected));
        assert!(!detected.blocks(ScanStatus::Suspicious));
        assert!(!detected.blocks(ScanStatus::NotDetected));

        let suspicious = Config {
            mode: Mode::Block,
            block_on: ScanStatus::Suspicious,
            ..Config::default()
        };
        assert!(suspicious.blocks(ScanStatus::Detected));
        assert!(suspicious.blocks(ScanStatus::Suspicious));
        assert!(!suspicious.blocks(ScanStatus::Clean));
    }
}
