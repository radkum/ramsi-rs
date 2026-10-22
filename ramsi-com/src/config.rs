use std::path::PathBuf;

use log::LevelFilter;
use shared::{
    PipeName,
    constants::{CONFIG_KEY, DEFAULT_LOG_DIR, RAMSI_PIPE_SUFFIX, config_value},
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
    pub log_level: LevelFilter,
    pub log_dir: PathBuf,
    pub dump: bool,
    pub pipe_name: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Monitor,
            block_on: ScanStatus::Detected,
            log_level: LevelFilter::Info,
            log_dir: PathBuf::from(DEFAULT_LOG_DIR),
            dump: false,
            pipe_name: PipeName::from_suffix(RAMSI_PIPE_SUFFIX).to_string(),
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
        self.mode == Mode::Block
            && match status {
                ScanStatus::Detected => true,
                ScanStatus::Suspicious => self.block_on == ScanStatus::Suspicious,
                ScanStatus::Clean | ScanStatus::NotDetected => false,
            }
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
        if let Ok(suffix) = key.get_value::<String, _>(config_value::PIPE) {
            let pipe_name = PipeName::from_suffix(&suffix);
            if pipe_name.verify().is_ok() {
                config.pipe_name = pipe_name.to_string();
            }
        }
        config
    }
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
        key.1.set_value(config_value::LOG_LEVEL, &"debug").unwrap();
        key.1.set_value(config_value::LOG_DIR, &"D:\\logs").unwrap();
        key.1.set_value(config_value::DUMP, &1u32).unwrap();
        key.1.set_value(config_value::PIPE, &"other").unwrap();

        let config = Config::from_key(&key.1);

        assert_eq!(config.mode, Mode::Block);
        assert_eq!(config.block_on, ScanStatus::Suspicious);
        assert_eq!(config.log_level, LevelFilter::Debug);
        assert_eq!(config.log_dir, PathBuf::from("D:\\logs"));
        assert!(config.dump);
        assert_eq!(config.pipe_name, r"\\.\pipe\other");
    }

    #[test]
    fn invalid_values_fall_back_to_defaults() {
        let key = TempKey::new("invalid");
        key.1.set_value(config_value::MODE, &"loud").unwrap();
        key.1.set_value(config_value::BLOCK_ON, &"loud").unwrap();
        key.1.set_value(config_value::LOG_LEVEL, &"loud").unwrap();
        key.1.set_value(config_value::PIPE, &"a|b").unwrap();

        assert_eq!(Config::from_key(&key.1), Config::default());
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
