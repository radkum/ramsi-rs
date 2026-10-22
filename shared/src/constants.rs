pub const RAMSI_PIPE_SUFFIX: &str = r"ramsi";
pub const CONFIG_KEY: &str = r"SOFTWARE\Ramsi";
pub const DEFAULT_LOG_DIR: &str = r"C:\ProgramData\ramsi";

// value names under CONFIG_KEY
pub mod config_value {
    pub const MODE: &str = "mode";
    pub const BLOCK_ON: &str = "block_on";
    pub const REPORT: &str = "report";
    pub const APPS: &str = "apps";
    pub const LOG_LEVEL: &str = "log_level";
    pub const LOG_DIR: &str = "log_dir";
    pub const DUMP: &str = "dump";
    pub const PIPE: &str = "pipe";
}
