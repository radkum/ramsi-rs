pub const RAMSI_PIPE_SUFFIX: &str = r"ramsi";
pub const RAMSI_CLSID: &str = "{b8614e83-84ac-45fb-82a8-21711aaf07f2}";
pub const CONFIG_KEY: &str = r"SOFTWARE\Ramsi";
pub const DEFAULT_LOG_DIR: &str = r"C:\ProgramData\ramsi";
// SYSTEM and admins: full; users: create files they own, not read others' logs
// and dumps
pub const LOG_DIR_SDDL: &str =
    "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1000a2;;;AU)(A;OICIIO;FA;;;CO)";
// owned by and writable only for SYSTEM and admins, providers ignore a rules
// file that is not
pub const RULES_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;AU)";

// value names under CONFIG_KEY
pub mod config_value {
    pub const MODE: &str = "mode";
    pub const BLOCK_ON: &str = "block_on";
    pub const REPORT: &str = "report";
    pub const APPS: &str = "apps";
    pub const LOG_LEVEL: &str = "log_level";
    pub const LOG_DIR: &str = "log_dir";
    pub const DUMP: &str = "dump";
    pub const MAX_CONTENT: &str = "max_content";
    pub const PIPE: &str = "pipe";
    pub const RULES: &str = "rules";
}
