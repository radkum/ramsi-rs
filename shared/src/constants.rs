pub const RAMSI_PIPE_SUFFIX: &str = r"ramsi";
// any local process may write to the pipe, so the trace server caps a message
pub const MAX_MESSAGE_LEN: u64 = 16 * 1024 * 1024;
// JSON escaping grows content up to 6x, so an event stays under MAX_MESSAGE_LEN
pub const MAX_CONTENT_LIMIT: u32 = 2 * 1024 * 1024;
pub const RAMSI_CLSID: &str = "{b8614e83-84ac-45fb-82a8-21711aaf07f2}";
pub const CONFIG_KEY: &str = r"SOFTWARE\Ramsi";
pub const DEFAULT_LOG_DIR: &str = r"C:\ProgramData\ramsi";
// admins and SYSTEM: full; users: own files only, no reading others'
pub const LOG_DIR_SDDL: &str =
    "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1000a2;;;AU)(A;OICIIO;FA;;;CO)";
// owner BA can only be set by an elevated process, providers check it
pub const PIPE_SDDL: &str =
    "O:BAD:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)";
// providers ignore a rules file that anyone but admins can change
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
