use log::debug;
use macros::lowercase_const_array;
use phf::phf_set;
use ps_parser::{PowerShellSession, Variables};

use super::Ramsi_Impl;
lowercase_const_array! {
const BLACKLIST_KEYWORDS: [&str; 6] = [
    "amsi.dll",
    "AMSI\\Providers\\",
    "AmsiEnable",
    "AmsiUtils",
    "amsiInitFailed",
    "invoke-mimikatz",
];
}
lowercase_const_array! {
const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "iex",
    "invoke",
    "start",
    "execute",
    "run",
    "create",
    "token",
    "Add-Type",
    "security",
    "Privileges",
    "Bypass",
    "cryptor",
    "RemoteThread",
    "Crypto",
    "Method",
    "DynamicAssembly",
    "Define",
    "DeflateStream",
    "IoControl",
    "DllImport",
    "Emit",
    "EncodedCommand",
    "ExpandString",
    "Free",
    "Base64",
    "GetAssemblies",
    "GetAsyncKeyState",
    "GetConstructor",
    "Virtual",
    "alloc",
];
}

static CLEANLIST_SHA256_MAP: phf::Set<&'static str> = phf_set! {
    "cf07194ee232eb531e15f690000d19846dea69cf05504782658afcfacb9228a2",
};

#[derive(Debug, PartialEq)]
pub(super) enum ScanStatus {
    Clean,
    Detected,
    Suspicious,
    NotDetected,
}

impl Ramsi_Impl {
    pub(super) fn scan_script(&self, script_content: String) -> ScanStatus {
        if let Some(status) = self.sha_scan(&script_content).into() {
            return status;
        }

        // maybe store Varialbes::env() somewhere to avoid recreating it every time?
        let mut ps_session = PowerShellSession::new().with_variables(Variables::env());
        let scan_content = match ps_session.parse_input(&script_content) {
            Ok(script_result) => script_result.deobfuscated(),
            Err(err) => {
                debug!("Failed to deobfuscate script: {err}");
                script_content
            },
        };
        if let Some(status) = self.heuristic_scan(&scan_content) {
            return status;
        }

        ScanStatus::NotDetected
    }

    fn sha_scan(&self, _script_content: &str) -> Option<ScanStatus> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(_script_content.as_bytes());
        let sha256 = hasher.finalize();
        let sha256_hex = format!("{:x}", sha256);

        if CLEANLIST_SHA256_MAP.contains(&sha256_hex.as_str()) {
            return Some(ScanStatus::Clean);
        }

        None
    }

    fn heuristic_scan(&self, script_content: &str) -> Option<ScanStatus> {
        let script_content = script_content.to_ascii_lowercase();
        debug!("Ramsi::scan_script");

        for s in BLACKLIST_KEYWORDS.iter() {
            if script_content.contains(s) {
                debug!("Blacklisted keyword in script detected. Keyword: {s}");
                return Some(ScanStatus::Detected);
            }
        }

        for s in SUSPICIOUS_KEYWORDS.iter() {
            if script_content.contains(s) {
                debug!("Suspicious keyword in script detected. Keyword: {s}");
                return Some(ScanStatus::Suspicious);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ramsi;

    #[test]
    fn blacklist_keywords() {
        let keywords: std::collections::HashSet<_> = BLACKLIST_KEYWORDS.iter().cloned().collect();

        let keywords_lowercased: [&str; 6] = [
            "amsi.dll",
            "amsi\\providers\\",
            "amsienable",
            "amsiutils",
            "amsiinitfailed",
            "invoke-mimikatz",
        ];
        let keywords_lowercased: std::collections::HashSet<_> =
            keywords_lowercased.iter().cloned().collect();

        assert_eq!(keywords, keywords_lowercased);
    }

    #[test]
    fn sha_scan() {
        let ramsi = Ramsi::new().into_static();
        assert_eq!(ramsi.scan_script("prompt".to_string()), ScanStatus::Clean);
    }
}
