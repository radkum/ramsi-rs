use log::debug;
use ps_parser::{PowerShellSession, Variables};

use super::Ramsi_Impl;
use super::keywords::*;

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

        if CLEANLIST_SHA256_SET.contains(&sha256) {
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

        // for s in SUSPICIOUS_FUNCTIONS.iter() {
        //     if script_content.contains(s) {
        //         debug!("Suspicious keyword in script detected. Keyword: {s}");
        //         return Some(ScanStatus::Suspicious);
        //     }
        // }

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
