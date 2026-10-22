use std::{
    collections::BTreeSet,
    sync::{Mutex, PoisonError},
};

use cs_parser::CSharpSession;
use log::debug;
use ps_parser::{CommandToken, PowerShellSession, ScriptResult, Variables};
use shared::DynResult;
pub use shared::ScanStatus;

use super::{PsVersion, ScriptType, rules::Rules};

#[derive(Debug, PartialEq)]
pub struct ScanResult {
    pub status: ScanStatus,
    pub reason: Option<String>,
}

impl ScanResult {
    fn new(status: ScanStatus, reason: String) -> Self {
        Self {
            status,
            reason: Some(reason),
        }
    }
}

pub struct Scanner {
    ps_session: Mutex<PowerShellSession>,
    rules: Rules,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new(Rules::default())
    }
}

struct Tokens {
    powershell_version: Option<PsVersion>,
    script_strings: BTreeSet<String>,
    commands_and_methods: BTreeSet<String>,
    ttypes: BTreeSet<String>,
}

impl Tokens {
    fn extend(&mut self, other: Tokens) {
        self.powershell_version = self.powershell_version.take().max(other.powershell_version);
        self.script_strings.extend(other.script_strings);
        self.commands_and_methods.extend(other.commands_and_methods);
        self.ttypes.extend(other.ttypes);
    }
}

impl Scanner {
    pub fn new(rules: Rules) -> Self {
        Self {
            ps_session: Mutex::new(PowerShellSession::new().with_variables(Variables::env())),
            rules,
        }
    }

    pub fn scan(&self, script_content: &str, script_type: ScriptType) -> ScanResult {
        if let Some(result) = self.sha_scan(script_content) {
            return result;
        }

        let tokens_res: DynResult<Tokens> = match script_type {
            ScriptType::PsCommand => {
                self.parse_tokens(script_content, PowerShellSession::parse_command)
            },
            ScriptType::PsScript => {
                self.parse_tokens(script_content, PowerShellSession::parse_script)
            },
            ScriptType::PsDataFile => Err(".psd1 file is not supported".into()),
            ScriptType::Other => Err("Only powershell scripts are supported".into()),
        };

        let tokens = tokens_res.unwrap_or_else(|err| {
            debug!("Failed to parse script: {err}");
            let string_set: BTreeSet<String> = Self::tokenize(script_content);
            // any word can be a call here, so skip telemetry functions like run or start
            let functions_and_commands = self
                .rules
                .blacklist_functions
                .iter()
                .filter(|f| string_set.contains(f.as_str()))
                .cloned()
                .collect();
            let ttypes = string_set.clone();

            Tokens {
                powershell_version: None,
                script_strings: string_set,
                commands_and_methods: functions_and_commands,
                ttypes,
            }
        });

        self.heuristic_scan(&tokens)
    }

    fn parse_tokens<E: std::error::Error + 'static>(
        &self,
        script_content: &str,
        parse: impl Fn(&mut PowerShellSession, &str) -> Result<ScriptResult, E>,
    ) -> DynResult<Tokens> {
        // the session lock is released before token extraction
        let script_res = parse(
            &mut self
                .ps_session
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
            script_content,
        )?;
        self.extract_tokens(script_res)
    }

    fn sha_scan(&self, _script_content: &str) -> Option<ScanResult> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(_script_content.as_bytes());
        let sha256 = hasher.finalize();

        if self.rules.is_allowlisted(&sha256.into()) {
            return Some(ScanResult::new(
                ScanStatus::Clean,
                format!("allowlisted sha256: {sha256:x}"),
            ));
        }

        None
    }

    fn heuristic_scan(&self, tokens: &Tokens) -> ScanResult {
        let Tokens {
            script_strings,
            commands_and_methods,
            ttypes,
            powershell_version,
        } = tokens;

        for s in self.rules.blacklist_keywords.iter() {
            if script_strings.contains(s.as_str()) {
                return ScanResult::new(
                    ScanStatus::Detected,
                    format!("Blacklisted keyword in script detected TECHNIC 1. Keyword: {s}"),
                );
            }
        }

        for s in self.rules.blacklist_functions.iter() {
            if commands_and_methods.contains(s.as_str()) {
                return ScanResult::new(
                    ScanStatus::Detected,
                    format!("Blacklisted function in script detected. Function: {s}"),
                );
            }
        }

        for keyword in self.rules.blacklist_keywords_endswith.iter() {
            for s in script_strings.iter() {
                if s.ends_with(keyword) {
                    return ScanResult::new(
                        ScanStatus::Detected,
                        format!("Blacklisted keyword (endswith) in script detected. Keyword: {s}"),
                    );
                }
            }
        }

        for s in self.rules.telemetry_strings.iter() {
            if script_strings.contains(s.as_str()) {
                return ScanResult::new(
                    ScanStatus::Suspicious,
                    format!("Telemetry keyword in script detected. Keyword: {s}"),
                );
            }
        }

        for s in self.rules.telemetry_functions.iter() {
            if commands_and_methods.contains(s.as_str()) {
                return ScanResult::new(
                    ScanStatus::Suspicious,
                    format!("Telemetry keyword in script detected. Keyword: {s}"),
                );
            }
        }

        for s in self.rules.telemetry_types.iter() {
            if ttypes.contains(s.as_str()) {
                return ScanResult::new(
                    ScanStatus::Suspicious,
                    format!("Telemetry type in script detected. Keyword: {s}"),
                );
            }
        }

        match powershell_version {
            Some(PsVersion::V2) => {
                return ScanResult::new(
                    ScanStatus::Suspicious,
                    "Powershell version 2 detected".to_string(),
                );
            },
            Some(PsVersion::Unknown) => {
                return ScanResult::new(
                    ScanStatus::Suspicious,
                    "Unknown Powershell version detected".to_string(),
                );
            },
            _ => {},
        }

        ScanResult {
            status: ScanStatus::NotDetected,
            reason: None,
        }
    }

    fn extract_tokens(&self, script_result: ScriptResult) -> DynResult<Tokens> {
        let tokens = script_result.tokens();
        let mut string_set = tokens.lowercased_string_set();
        let mut commands_and_methods = tokens
            .methods_and_commands()
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let ttypes = tokens
            .ttypes()
            .iter()
            .map(|s| s.to_string())
            .collect::<BTreeSet<_>>();

        let commands = tokens.commands();

        let (powershell_commands, powershell_version) = Self::parse_powershell_cmd_args(&commands);

        let (cs_lowercased, cs_commands_and_methods) = Self::parse_embedded_csharp(&commands);
        string_set.extend(cs_lowercased);
        commands_and_methods.extend(cs_commands_and_methods);

        let mut tokens = Tokens {
            powershell_version,
            script_strings: string_set,
            commands_and_methods,
            ttypes,
        };
        // the -command text is a script of its own
        for command in powershell_commands {
            tokens.script_strings.extend(Self::tokenize(&command));
            if let Ok(command_tokens) =
                self.parse_tokens(&command, PowerShellSession::parse_command)
            {
                tokens.extend(command_tokens);
            }
        }
        Ok(tokens)
    }

    fn tokenize(content: &str) -> BTreeSet<String> {
        content
            .split(|c: char| !c.is_alphanumeric() && c != '\\' && c != '.' && c != '-')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
            .collect()
    }

    fn parse_embedded_csharp(commands: &[CommandToken]) -> (BTreeSet<String>, BTreeSet<String>) {
        let mut cs_lowercased = BTreeSet::new();
        let mut cs_commands_and_methods = BTreeSet::new();
        for cmd in commands {
            if cmd.name().eq_ignore_ascii_case("add-type")
                && let Ok((lowercased_strings, commands_and_methods)) = Self::parse_add_type(cmd)
            {
                cs_commands_and_methods.extend(commands_and_methods);
                cs_lowercased.extend(lowercased_strings);
            }
        }
        (cs_lowercased, cs_commands_and_methods)
    }

    fn parse_powershell_cmd_args(
        commands: &[CommandToken],
    ) -> (BTreeSet<String>, Option<PsVersion>) {
        let mut powershell_version: Option<PsVersion> = None;
        let powershell_arguments = commands
            .iter()
            .filter(|cmd| Self::is_powershell(cmd.name()))
            .filter_map(|cmd| {
                for (i, arg_name) in cmd.args().iter().enumerate() {
                    if Self::is_parameter(arg_name, "-command") {
                        // the rest of the command line is the script
                        return Some(cmd.args()[i + 1..].join(" "));
                    } else if Self::is_parameter(arg_name, "-version") {
                        // major version of "2", "2.0", "5.1"
                        let ps_version = cmd
                            .args()
                            .get(i + 1)
                            .and_then(|s| s.split('.').next()?.parse::<u32>().ok());
                        powershell_version = powershell_version.take().max(match ps_version {
                            Some(..=2) => Some(PsVersion::V2),
                            Some(3..) => Some(PsVersion::V3AndAbove),
                            _ => Some(PsVersion::Unknown),
                        });
                    }
                }
                None
            })
            .collect::<BTreeSet<_>>();
        (powershell_arguments, powershell_version)
    }

    fn is_powershell(name: &str) -> bool {
        let exe = name.rsplit(['\\', '/']).next().unwrap_or(name);
        ["powershell", "pwsh", "powershell.exe", "pwsh.exe"]
            .iter()
            .any(|n| exe.eq_ignore_ascii_case(n))
    }

    // powershell.exe accepts any prefix of a parameter name, e.g. -c, -comm
    fn is_parameter(arg: &str, name: &str) -> bool {
        arg.len() >= 2 && name.starts_with(&arg.to_ascii_lowercase())
    }

    fn parse_add_type(cmd: &CommandToken) -> DynResult<(BTreeSet<String>, BTreeSet<String>)> {
        let mut lowercased_strings = BTreeSet::new();
        let mut commands_and_methods = BTreeSet::new();
        for arg in cmd.args().iter() {
            if arg.starts_with("-") {
                continue;
            }
            let mut cs_session = CSharpSession::new();
            match cs_session.parse_input(arg) {
                Ok(script_result) => {
                    let cs_tokens = script_result.tokens();
                    let cs_lowercased = cs_tokens.lowercased_string_set();
                    lowercased_strings.extend(cs_lowercased);

                    commands_and_methods.extend(
                        cs_tokens
                            .methods()
                            .iter()
                            .map(|m| m.name().to_ascii_lowercase())
                            .collect::<BTreeSet<_>>(),
                    );

                    commands_and_methods.extend(
                        cs_tokens
                            .function_declarations()
                            .iter()
                            .map(|m| m.name().to_ascii_lowercase())
                            .collect::<BTreeSet<_>>(),
                    );
                },
                Err(err) => {
                    log::warn!("Failed to parse CSharp code: {err}")
                },
            }
        }
        Ok((lowercased_strings, commands_and_methods))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blacklist_keywords() {
        let keywords: std::collections::HashSet<_> = super::super::keywords::BLACKLIST_KEYWORDS
            .iter()
            .cloned()
            .collect();

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

        assert!(keywords_lowercased.is_subset(&keywords));
    }

    #[test]
    fn sha_scan() {
        assert_eq!(
            Scanner::default()
                .scan("prompt", ScriptType::PsCommand)
                .status,
            ScanStatus::Clean
        );
    }

    #[test]
    fn rules_from_file_are_applied() {
        use sha2::{Digest, Sha256};
        let sha256 = hex::encode(Sha256::digest("Get-Date"));
        let rules = Rules::parse(&format!(
            "blacklist_keywords = [\"Evil-Thing\"]\nallowlist_sha256 = [\"{sha256}\"]"
        ))
        .unwrap();
        let scanner = Scanner::new(rules);

        let result = scanner.scan("Write-Output 'evil-thing'", ScriptType::PsScript);
        assert_eq!(result.status, ScanStatus::Detected);
        let result = scanner.scan("Get-Date", ScriptType::PsCommand);
        assert_eq!(result.status, ScanStatus::Clean);
    }

    fn status(script: &str) -> ScanStatus {
        Scanner::default().scan(script, ScriptType::PsScript).status
    }

    #[test]
    fn commands_match_case_insensitively() {
        assert_eq!(status("AmsiInitialize 1"), ScanStatus::Detected);
        assert_eq!(status("Add-Type -AssemblyName x"), ScanStatus::Suspicious);
    }

    #[test]
    fn powershell_version_3_and_above_is_not_suspicious() {
        assert_eq!(
            status("powershell -version 5 -NoProfile"),
            ScanStatus::NotDetected
        );
        assert_eq!(status("powershell -version 7.4"), ScanStatus::NotDetected);
        assert_eq!(status("powershell -version 2.0"), ScanStatus::Suspicious);
    }

    #[test]
    fn powershell_by_path_and_abbreviated_parameters() {
        assert_eq!(
            status(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -version 2"),
            ScanStatus::Suspicious
        );
        assert_eq!(status("POWERSHELL -V 2"), ScanStatus::Suspicious);
        assert_eq!(status("pwsh -c iex x"), ScanStatus::Suspicious);
    }

    #[test]
    fn command_argument_is_scanned_as_code() {
        assert_eq!(
            status(r#"powershell -NoProfile -Command "Write-Output 'x'; iex 'y'""#),
            ScanStatus::Suspicious
        );
        assert_eq!(
            status("powershell -command Write-Output amsiutils"),
            ScanStatus::Detected
        );
    }

    #[test]
    fn encoded_command_is_scanned() {
        // Write-Output 'AmsiUtils'
        let encoded = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEEAbQBzAGkAVQB0AGkAbABzACcA";
        assert_eq!(
            status(&format!("powershell -enc {encoded}")),
            ScanStatus::Detected
        );
        assert_eq!(
            status(&format!("Add-Type x; powershell -e {encoded}; Get-Date")),
            ScanStatus::Detected
        );
    }

    #[test]
    fn fallback_does_not_match_common_words_as_functions() {
        let scanner = Scanner::default();
        let scan = |s| scanner.scan(s, ScriptType::Other).status;
        assert_eq!(
            scan("Start the Run, then Free the Token"),
            ScanStatus::NotDetected
        );
        assert_eq!(scan("AmsiInitialize(ctx)"), ScanStatus::Detected);
        assert_eq!(scan("LoadLibrary('amsi.dll')"), ScanStatus::Detected);
    }

    #[test]
    fn command_text_words_are_not_calls() {
        assert_eq!(
            status(r#"powershell -c "Write-Host Start the Run""#),
            ScanStatus::NotDetected
        );
    }

    #[test]
    fn version_2_is_not_hidden_by_a_later_version() {
        assert_eq!(
            status("powershell -version 2 -c x; powershell -version 5 -c y"),
            ScanStatus::Suspicious
        );
        assert_eq!(
            status("powershell -version 5 -c x; powershell -version 2 -c y"),
            ScanStatus::Suspicious
        );
        assert_eq!(
            status(r#"powershell -version 5 -command "powershell -version 2 -c x""#),
            ScanStatus::Suspicious
        );
    }

    #[test]
    fn concurrent_scans() {
        let scanner = Scanner::default();
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..20 {
                        scanner.scan("Get-Process | Out-Null", ScriptType::PsCommand);
                    }
                });
            }
        });
    }
}
