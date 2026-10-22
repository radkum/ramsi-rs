use std::{collections::BTreeSet, sync::PoisonError};

use cs_parser::CSharpSession;
use log::debug;
use ps_parser::{CommandToken, ScriptResult, Token as PsToken};
use shared::DynResult;

use super::{PsVersion, Ramsi_Impl, ScriptType, keywords::*};

type PsTokens = Vec<PsToken>;

#[derive(Debug, PartialEq)]
pub(super) enum ScanStatus {
    Clean,
    Detected,
    Suspicious,
    NotDetected,
}

struct Tokens {
    powershell_version: Option<PsVersion>,
    script_strings: BTreeSet<String>,
    commands_and_methods: BTreeSet<String>,
    ttypes: BTreeSet<String>,
}

struct RefTokens<'a> {
    powershell_version: Option<&'a PsVersion>,
    script_strings: BTreeSet<&'a str>,
    commands_and_methods: BTreeSet<&'a str>,
    ttypes: BTreeSet<&'a str>,
}

impl<'a> From<&'a Tokens> for RefTokens<'a> {
    fn from(tokens: &'a Tokens) -> Self {
        let Tokens {
            powershell_version,
            script_strings,
            commands_and_methods,
            ttypes,
        } = tokens;

        let script_strings = script_strings.iter().map(|s| s.as_str()).collect();
        let commands_and_methods = commands_and_methods.iter().map(|s| s.as_str()).collect();
        let ttypes = ttypes.iter().map(|s| s.as_str()).collect();

        RefTokens {
            powershell_version: powershell_version.as_ref(),
            script_strings,
            commands_and_methods,
            ttypes,
        }
    }
}

impl Ramsi_Impl {
    pub(super) fn scan_script(&self, script_content: &str, script_type: ScriptType) -> ScanStatus {
        if let Some(status) = self.sha_scan(script_content) {
            return status;
        }

        // the session lock is released before token extraction
        let tokens_res: DynResult<Tokens> = match script_type {
            ScriptType::PsCommand => {
                let res = self
                    .ps_session
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .parse_command(script_content);
                res.map_err(|err| err.into())
                    .and_then(|script_res| Self::extract_tokens(script_res))
            },
            ScriptType::PsScript => {
                let res = self
                    .ps_session
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .parse_script(script_content);
                res.map_err(|err| err.into())
                    .and_then(|script_res| Self::extract_tokens(script_res))
            },
            ScriptType::PsDataFile => Err(".psd1 file is not supported".into()),
            ScriptType::Other => Err("Only powershell scripts are supported".into()),
        };

        let tokens = tokens_res.unwrap_or_else(|err| {
            debug!("Failed to parse script: {err}");
            let string_set: BTreeSet<String> = Self::tokenize(script_content);
            let functions_and_commands = string_set.clone();
            let ttypes = string_set.clone();

            Tokens {
                powershell_version: None,
                script_strings: string_set,
                commands_and_methods: functions_and_commands,
                ttypes,
            }
        });

        self.heuristic_scan((&tokens).into())
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

    fn heuristic_scan(&self, tokens: RefTokens<'_>) -> ScanStatus {
        let RefTokens {
            script_strings,
            commands_and_methods,
            ttypes,
            powershell_version,
        } = tokens;

        for s in BLACKLIST_KEYWORDS.iter() {
            if script_strings.contains(s) {
                debug!("Blacklisted keyword in script detected TECHNIC 1. Keyword: {s}");
                return ScanStatus::Detected;
            }
        }

        for s in BLACKLIST_FUNCTIONS.iter() {
            if commands_and_methods.contains(s) {
                debug!("Blacklisted function in script detected. Function: {s}");
                return ScanStatus::Detected;
            }
        }

        for keyword in BLACKLIST_KEYWORDS_ENDSWITH.iter() {
            for s in script_strings.iter() {
                if s.ends_with(keyword) {
                    debug!("Blacklisted keyword (endswith) in script detected. Keyword: {s}");
                    return ScanStatus::Detected;
                }
            }
        }

        for s in TELEMETRY_STRINGS.iter() {
            if script_strings.contains(s) {
                debug!("Telemetry keyword in script detected. Keyword: {s}");
                return ScanStatus::Suspicious;
            }
        }

        for s in TELEMETRY_FUNCTIONS.iter() {
            if commands_and_methods.contains(s) {
                debug!("Telemetry keyword in script detected. Keyword: {s}");
                return ScanStatus::Suspicious;
            }
        }

        for s in TELEMETRY_TYPES.iter() {
            if ttypes.contains(s) {
                debug!("Telemetry type in script detected. Keyword: {s}");
                return ScanStatus::Suspicious;
            }
        }

        match powershell_version {
            Some(PsVersion::V2) => {
                debug!("Powershell version 2 detected");
                return ScanStatus::Suspicious;
            },
            Some(PsVersion::Unknown) => {
                debug!("Unknown Powershell version detected ");
                return ScanStatus::Suspicious;
            },
            _ => {},
        }

        ScanStatus::NotDetected
    }

    fn extract_tokens(script_result: ScriptResult) -> DynResult<Tokens> {
        let tokens = script_result.tokens();
        let mut string_set = tokens.lowercased_string_set();
        let mut commands_and_methods = tokens
            .methods_and_commands()
            .iter()
            .map(|s| s.to_string())
            .collect::<BTreeSet<_>>();
        let ttypes = tokens
            .ttypes()
            .iter()
            .map(|s| s.to_string())
            .collect::<BTreeSet<_>>();

        let tokens = tokens.all();

        let (powershell_arguments, powershell_version) = Self::parse_powershell_cmd_args(&tokens);
        commands_and_methods.extend(powershell_arguments);

        let (cs_lowercased, cs_commands_and_methods) = Self::parse_embedded_csharp(&tokens);
        string_set.extend(cs_lowercased);
        commands_and_methods.extend(cs_commands_and_methods);

        Ok(Tokens {
            powershell_version,
            script_strings: string_set,
            commands_and_methods,
            ttypes,
        })
    }

    fn tokenize(content: &str) -> BTreeSet<String> {
        content
            .split(|c: char| !c.is_alphanumeric() && c != '\\' && c != '.' && c != '-')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
            .collect()
    }

    fn parse_embedded_csharp(tokens: &PsTokens) -> (BTreeSet<String>, BTreeSet<String>) {
        let mut cs_lowercased = BTreeSet::new();
        let mut cs_commands_and_methods = BTreeSet::new();
        for token in tokens.iter() {
            if let ps_parser::Token::Command(cmd) = token
                && cmd.name().eq_ignore_ascii_case("add-type")
                && let Ok((lowercased_strings, commands_and_methods)) = Self::parse_add_type(cmd)
            {
                cs_commands_and_methods.extend(commands_and_methods);
                cs_lowercased.extend(lowercased_strings);
            }
        }
        (cs_lowercased, cs_commands_and_methods)
    }

    fn parse_powershell_cmd_args(tokens: &PsTokens) -> (BTreeSet<String>, Option<PsVersion>) {
        let mut powershell_version: Option<PsVersion> = None;
        let powershell_arguments = tokens
            .iter()
            .filter_map(|t| match t {
                ps_parser::Token::Command(cmd) if cmd.name() == "powershell" => {
                    for (i, arg_name) in cmd.args().iter().enumerate() {
                        if arg_name == "-command" {
                            return cmd.args().get(i + 1).map(|s| s.to_ascii_lowercase());
                        } else if arg_name == "-version" {
                            let ps_version =
                                cmd.args().get(i + 1).and_then(|s| s.parse::<u32>().ok());
                            powershell_version = match ps_version {
                                Some(2) => Some(PsVersion::V2),
                                Some(3) => Some(PsVersion::V3AndAbove),
                                _ => Some(PsVersion::Unknown),
                            };
                        }
                    }
                    None
                },
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        (powershell_arguments, powershell_version)
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
                            .map(|m| m.name().to_string())
                            .collect::<BTreeSet<_>>(),
                    );

                    commands_and_methods.extend(
                        cs_tokens
                            .function_declarations()
                            .iter()
                            .map(|m| m.name().to_string())
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

        assert!(keywords_lowercased.is_subset(&keywords));
    }

    #[test]
    fn sha_scan() {
        let ramsi = Ramsi::new().into_static();
        assert_eq!(
            ramsi.scan_script("prompt", ScriptType::PsCommand),
            ScanStatus::Clean
        );
    }

    #[test]
    fn concurrent_scans() {
        let ramsi = Ramsi::new().into_static();
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..20 {
                        ramsi.scan_script("Get-Process | Out-Null", ScriptType::PsCommand);
                    }
                });
            }
        });
    }
}
