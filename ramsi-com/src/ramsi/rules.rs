use std::{collections::HashSet, path::Path};

use serde::Deserialize;
use shared::DynResult;

use super::keywords::*;

// lists from rules.toml extend the built-in ones
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RulesFile {
    blacklist_keywords: Vec<String>,
    blacklist_keywords_endswith: Vec<String>,
    blacklist_functions: Vec<String>,
    telemetry_strings: Vec<String>,
    telemetry_functions: Vec<String>,
    telemetry_types: Vec<String>,
    allowlist_sha256: Vec<String>,
}

pub struct Rules {
    pub blacklist_keywords: Vec<String>,
    pub blacklist_keywords_endswith: Vec<String>,
    pub blacklist_functions: Vec<String>,
    pub telemetry_strings: Vec<String>,
    pub telemetry_functions: Vec<String>,
    pub telemetry_types: Vec<String>,
    allowlist_sha256: HashSet<[u8; 32]>,
}

impl Default for Rules {
    fn default() -> Self {
        Self::from_file(RulesFile::default()).unwrap()
    }
}

impl Rules {
    pub fn load(path: &Path) -> DynResult<Self> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    pub(super) fn parse(toml: &str) -> DynResult<Self> {
        Self::from_file(toml::from_str(toml)?)
    }

    fn from_file(file: RulesFile) -> DynResult<Self> {
        fn merge(builtin: &[&str], extra: Vec<String>) -> Vec<String> {
            builtin
                .iter()
                .map(|s| s.to_string())
                .chain(extra.into_iter().map(|s| s.to_ascii_lowercase()))
                .collect()
        }

        let mut allowlist_sha256 = HashSet::new();
        for sha256 in file.allowlist_sha256 {
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(&sha256, &mut bytes)
                .map_err(|err| format!("Invalid sha256 \"{sha256}\": {err}"))?;
            allowlist_sha256.insert(bytes);
        }

        Ok(Self {
            blacklist_keywords: merge(&BLACKLIST_KEYWORDS, file.blacklist_keywords),
            blacklist_keywords_endswith: merge(
                &BLACKLIST_KEYWORDS_ENDSWITH,
                file.blacklist_keywords_endswith,
            ),
            blacklist_functions: merge(&BLACKLIST_FUNCTIONS, file.blacklist_functions),
            telemetry_strings: merge(&TELEMETRY_STRINGS, file.telemetry_strings),
            telemetry_functions: merge(&TELEMETRY_FUNCTIONS, file.telemetry_functions),
            telemetry_types: merge(&TELEMETRY_TYPES, file.telemetry_types),
            allowlist_sha256,
        })
    }

    pub fn is_allowlisted(&self, sha256: &[u8; 32]) -> bool {
        CLEANLIST_SHA256_SET.contains(sha256) || self.allowlist_sha256.contains(sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_extends_builtin_lists_lowercased() {
        let rules = Rules::parse(
            r#"
            blacklist_keywords = ["Evil-Thing"]
            allowlist_sha256 = ["CF07194EE232EB531E15F690000D19846DEA69CF05504782658AFCFACB9228A2"]
            "#,
        )
        .unwrap();

        assert!(rules.blacklist_keywords.contains(&"evil-thing".to_string()));
        assert!(rules.blacklist_keywords.contains(&"amsiutils".to_string()));
        assert_eq!(rules.telemetry_types.len(), TELEMETRY_TYPES.len());
    }

    #[test]
    fn invalid_files_are_rejected() {
        assert!(Rules::parse("unknown_list = []").is_err());
        assert!(Rules::parse(r#"allowlist_sha256 = ["abc"]"#).is_err());
        assert!(Rules::parse("blacklist_keywords = 1").is_err());
    }
}
