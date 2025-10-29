use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum CompFlag {
    CaseInsensitive,
    ApostropheInsensitive,
    Both,
}

#[derive(Debug, Clone)]
pub struct FatString {
    pub plain: String,
    pub case_insensitive: String,
    pub apostrophe_insensitive: String,
    pub ca_insensitive: String,
}

impl<'de> Deserialize<'de> for FatString {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(FatString::from(s))
    }
}

impl serde::Serialize for FatString {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.plain)
    }
}

impl From<&str> for FatString {
    fn from(s: &str) -> Self {
        Self::from(s.to_string())
    }
}

impl From<&String> for FatString {
    fn from(s: &String) -> Self {
        Self::from(s.to_string())
    }
}

impl From<String> for FatString {
    fn from(s: String) -> Self {
        let case_insensitive = s.to_lowercase();
        let apostrophe_insensitive = s.replace("'", "");
        let ca_insensitive = apostrophe_insensitive.to_lowercase();
        Self {
            plain: s,
            case_insensitive,
            apostrophe_insensitive,
            ca_insensitive,
        }
    }
}

impl FatString {
    pub fn choose<'a>(&'a self, comp_flag: &Option<CompFlag>) -> &'a str {
        if let Some(comp_flag) = comp_flag {
            match comp_flag {
                CompFlag::Both => self.ca_insensitive.as_ref(),
                CompFlag::CaseInsensitive => self.case_insensitive.as_ref(),
                CompFlag::ApostropheInsensitive => self.apostrophe_insensitive.as_ref(),
            }
        } else {
            self.plain.as_ref()
        }
    }
}
