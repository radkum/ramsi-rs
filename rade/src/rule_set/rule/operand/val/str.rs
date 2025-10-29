use serde::{Deserialize, Serialize};

use super::{Cast, Eq, InsensitiveFlag, Val};
use crate::{Event, FatString};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub enum FieldStr {
    Content,
    AppName,
    FileName,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Str {
    Lit(FatString),
    Field(FieldStr),
}

impl Str {
    pub fn contains(&self, elem: &Val, event: &Event, comp_flag: &Option<InsensitiveFlag>) -> bool {
        let (Some(s1), Some(s2)) = (self.as_str(event, comp_flag), elem.as_str(event, comp_flag))
        else {
            return false;
        };
        //log::trace!("Checking if '{}' contains '{}'", s1, s2);
        s1.contains(s2)
    }

    pub fn starts_with(
        &self,
        elem: &Str,
        event: &Event,
        comp_flag: &Option<InsensitiveFlag>,
    ) -> bool {
        let (Some(s1), Some(s2)) = (self.as_str(event, comp_flag), elem.as_str(event, comp_flag))
        else {
            return false;
        };
        s1.starts_with(s2)
    }

    pub fn ends_with(
        &self,
        elem: &Str,
        event: &Event,
        comp_flag: &Option<InsensitiveFlag>,
    ) -> bool {
        let (Some(s1), Some(s2)) = (self.as_str(event, comp_flag), elem.as_str(event, comp_flag))
        else {
            return false;
        };
        s1.ends_with(&s2)
    }
}

impl Cast for Str {
    fn as_str<'a>(
        &'a self,
        event: &'a Event,
        comp_flag: &Option<InsensitiveFlag>,
    ) -> Option<&'a str> {
        let fat_string = match self {
            Self::Lit(s) => Some(s),
            Self::Field(field) => match field {
                FieldStr::Content => event.content.as_ref(),
                FieldStr::AppName => event.app_name.as_ref(),
                FieldStr::FileName => event.file_name.as_ref(),
            },
        };

        fat_string.map(|fat_string| fat_string.choose(comp_flag))
    }

    // fn as_str_list<'a>(&'a self, event: &'a Event, comp_flag: &Option<CompFlag>)
    // -> Option<Vec<String>> {     self.as_str(event, comp_flag).map(|s|
    // vec![s]) }
}

impl Eq for Str {
    fn eq<'a>(&'a self, elem: &Val, event: &'a Event, comp_flag: &Option<InsensitiveFlag>) -> bool {
        let (Some(s1), Some(s2)) = (self.as_str(event, comp_flag), elem.as_str(event, comp_flag))
        else {
            return false;
        };
        s1 == s2
    }

    fn neq<'a>(
        &'a self,
        elem: &Val,
        event: &'a Event,
        comp_flag: &Option<InsensitiveFlag>,
    ) -> bool {
        let (Some(s1), Some(s2)) = (self.as_str(event, comp_flag), elem.as_str(event, comp_flag))
        else {
            return false;
        };
        s1 != s2
    }
}
