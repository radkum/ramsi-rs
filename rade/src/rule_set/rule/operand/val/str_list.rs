use serde::{Deserialize, Serialize};

use super::{Cast, Contains, InsensitiveFlag, Val};
use crate::{Event, FatString};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub enum FieldStrList {
    ContentTokens,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum StrList {
    Lit(Vec<FatString>),
    Field(FieldStrList),
}

impl Cast for StrList {
    fn as_str<'a>(
        &'a self,
        event: &'a crate::Event,
        comp_flag: &Option<InsensitiveFlag>,
    ) -> Option<&'a str> {
        let list = match self {
            Self::Lit(s) => Some(s),
            Self::Field(field) => match field {
                FieldStrList::ContentTokens => event.content_tokens.as_ref(),
            },
        };

        let list = list?;
        if list.is_empty() {
            return None;
        }

        Some(list[0].choose(comp_flag))
    }

    fn as_str_list<'a>(
        &'a self,
        event: &'a Event,
        comp_flag: &Option<InsensitiveFlag>,
    ) -> Option<Vec<&'a str>> {
        let list = match self {
            Self::Lit(s) => Some(s),
            Self::Field(field) => match field {
                FieldStrList::ContentTokens => event.content_tokens.as_ref(),
            },
        };
        let list = list?;
        if list.is_empty() {
            return None;
        }

        Some(list.iter().map(|fs| fs.choose(comp_flag)).collect())
    }
}

impl Contains for StrList {
    fn contains(
        &self,
        elem: &Val,
        event: &crate::Event,
        comp_flag: &Option<InsensitiveFlag>,
    ) -> bool {
        let Some(str_list) = self.as_str_list(event, comp_flag) else {
            return false;
        };

        let Some(str) = elem.as_str(event, comp_flag) else {
            return false;
        };

        str_list.contains(&str)
    }
}
