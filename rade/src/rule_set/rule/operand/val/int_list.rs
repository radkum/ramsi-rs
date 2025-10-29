use serde::{Deserialize, Serialize};

use super::{Cast, CompFlag, Eq, Val};
use crate::{Event, rule_set::rule::operand::val::Contains};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct IntList(pub Vec<u64>);

impl IntList {
    pub fn new(list: Vec<u64>) -> Self {
        Self(list)
    }
    pub fn eq<'a>(&self, elem: &Val, event: &'a Event) -> bool {
        let (Some(i1), Some(i2)) = (self.as_u64_list(event), elem.as_u64_list(event)) else {
            return false;
        };
        i1 == i2
    }

    pub fn as_u64<'a>(&'a self, _event: &'a Event) -> Option<u64> {
        if self.0.len() == 1 {
            self.0[0].into()
        } else {
            None
        }
    }
}

impl Cast for IntList {
    fn as_u64<'a>(&'a self, _event: &'a Event) -> Option<u64> {
        if self.0.len() == 1 {
            self.0[0].into()
        } else {
            None
        }
    }

    fn as_u64_list<'a>(&'a self, _event: &'a Event) -> Option<&'a Vec<u64>> {
        Some(&self.0)
    }
}
impl Contains for IntList {
    fn contains<'a>(&self, elem: &Val, event: &'a Event, _: &Option<CompFlag>) -> bool {
        let Some(elem) = elem.as_u64(event) else {
            return false;
        };

        self.0.contains(&elem)
    }
}
