use crate::{Event, GUID};

#[derive(Debug, Default)]
pub struct Matches(Vec<Match_>);
impl Matches {
    pub fn add_match(&mut self, _event: Event, rule_id: GUID) {
        self.0.push(Match_ { rule_id });
    }
}

#[derive(Debug)]
pub struct Match_ {
    rule_id: GUID,
}

impl Match_ {
    pub fn rule_id(&self) -> &GUID {
        &self.rule_id
    }
}
