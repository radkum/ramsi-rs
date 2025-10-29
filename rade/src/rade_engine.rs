use crate::{Events, Matches, Rules};

pub struct RadeEngine {
    rules: Rules,
}

impl RadeEngine {
    pub fn new() -> Self {
        Self { rules: vec![] }
    }

    pub fn load_rules(&mut self, rules: Rules) {
        self.rules = rules;
    }

    pub fn eval_bottom_up(&mut self, events: Events) -> Matches {
        let mut matches = Matches::new();

        for rule in &self.rules {
            for event in events.iter() {
                if rule.evaluate(event) {
                    matches.add_match(event.clone(), rule.id().clone());
                }
            }
        }

        matches
    }
}
