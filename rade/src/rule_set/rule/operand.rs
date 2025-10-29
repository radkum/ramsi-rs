mod val;

use serde::{Deserialize, Serialize};
pub use val::*;

use crate::{CompFlag, Event};
#[derive(Debug, Deserialize, Serialize)]
pub enum Operand {
    And(Vec<Operand>),
    Or(Vec<Operand>),
    Eq(Val, Val, Option<CompFlag>),
    Neq(Val, Val, Option<CompFlag>),
    StartsWith(Str, Str, Option<CompFlag>),
    EndsWith(Str, Str, Option<CompFlag>),
    Contains(
        Val,
        Val,
        #[serde(skip_serializing_if = "Option::is_none", default)] Option<CompFlag>,
    ),
}

impl Operand {
    pub fn evaluate(&self, event: &Event) -> bool {
        match self {
            Operand::Or(operands) => {
                for operand in operands {
                    if operand.evaluate(event) {
                        return true;
                    }
                }
                false
            },
            Operand::And(operands) => {
                for operand in operands {
                    if !operand.evaluate(event) {
                        return false;
                    }
                }
                true
            },
            Operand::Eq(val1, val2, flag) => val1.eq(val2, event, flag),
            Operand::Neq(val1, val2, flag) => val1.neq(val2, event, flag),
            Operand::StartsWith(val1, val2, flag) => val1.starts_with(val2, event, flag),
            Operand::EndsWith(val1, val2, flag) => val1.ends_with(val2, event, flag),
            Operand::Contains(val1, val2, flag) => val1.contains(val2, event, flag),
        }
    }
}
