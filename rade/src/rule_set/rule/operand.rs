mod val;

use serde::{Deserialize, Serialize};
pub use val::*;

use crate::{Event, InsensitiveFlag};

#[derive(Debug, Deserialize, Serialize)]
pub enum Operand {
    And(Vec<Operand>),
    Or(Vec<Operand>),
    Eq(Val, Val, #[serde(default)] Option<InsensitiveFlag>),
    Neq(Val, Val, #[serde(default)] Option<InsensitiveFlag>),
    StartsWith(Str, Str, #[serde(default)] Option<InsensitiveFlag>),
    EndsWith(Str, Str, #[serde(default)] Option<InsensitiveFlag>),
    Contains(Val, Val, #[serde(default)] Option<InsensitiveFlag>),
}

impl Operand {
    pub fn evaluate(&self, event: &Event) -> bool {
        match self {
            Operand::Or(operands) => {
                let mut result = false;
                for operand in operands {
                    if operand.evaluate(event) {
                        result = true;
                        break;
                    }
                }
                result
            },
            Operand::And(operands) => {
                let mut result = true;
                for operand in operands {
                    if !operand.evaluate(event) {
                        result = false;
                        break;
                    }
                }
                result
            },
            Operand::Eq(val1, val2, flag) => val1.eq(val2, event, flag),
            Operand::Neq(val1, val2, flag) => val1.neq(val2, event, flag),
            Operand::StartsWith(val1, val2, flag) => val1.starts_with(val2, event, flag),
            Operand::EndsWith(val1, val2, flag) => val1.ends_with(val2, event, flag),
            Operand::Contains(val1, val2, flag) => val1.contains(val2, event, flag),
        }
    }
}
