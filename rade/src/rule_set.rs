mod source;
use serde::{Deserialize, Serialize};
type GUID = uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub enum Field {
    Content,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Val {
    Str(String),
    Num(i64),
    Field(Field),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Operand {
    And(Vec<Operand>),
    AIContains(Val, Val),
}

type Condition = Operand;

#[derive(Debug, Deserialize, Serialize)]
pub struct Rule {
    id: GUID,
    name: Option<String>,
    description: Option<String>,
    mitre_tactic: Option<String>,
    mitre_tactic_id: Option<String>,
    mitre_id: Option<String>,
    example: Option<String>,
    condition: Option<Condition>,
}

impl Rule {
    pub fn from_str() -> Result<Self, serde_yaml_bw::Error> {
        let yaml_str = source::RULE;
        serde_yaml_bw::from_str::<Rule>(yaml_str)
    }

    pub fn new(
        guid: GUID,
        name: &str,
        description: &str,
        mitre_tactic: &str,
        mitre_tactic_id: &str,
        mitre_id: &str,
        example: &str,
        condition: Condition,
    ) -> Self {
        Self {
            id: guid,
            name: Some(name.to_string()),
            description: Some(description.to_string()),
            mitre_tactic: Some(mitre_tactic.to_string()),
            mitre_tactic_id: Some(mitre_tactic_id.to_string()),
            mitre_id: Some(mitre_id.to_string()),
            example: Some(example.to_string()),
            condition: Some(condition),
        }
    }
}

pub struct RuleSet {
    id: String,
    ttype: String,
    rules: Vec<Rule>,
}
