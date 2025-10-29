mod operand;

use std::str::FromStr;

//use operand::Operand;
pub use operand::*;
use serde::{Deserialize, Serialize};

use super::RuleResult;
use crate::{Event, GUID};

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

impl FromStr for Rule {
    type Err = anyhow::Error;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Ok(serde_yaml_bw::from_str::<Rule>(src)?)
    }
}
impl Rule {
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

    #[cfg(feature = "std")]
    pub fn from_path(src: &std::path::Path) -> RuleResult<Self> {
        let content = std::fs::read_to_string(src)?;
        Ok(serde_yaml_bw::from_str::<Rule>(&content)?)
    }

    pub fn id(&self) -> &GUID {
        &self.id
    }

    pub fn evaluate(&self, event: &Event) -> bool {
        let Some(condition) = &self.condition else {
            return false;
        };
        condition.evaluate(event)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::InsensitiveFlag;

    #[test]
    fn test_rule_from_str() {
        let rule_yaml = r#"
id: 43025534-69e4-4e81-a78f-fad61111a7df
name: Bypass Amsi
description: This rule detects the modification of the amsiInitFailed field to bypass AMSI.     
mitre_tactic: Defense Evasion
mitre_tactic_id: TA0005
mitre_id: T1562.001
example: '"[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField(''amsiInitFailed'',''NonPublic,Static'').SetValue($null,$true)"'
condition: !And
- !Contains
  - !Field Content
  - !Str '[Ref].Assembly.GetType(''System.Management.Automation.AmsiUtils'')'
  - CaseAndApostrophe
- !Contains
  - !Field Content
  - !Str .GetField('amsiInitFailed'
  - CaseAndApostrophe
"#;
        let rule_from_str = Rule::from_str(rule_yaml).unwrap();
        let rule = Rule::new(
            uuid::Uuid::from_str("43025534-69e4-4e81-a78f-fad61111a7df").unwrap(),
            "Bypass Amsi",
            "This rule detects the modification of the amsiInitFailed field to bypass AMSI.",
            "Defense Evasion",
            "TA0005",
            "T1562.001",
            r#""[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)""#,
            Operand::And(vec![
                Operand::Contains(
                    Val::Str(Str::Field(FieldStr::Content)),
                    Val::Str(Str::Lit(
                        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')".into(),
                    )),
                    Some(InsensitiveFlag::CaseAndApostrophe),
                ),
                Operand::Contains(
                    Val::Str(Str::Field(FieldStr::Content)),
                    Val::Str(Str::Lit(".GetField('amsiInitFailed'".into())),
                    Some(InsensitiveFlag::CaseAndApostrophe),
                ),
            ]),
        );

        assert_eq!(
            rule_from_str.id,
            uuid::Uuid::from_str("43025534-69e4-4e81-a78f-fad61111a7df").unwrap()
        );

        assert_eq!(
            serde_yaml_bw::to_string(&rule_from_str).unwrap(),
            serde_yaml_bw::to_string(&rule).unwrap()
        );
    }
}
