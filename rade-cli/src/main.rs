use std::str::FromStr;

use rade::rule_set::*;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let condition = Operand::And(vec![
        Operand::AIContains(
            Val::Field(Field::Content),
            Val::Str(
                "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')".to_string(),
            ),
        ),
        Operand::AIContains(
            Val::Field(Field::Content),
            Val::Str(".GetField('amsiInitFailed'".to_string()),
        ),
    ]);
    let new_r = Rule::new(
        uuid::Uuid::from_str("43025534-69e4-4e81-a78f-fad61111a7df")?,
        "Test Rule",
        "This rule detects the modification of the amsiInitFailed field to bypass AMSI.",
        "Defense Evasion",
        "TA0005",
        "T1562.001",
        r#""[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)""#,
        condition,
    );

    println!("{}", serde_yaml_bw::to_string(&new_r)?);

    let rule = Rule::from_str()?;
    println!("RULE: {:?}", rule);
    Ok(())
}
