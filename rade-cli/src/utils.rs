#![allow(dead_code)]
use std::str::FromStr;

use anyhow::anyhow;
use rade::*;
type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;

fn create_event() {
    let event1 = Event::new(Some(1234), Some(5678), Some("C:\\path\\to\\exe".into()), Some("powershell".into()), Some("script.ps1".into()), Some(r#""[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)""#.into()), Some(4321), Some(1));
    //let event2 = Event::new(Some(1234), Some(5678),
    // Some("C:\\path\\to\\exe".into()), Some("powershell".into()),
    // Some("script.ps1".into()),
    // Some(r#""[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").
    // GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)""#.
    // into()), Some(4321), Some(1));

    //let events = Events::new(vec![event1, event2]);
    // events
    //     .serialize(&mut
    // std::fs::File::create("rade/test_data/events.yaml").unwrap())
    //     .unwrap();
    println!("{}", serde_yaml_bw::to_string(&event1).unwrap());
}

fn read_rule() -> Result<()> {
    let rule_path = "rade/test_data/rules/amsi_disable/AmsiInitFailed.yaml";
    let rule_yaml = std::fs::read_to_string(rule_path)?;
    let rule = Rule::from_str(&rule_yaml)?;
    println!("RULE: {:?}", rule);
    Ok(())
}

fn serialiaze_ruleset() -> Result<()> {
    let rule_path = "rade/test_data/rules";
    let rule_yaml = std::fs::read_to_string(rule_path)?;
    let rule = Rule::from_str(&rule_yaml)?;
    println!("RULE: {:?}", rule);

    let rule_set = RuleSet::from(rule);
    rule_set.serialize(&mut std::fs::File::create("rade/test_data/ruleset.bin")?)?;
    Ok(())
}

pub fn serialize_ruleset_from_dir() -> Result<()> {
    let rule_path = "rade/test_data/rules";
    let rules = Rules::from_dir(std::path::Path::new(rule_path))
        .map_err(|err| anyhow!("Failed to load rules from dir {}: {:?}", rule_path, err))?;

    let rule_set = RuleSet::from(rules);
    rule_set
        .serialize(&mut std::fs::File::create("rade/test_data/ruleset.bin")?)
        .map_err(|err| anyhow!("Failed to serialize ruleset: {:?}", err))?;
    Ok(())
}

fn create_rule() -> Rule {
    let condition = Operand::And(vec![
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
    ]);
    let rule = Rule::new(
        uuid::Uuid::from_str("43025534-69e4-4e81-a78f-fad61111a7df").unwrap(),
        "Bypass Amsi",
        "This rule detects the modification of the amsiInitFailed field to bypass AMSI.",
        "Defense Evasion",
        "TA0005",
        "T1562.001",
        r#""[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)""#,
        condition,
    );
    println!("{}", serde_yaml_bw::to_string(&rule).unwrap());
    rule
}
