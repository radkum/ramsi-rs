use std::str::FromStr;

use rade::*;

type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;

fn main() -> Result<()> {
    let events = Events::deserialize(&mut std::fs::File::open("rade/test_data/events.bin")?)?;
    let rule_set = RuleSet::deserialize(&mut std::fs::File::open("rade/test_data/ruleset.bin")?)?;

    println!("Loaded {} events", events.iter().count());
    println!("Loaded {} rules", rule_set.rules().len());
    let mut engine = RadeEngine::new();
    engine.load_rules(rule_set.retain_rules());

    let matches = engine.eval_bottom_up(events);
    println!("{:?}", matches);
    Ok(())
}

#[allow(dead_code)]
fn serialize_events() {
    let event1 = Event::new(Some(1234), Some(5678), Some("C:\\path\\to\\exe".into()), Some("powershell".into()), Some("script.ps1".into()), Some(r#""[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)""#.into()), Some(4321), Some(1));
    let event2 = Event::new(Some(1234), Some(5678), Some("C:\\path\\to\\exe".into()), Some("powershell".into()), Some("script.ps1".into()), Some(r#""[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)""#.into()), Some(4321), Some(1));

    let events = Events::new(vec![event1, event2]);
    events
        .serialize(&mut std::fs::File::create("rade/test_data/events.bin").unwrap())
        .unwrap();
}

#[allow(dead_code)]
fn read_rule() -> Result<()> {
    let rule_path = "rade/test_data/rules/amsi_disable/AmsiInitFailed.yaml";
    let rule_yaml = std::fs::read_to_string(rule_path)?;
    let rule = Rule::from_str(&rule_yaml)?;
    println!("RULE: {:?}", rule);
    Ok(())
}

#[allow(dead_code)]
fn serialiaze_ruleset() -> Result<()> {
    let rule_path = "rade/test_data/Bypass_Amsi.yaml";
    let rule_yaml = std::fs::read_to_string(rule_path)?;
    let rule = Rule::from_str(&rule_yaml)?;
    println!("RULE: {:?}", rule);

    let rule_set = RuleSet::from(rule);
    rule_set.serialize(&mut std::fs::File::create("rade/test_data/ruleset.bin")?)?;
    Ok(())
}

#[allow(dead_code)]
fn create_rule() -> Rule {
    let condition = Operand::And(vec![
        Operand::Contains(
            Val::Str(Str::Field(FieldStr::Content)),
            Val::Str(Str::Lit(
                "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')".into(),
            )),
            None,
            //Some(CompFlag::Both),
        ),
        Operand::Contains(
            Val::Str(Str::Field(FieldStr::Content)),
            Val::Str(Str::Lit(".GetField('amsiInitFailed'".into())),
            Some(CompFlag::Both),
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
