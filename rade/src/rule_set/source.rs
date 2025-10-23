pub(super) const RULE: &str = r#"
id: 43025534-69e4-4e81-a78f-fad61111a7df
name: Test Rule
description: This rule detects the modification of the amsiInitFailed field to bypass AMSI.     
mitre_tactic: Defense Evasion
mitre_tactic_id: TA0005
mitre_id: T1562.001
example: '"[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField(''amsiInitFailed'',''NonPublic,Static'').SetValue($null,$true)"'
condition: !And
- !AIContains
  - !Field Content
  - !Str '[Ref].Assembly.GetType(''System.Management.Automation.AmsiUtils'')'
- !AIContains
  - !Field Content
  - !Str .GetField('amsiInitFailed'
    "#;
