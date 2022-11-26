# Allow Operation with Consent Admin

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1548/)
Tactic: Privilege Escalation

Technique: Abuse Elevation Control Mechanism

## Description
This rule identifies a potential privilege escalation attempt to perform malicious task. This registry modification is designed to allow the Consent Admin to perform an operation that requires elevation without consent or credentials. We also found this in some attacker to gain privilege escalation to the compromise machine.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Registry 
    where Registry.registry_path="*\\Microsoft\\Windows\\CurrentVersion\\Policies\\System*" Registry.registry_value_name=ConsentPromptBehaviorAdmin Registry.registry_value_data="0x00000000" 
    by _time host Registry.user Registry.process_name Registry.registry_key_name Registry.registry_value_name Registry.registry_value_data 
| `drop_dm_object_name(Registry)`
```