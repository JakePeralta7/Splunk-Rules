# Add DefaultUser And Password In Registry

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1552/002/)
Tactic: Credential Access

Technique: Unsecured Credentials

Sub-Technique: Credentials in Registry

## Description
This rule detects a suspicious registry modification to implement auto admin logon to a host. This technique was seen in BlackMatter ransomware to automatically logon to the compromise host after triggering a safemode boot to continue encrypting the whole network. 

This behavior is not a common practice and really a suspicious TTP or alert need to be consider if found within then network premise.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Registry 
    where Registry.registry_path="*SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon*" AND Registry.registry_value_name=DefaultPassword OR Registry.registry_value_name=DefaultUserName 
    by _time host Registry.user Registry.process_name Registry.process_guid Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.registry_key_name 
| `drop_dm_object_name(Registry)`
```