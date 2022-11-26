# Replace WinLogon Default Shell

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1491/001/)
Tactic: Impact

Technique: Defacement

Sub-Technique: Internal Defacement

## Description
This rule detects changes made to the registry value `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` or `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`, this setting decide what process will be launched first by userinit.exe.

Though not common, an adversary may abuse it in order to make only his process to pop-up to the user after he logs in.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Registry 
    where Registry.registry_path= "*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon*" AND Registry.registry_value_name=Shell 
    by _time Registry.dest Registry.user Registry.process_name Registry.registry_key_name Registry.registry_value_name Registry.registry_value_data 
| `drop_dm_object_name(Registry)`
```