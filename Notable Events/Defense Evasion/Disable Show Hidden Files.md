# Disable Show Hidden Files

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1564/001/)
Tactic: Defense Evasion

Technique: Hide Artifacts

Sub-Technique: Hidden Files and Directories

## Description
The following analytic is to identify a modification in the Windows registry to prevent users from seeing all the files with hidden attributes. This event or techniques are known on some worm and trojan spy malware that will drop hidden files on the infected machine.

Note: Legitimate users would trigger this alert lots of times.

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Registry 
    where (Registry.registry_path="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden" OR Registry.registry_path="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideFileExt" Registry.registry_value_data="0x00000001") OR (Registry.registry_path="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowSuperHidden" Registry.registry_value_data="0x00000000") 
    by _time Registry.dest Registry.user Registry.action Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid
| `drop_dm_object_name(Registry)`
```