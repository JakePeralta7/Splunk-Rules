# Disable UAC in Registry

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1548/002/)
Tactic: Privilege Escalation

Technique: Abuse Elevation Control Mechanism

Sub-Technique: Bypass User Account Control

## Description
UAC, short for User Account Control, is a component of Microsoft Windows’s security system. It can help mitigate the impact of malware by preventing apps from making unwanted changes on the PC.

Windows will pop up a UAC confirmation dialog to ask you to confirm the change or not when some software attempts to change system-related parts of the file system or Windows Registry. Simply put, UAC can offer a special security environment, which protects your user account that has limited access rights well.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Registry 
    where Registry.registry_path="*SOFTWARE\\Microsoft\\*\\Policies\\System\\EnableLUA" AND Registry.action=modified 
    by host Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_type Registry.registry_value_data
```