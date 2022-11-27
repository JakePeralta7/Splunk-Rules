# Change Default File Association

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1546/001/)
Tactic: Persistence

Technique: Event Triggered Execution

Sub-Technique: Change Default File Association

## Description
This analytic is developed to detect suspicious registry modification to change the default file association of windows to malicious payload. This techninique was seen in some APT where it modify the default process to run file association, like .txt to notepad.exe. Instead notepad.exe it will point to a Script or other payload that will load malicious command to the compromised host.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Registry 
    where Registry.registry_path="*HKCR\\*" Registry.registry_path="*\\shell\\open\\command\\*" 
    by _time host Registry.process_name Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data 
| `drop_dm_object_name(Registry)`
```