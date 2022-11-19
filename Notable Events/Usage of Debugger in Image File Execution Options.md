# Usage of Debugger in Image File Execution Options

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1546/012/){:target="_blank"}
Tactic: Persistence
Technique: Event Triggered Execution
Sub-Technique: Image File Execution Options Injection

## Description
The Debugger registry key can allow an adversary to intercept the execution of files, causing a different process to be executed. This functionality can be abused by an adversary to establish persistence.

## SPL
```spl
| tstats count 
from datamodel=Endpoint.Registry 
where Registry.registry_path="*SOFTWARE\\Microsoft\\*\\Image File Execution Options\\*\\Debugger" AND Registry.action=modified
by host Registry.user Registry.action Registry.registry_path Registry.registry_value_name Registry.registry_value_type Registry.registry_value_data
```