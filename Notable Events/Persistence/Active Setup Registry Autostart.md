# Active Setup Registry Autostart

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/014/)
Tactic: Persistence

Technique: Boot or Logon Autostart Execution

Sub-Technique: Active Setup

## Description
Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer. These programs will be executed under the context of the user and will have the account's associated permissions level.

Adversaries may abuse Active Setup by creating a key under `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\` and setting a malicious value for StubPath. This value will serve as the program that will be executed when a user logs into the computer.

Adversaries can abuse these components to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Registry 
    where Registry.registry_path="*\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components*" Registry.registry_value_name="StubPath" 
    by _time Registry.dest Registry.user Registry.action Registry.process_name Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid 
| `drop_dm_object_name(Registry)`
```