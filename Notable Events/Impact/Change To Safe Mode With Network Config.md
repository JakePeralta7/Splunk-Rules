# Change To Safe Mode With Network Config

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1490/)
Tactic: Impact

Technique: Inhibit System Recovery

## Description
This rule detects a suspicious bcdedit commandline to configure the host to boot in safe mode with network config. This technique was seen in blackMatter ransomware where it force the compromised host to boot in safe mode to continue its encryption and bring back to normal boot using bcdedit deletevalue command. 

This TTP can be a good alert for host that booted from safe mode forcefully since it need to modify the boot configuration to bring it back to normal.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where Processes.process_name = bcdedit.exe Processes.process="*/set*" Processes.process="*{current}*" Processes.process="*safeboot*" Processes.process="*network*" 
    by _time host Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)`
```