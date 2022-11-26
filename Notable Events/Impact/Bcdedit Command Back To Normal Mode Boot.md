# Bcdedit Command Back To Normal Mode Boot

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1490/)
Tactic: Impact

Technique: Inhibit System Recovery

## Description
This search is to detect a suspicious bcdedit commandline to configure the host from safe mode back to normal boot configuration. This technique was seen in blackMatter ransomware where it force the compromised host to boot in safe mode to continue its encryption and bring back to normal boot using bcdedit deletevalue command. This TTP can be a good alert for host that booted from safe mode forcefully since it need to modify the boot configuration to bring it back to normal.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where Processes.process_name=bcdedit.exe Processes.process="*/deletevalue*" Processes.process="*{current}*" Processes.process="*safeboot*" 
    by _time host Processes.user Processes.original_file_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
```