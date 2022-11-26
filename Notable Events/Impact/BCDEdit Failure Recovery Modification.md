# BCDEdit Failure Recovery Modification

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1490/)
Tactic: Impact

Technique: Inhibit System Recovery

## Description
This rule looks for flags passed to bcdedit.exe modifications to the built-in Windows error recovery boot configurations. 

This is typically used by ransomware to prevent recovery.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where Processes.process_name = bcdedit.exe Processes.process="*recoveryenabled*" (Processes.process="* no*") 
    by _time host Processes.user Processes.original_file_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
```