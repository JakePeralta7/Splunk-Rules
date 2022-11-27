# CHCP Command Execution

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/)
Tactic: Execution

Technique: Command and Scripting Interpreter

## Description
This rule detects execution of chcp.exe application. this utility is used to change the active code page of the console. This technique was seen in icedid malware to know the locale region/language/country of the compromise host.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where Processes.parent_process_name=cmd.exe Processes.parent_process=*/c* Processes.process_name=chcp.com 
    by _time host Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
```