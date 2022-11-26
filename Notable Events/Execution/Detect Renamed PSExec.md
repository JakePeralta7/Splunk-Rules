# Detect Renamed PSExec

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1569/002/)
Tactic: Execution

Technique: System Services

Sub-Technique: Service Execution

## Description
The following rule identifies renamed instances of PsExec.exe being utilized on an endpoint. Most instances, it is highly probable to capture Psexec.exe or other SysInternal utility usage with the command-line argument of -accepteula. 

During triage, validate this is the legitimate version of PsExec by reviewing the PE metadata. In addition, review parallel processes for further suspicious behavior.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where (Processes.process_name!=psexec.exe OR Processes.process_name!=psexec64.exe) AND Processes.original_file_name=psexec.c 
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.original_file_name
```