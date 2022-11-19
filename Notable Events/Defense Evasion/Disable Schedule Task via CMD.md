# Disable Schedule Task via CMD

## [MITRE AT&CK](https://attack.mitre.org/techniques/T1562/001/)
Tactic: Defense Evasion

Technique: Impair Defenses

Sub-Technique: Disable or Modify Tools

## Description
This analytic is to detect a suspicious commandline to disable existing schedule task. This technique is used by adversaries or commodity malware like IcedID to disable security application (AV products) in the targetted host to evade detections. 

This TTP is a good pivot to check further why and what other process run before and after this detection. check which process execute the commandline and what task is disabled. parent child process is quite valuable in this scenario too.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where Processes.process_name=schtasks.exe Processes.process=*/change* Processes.process=*/disable* 
    by Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.dest
```