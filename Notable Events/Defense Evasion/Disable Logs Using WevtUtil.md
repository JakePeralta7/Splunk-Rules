# Disable Logs Using WevtUtil

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1070/001/)
Tactic: Defense Evasion

Technique: Indicator Removal

Sub-Technique: Clear Windows Event Logs

## Description
Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications. There are three system-defined sources of events: System, Application, and Security, with five event types: Error, Warning, Information, Success Audit, and Failure Audit.

This rule detecte execution of wevtutil.exe to disable logs. This technique was seen in several ransomware to disable the event logs to evade alerts and detections.

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Processes
    where Processes.process_name="wevtutil.exe" Processes.process="* sl *" Processes.process="*/e:false*"
    by Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.dest Processes.user Processes.process_id Processes.process_guid
```