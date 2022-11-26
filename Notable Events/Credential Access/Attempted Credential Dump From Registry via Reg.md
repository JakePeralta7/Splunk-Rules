# Attempted Credential Dump From Registry via Reg

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1003/002/)
Tactic: Credential Access

Technique: OS Credential Dumping

Sub-Technique: Security Account Manager

## Description
The following rule identifies the use of reg.exe attempting to export Windows registry keys that contain hashed credentials. Adversaries will utilize this technique to capture and perform offline password cracking.

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Processes
    where Processes.process_name="reg.exe" Processes.process="*save*" (Processes.process="*\\SAM*" OR Processes.process="*\\System*")
    by _time host Processes.user Processes.original_file_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
```