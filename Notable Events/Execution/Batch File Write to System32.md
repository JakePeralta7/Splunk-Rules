# Batch File Write to System32

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/002/)
Tactic: Execution

Technique: User Execution

Sub-Technique: Malicious File

## Description
The rule looks for a batch file (.bat) written to the Windows system directory tree.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Filesystem 
    where Filesystem.file_path IN ("*\\system32\\*", "*\\syswow64\\*") Filesystem.file_name="*.bat" 
    by _time host Filesystem.user Filesystem.process_name Filesystem.action Filesystem.file_create_time Filesystem.file_name Filesystem.file_path 
| `drop_dm_object_name(Filesystem)`
```