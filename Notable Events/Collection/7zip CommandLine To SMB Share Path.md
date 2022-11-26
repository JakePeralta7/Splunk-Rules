# 7zip CommandLine To SMB Share Path

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1560/001/)
Tactic: Collection

Technique: Archive Collected Data

Sub-Technique: Archive via Utility

## Description
This rule detects a suspicious 7z process with commandline pointing to SMB network share. This technique was seen in CONTI LEAK tools where it use 7z to archive a sensitive files and place it in network share tmp folder. This search is a good hunting query that may give analyst a hint why specific user try to archive a file pointing to SMB user which is un usual.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where (Processes.process_name ="7z.exe" OR Processes.process_name = "7za.exe" OR Processes.original_file_name = "7z.exe" OR Processes.original_file_name = "7za.exe") AND (Processes.process="*\\C$\\*" OR Processes.process="*\\Admin$\\*" OR Processes.process="*\\IPC$\\*") 
    by Processes.original_file_name Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.parent_process_id Processes.process_id Processes.dest Processes.user
```