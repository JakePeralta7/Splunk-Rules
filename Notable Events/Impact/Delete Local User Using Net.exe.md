# Delete Local User Using Net.exe

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1531/)
Tactic: Impact

Technique: Account Access Removal

## Description
This analytic will detect a suspicious net.exe/net1.exe command-line to delete a user on a system. This technique may be use by an administrator for legitimate purposes, however this behavior has been used in the wild to impair some user or deleting adversaries tracks created during its lateral movement additional systems. 

During triage, review parallel processes for additional behavior. Identify any other user accounts created before or after.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where (Processes.process_name="net1.exe" OR Processes.process_name="net.exe") AND Processes.process="*user*" AND Processes.process="*/delete*"
    by Processes.dest Processes.user Processes.original_file_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
```