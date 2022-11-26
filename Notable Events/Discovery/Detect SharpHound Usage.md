# Detect SharpHound Usage

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1069/)
Tactic: Discovery

Technique: Permission Groups Discovery

## Description
The following analytic identifies SharpHound binary usage by using the original filena,e. In addition to renaming the PE, other coverage is available to detect command-line arguments. This particular analytic looks for the original_file_name of SharpHound.exe and the process name. 

It is possible older instances of SharpHound.exe have different original filenames. Dependent upon the operator, the code may be re-compiled and the attributes removed or changed to anything else.

During triage, review the metadata of the binary in question. Review parallel processes for suspicious behavior. Identify the source of this binary.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where (Processes.process_name=sharphound.exe OR Processes.original_file_name=SharpHound.exe) 
    by Processes.dest Processes.user Processes.parent_process_name Processes.original_file_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
```