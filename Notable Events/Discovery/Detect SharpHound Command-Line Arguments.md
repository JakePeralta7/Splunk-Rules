# Detect SharpHound Command-Line Arguments

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1069/)
Tactic: Discovery

Technique: Permission Groups Discovery

## Description
The following analytic identifies common command-line arguments used by SharpHound -collectionMethod and invoke-bloodhound. Being the script is FOSS, function names may be modified, but these changes are dependent upon the operator. 

In most instances the defaults are used. This analytic works to identify the common command-line attributes used. It does not cover the entirety of every argument in order to avoid false positives.

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Processes
    where Processes.process IN ("*-collectionMethod*","*invoke-bloodhound*")
    by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
```