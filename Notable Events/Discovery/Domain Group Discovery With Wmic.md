# Domain Group Discovery With Wmic

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1069/002/)
Tactic: Discovery

Technique: Permission Groups Discovery

Sub-Technique: Domain Groups

## Description
This rule looks for the execution of wmic.exe with command-line arguments utilized to query for domain groups. The arguments utilized in this command return a list of all domain groups. Red Teams and adversaries alike use wmic.exe to enumerate domain groups for situational awareness and Active Directory Discovery.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where Processes.process_name="wmic.exe" Processes.process=*/NAMESPACE:\\\\root\\directory\\ldap* Processes.process=*ds_group* Processes.process="*GET ds_samaccountname*"
    by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)`
```