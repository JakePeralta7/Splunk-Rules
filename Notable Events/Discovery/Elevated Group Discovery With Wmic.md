# Elevated Group Discovery With Wmic

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1069/002/)
Tactic: Discovery

Technique: Permission Groups Discovery

Sub-Technique: Domain Groups

## Description
This rule looks for the execution of wmic.exe with command-line arguments utilized to query for specific domain groups. Red Teams and adversaries alike use net.exe to enumerate elevated domain groups for situational awareness and Active Directory Discovery to identify high privileged users.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where Processes.process_name="wmic.exe" Processes.process=*/NAMESPACE:\\\\root\\directory\\ldap* (Processes.process="*Domain Admins*" OR Processes.process="*Enterprise Admins*" OR Processes.process="*Schema Admins*" OR Processes.process="*Account Operators*" OR Processes.process="*Server Operators*" OR Processes.process="*Protected Users*" OR Processes.process="*Dns Admins*") 
    by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)`
```