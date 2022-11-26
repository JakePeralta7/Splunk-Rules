# Disable User Account Using Net.exe

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1531/)
Tactic: Impact

Technique: Account Access Removal

## Description
Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts. Adversaries may also subsequently log off and/or perform a System Shutdown/Reboot to set malicious changes into place.

This rule will identify a suspicious command-line that disables a user account using the native net.exe or net1.exe utility to Windows. This technique may used by the adversaries to interrupt availability of accounts and continue the impact against the organization.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where (Processes.process_name="net.exe" OR Processes.process_name="net1.exe") Processes.process="* user *" Processes.process="*/active:no*"
    by Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.dest Processes.user Processes.process_id Processes.process_guid
```