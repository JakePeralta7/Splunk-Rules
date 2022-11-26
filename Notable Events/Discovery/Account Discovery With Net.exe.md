# Account Discovery With Net.exe

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1087/002/)
Tactic: Discovery

Technique: Account Discovery

Sub-Technique: Domain Account

## Description
This rule detects a potential account discovery series of command used by several malware or attack to recon the target machine. This technique is also seen in some note worthy malware like trickbot where it runs a cmd process, or even drop its module that will execute the said series of net command. This series of command are good correlation search and indicator of attacker recon if seen in the machines within a none technical user or department (HR, finance, ceo and etc) network.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where (Processes.process_name="net.exe" OR Processes.original_file_name="net.exe" OR Processes.process_name="net1.exe" OR Processes.original_file_name="net1.exe") AND (Processes.process="*user*" OR Processes.process="*config*" OR Processes.process="*view /all*") 
    by Processes.process_name Processes.dest Processes.user Processes.parent_process_name 
| where count >= 5
| `drop_dm_object_name(Processes)`
```