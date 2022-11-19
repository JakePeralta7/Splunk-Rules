# Create local accounts using net exe

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1136/001/)
Tactic: Persistence

Technique: Create Account

Sub-Technique: Local Account

# Description
Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. With a sufficient level of access, the net user /add command can be used to create a local account. On macOS systems the dscl -create command can be used to create a local account.

Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where (Processes.process_name=net.exe OR Processes.process_name=net1.exe) AND Processes.process=*/add*
    by Processes.dest Processes.user Processes.original_file_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
```