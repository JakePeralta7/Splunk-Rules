# Aacinfo.exe Usage

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1518/001/)
Tactic: Discovery

Technique: Software Discovery

Sub-Technique: Security Software Discovery

## Description
Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as firewall rules and anti-virus. Adversaries may use the information from Security Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Aacinfo can be used to export Trellix Endpoint Security Threat Prevention Policy

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Processes
    where Processes.process_name=aacinfo.exe
    by Processes.dest Processes.user Processes.original_file_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
```