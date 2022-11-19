# Dump LSASS via Task Manager

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1003/001/)
Tactic: Credential Access

Technique: OS Credential Dumping

Sub-Technique: LSASS Memory

## Overview
Obtaining user operating system (OS) credentials from a targeted device is among threat actors’ primary goals when launching attacks because these credentials serve as a gateway to various objectives they can achieve in their target organization’s environment, such as lateral movement. One technique attackers use is targeting credentials in the Windows Local Security Authority Subsystem Service (LSASS) process memory because it can store not only a current user’s OS credentials but also a domain admin’s.

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Filesystem 
    where Filesystem.file_name=lsass.DMP AND Filesystem.action=created
    by host Filesystem.user Filesystem.action Filesystem.file_path Filesystem.process_id
```