# Check Elevated CMD using whoami

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1033/)
Tactic: Discovery

Technique: System Owner/User Discovery

## Description
This search is to detect a suspicious whoami execution to check if the cmd or shell instance process is with elevated privileges. This technique was seen in FIN7 js implant where it execute this as part of its data collection to the infected machine to check if the running shell cmd process is elevated or not. This TTP is really a good alert for known attacker that recon on the targetted host.

This command is not so commonly executed by a normal user or even an admin to check if a process is elevated.