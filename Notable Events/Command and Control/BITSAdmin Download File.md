# BITSAdmin Download File

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1105/)
Tactic: Command and Control

Technique: Ingress Tool Transfer

## Description
This rule identifies Microsoft Background Intelligent Transfer Service utility bitsadmin.exe using the transfer parameter to download a remote object. 

In addition, look for download or upload on the command-line, the switches are not required to perform a transfer. Capture any files downloaded. Review the reputation of the IP or domain used. Typically once executed, a follow on command will be used to execute the dropped file. Note that the network connection or file modification events related will not spawn or create from bitsadmin.exe, but the artifacts will appear in a parallel process of svchost.exe with a command-line similar to svchost.exe -k netsvcs -s BITS. 

It's important to review all parallel and child processes to capture any behaviors and artifacts. In some suspicious and malicious instances, BITS jobs will be created. You can use bitsadmin /list /verbose to list out the jobs during investigation.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where (Processes.process_name=bitsadmin.exe OR Processes.original_file_name=bitsadmin.exe) Processes.process="*transfer*"
    by _time host Processes.user Processes.parent_process Processes.original_file_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)`
```