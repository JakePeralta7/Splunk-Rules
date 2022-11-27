# CertUtil Download With VerifyCtl and Split Arguments

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1105/)
Tactics: Command and Control

Techniques: Ingress Tool Transfer

## Description
Certutil.exe may download a file from a remote destination using -VerifyCtl. 

This behavior does require a URL to be passed on the command-line. In addition, -f (force) and -split (Split embedded ASN.1 elements, and save to files) will be used. It is not entirely common for certutil.exe to contact public IP space. 

During triage, capture any files on disk and review. Review the reputation of the remote IP or domain in question. Using -VerifyCtl, the file will either be written to the current working directory or `%APPDATA%\..\LocalLow\Microsoft\CryptnetUrlCache\Content\&lt;hash&gt;`.

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Processes
    where (Processes.process_name=certutil.exe OR Processes.original_file_name=CertUtil.exe) AND ((Processes.process=*VerifyCtl* Processes.process=*split*) OR Processes.process=*VerifyCtl*)
    by _time host Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
```