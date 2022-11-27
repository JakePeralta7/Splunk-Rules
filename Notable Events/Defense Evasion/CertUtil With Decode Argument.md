# CertUtil With Decode Argument

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1140/)
Tactic: Defense Evasion

Technique: Deobfuscate/Decode Files or Information

## Description
CertUtil.exe may be used to encode and decode a file, including PE and script code. Encoding will convert a file to base64 with -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- tags. Malicious usage will include decoding a encoded file that was downloaded. Once decoded, it will be loaded by a parallel process. Note that there are two additional command switches that may be used - encodehex and decodehex. Similarly, the file will be encoded in HEX and later decoded for further execution. 

During triage, identify the source of the file being decoded. Review its contents or execution behavior for further analysis.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where (Processes.process_name=certutil.exe OR Processes.original_file_name=CertUtil.exe) Processes.process=*decode* 
    by _time host Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
```