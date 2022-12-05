# Detect SharpHound File Modifications

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1069/)
Tactic: Discovery

Technique: Permission Groups Discovery

## Description
SharpHound is used as a reconnaissance collector, ingestor, for BloodHound. SharpHound will query the domain controller and begin gathering all the data related to the domain and trusts. For output, it will drop a .zip file upon completion following a typical pattern that is often not changed. This analytic focuses on the default file name scheme. Note that this may be evaded with different parameters within SharpHound, but that depends on the operator. -randomizefilenames and -encryptzip are two examples.

In addition, executing SharpHound via .exe or .ps1 without any command-line arguments will still perform activity and dump output to the default filename. Example default filename 20210601181553_BloodHound.zip. SharpHound creates multiple temp files following the same pattern 20210601182121_computers.json, domains.json, gpos.json, ous.json and users.json. Tuning may be required, or remove these json's entirely if it is too noisy.

During traige, review parallel processes for further suspicious behavior. Typically, the process executing the .ps1 ingestor will be PowerShell.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Filesystem 
    where Filesystem.file_name IN ("*bloodhound.zip", "*_computers.json", "*_gpos.json", "*_domains.json", "*_users.json", "*_groups.json", "*_ous.json", "*_containers.json") 
    by Filesystem.dest Filesystem.file_create_time Filesystem.process_id Filesystem.file_name Filesystem.file_path
```