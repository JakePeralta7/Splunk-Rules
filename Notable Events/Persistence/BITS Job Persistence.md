# BITS Job Persistence

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1548/002/)
Tactic: Persistence

Technique: BITS Jobs

## Description
The following query identifies Microsoft Background Intelligent Transfer Service utility bitsadmin.exe scheduling a BITS job to persist on an endpoint. The query identifies the parameters used to create, resume or add a file to a BITS job. Typically seen combined in a oneliner or ran in sequence. 

If identified, review the BITS job created and capture any files written to disk. It is possible for BITS to be used to upload files and this may require further network data analysis to identify. 

You can use bitsadmin /list /verbose to list out the jobs during investigation.

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Processes
    where (Processes.process_name=bitsadmin.exe OR Processes.original_file_name=bitsadmin.exe) Processes.process IN (*create*, *addfile*, *setnotifyflags*, *setnotifycmdline*, *setminretrydelay*, *setcustomheaders*, *resume*)
    by Processes.dest Processes.user Processes.original_file_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
```