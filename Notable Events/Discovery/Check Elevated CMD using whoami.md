# Check Elevated CMD using whoami

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1033/)
Tactic: Discovery

Technique: System Owner/User Discovery

## Description
This search is to detect a suspicious whoami execution to check if the cmd or shell instance process is with elevated privileges. This technique was seen in FIN7 js implant where it execute this as part of its data collection to the infected machine to check if the running shell cmd process is elevated or not. This TTP is really a good alert for known attacker that recon on the targetted host.

This command is not so commonly executed by a normal user or even an admin to check if a process is elevated.

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Processes
    where Processes.process = "*whoami*" Processes.process = "*/group*"
    by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| join left=L right=R where L.Processes.dest=R.Processes.dest L.Processes.parent_process_id=R.Processes.parent_process_id 
    [ tstats count 
        from datamodel=Endpoint.Processes 
        where Processes.process="*find*" Processes.process="*12288*"
        by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id] 
| fields L.Processes.dest L.Processes.user L.Processes.parent_process L.Processes.parent_process_id L.Processes.process_name L.Processes.process L.Processes.process_id R.Processes.process_name R.Processes.process R.Processes.process_id
```