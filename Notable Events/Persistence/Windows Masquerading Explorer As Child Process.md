# Windows Masquerading Explorer As Child Process

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1574/002/)
Tactic: Persistence

Technique: Hijack Execution Flow

Sub-Technique: DLL Side-Loading

## Description
The following rule identifies a suspicious parent process of explorer.exe. Explorer is usually executed by userinit.exe that will exit after execution that causes the main explorer.exe no parent process. Some malware like qakbot spawn another explorer.exe to inject its code. This TTP detection is a good indicator that a process spawning explorer.exe might inject code or masquerading its parent child process to evade detections.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where Processes.parent_process_name IN ("cmd.exe", "powershell.exe", "regsvr32.exe") AND Processes.process_name="explorer.exe" 
    by Processes.dest Processes.parent_process Processes.parent_process_name Processes.process_name Processes.process_id Processes.process_guid Processes.process Processes.user Processes.parent_process_id 
| `drop_dm_object_name("Processes")`
```

## TODO
Check this possible logic in production, might need some fine-tuning
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where Processes.parent_process_name!="userinit.exe" AND Processes.process_name="explorer.exe" 
    by Processes.dest Processes.parent_process Processes.parent_process_name Processes.process_name Processes.process_id Processes.process_guid Processes.process Processes.user Processes.parent_process_id 
| `drop_dm_object_name("Processes")`
```