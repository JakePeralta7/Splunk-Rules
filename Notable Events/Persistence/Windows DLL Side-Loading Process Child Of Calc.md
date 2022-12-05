# Windows DLL Side-Loading Process Child Of Calc

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1574/002/)
Tactic: Persistence

Technique: Hijack Execution Flow

Sub-Technique: DLL Side-Loading

## Description
The following rule identifies the suspicious child process of calc.exe due to dll side loading technique to execute another executable. This technique was seen in qakbot malware that uses dll side loading technique to calc applications to load its malicious dll code. The malicious dll that abuses dll side loading technique will load the actual qakbot loader dll using regsvr32.exe application. This TTP is a good indicator of qakbot since the calc.exe will not load other child processes aside from win32calc.exe.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where Processes.parent_process_name="calc.exe" AND Processes.process_name!="win32calc.exe" 
    by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process_id Processes.process_guid Processes.process 
| `drop_dm_object_name("Processes")`
```