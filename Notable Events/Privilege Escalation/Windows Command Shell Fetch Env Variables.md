# Windows Command Shell Fetch Env Variables

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)
Tactic: Privilege Escalation

Technique: Process Injection

## Description
The following rule identifies a suspicious process command line fetching the environment variables with a non-shell parent process. This technique was seen in qakbot malware where it fetches the environment variable in the target or compromised host. This TTP detection is a good pivot of possible malicious behavior since the command line is executed by a common non-shell process like cmd.exe , powershell.exe and many more. This can also be a good sign that the parent process has a malicious code injected to it to execute this command.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Processes 
    where Processes.process = "*cmd /c set" OR Processes.process = "*cmd.exe /c set" AND NOT (Processes.parent_process_name = "cmd.exe" OR Processes.parent_process_name = "powershell*" OR Processes.parent_process_name="pwsh.exe" OR Processes.parent_process_name = "explorer.exe") 
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.original_file_name 
| `drop_dm_object_name(Processes)`
```