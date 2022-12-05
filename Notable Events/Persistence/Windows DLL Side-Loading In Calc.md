# Windows DLL Side-Loading In Calc

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1574/002/)
Tactic: Persistence

Technique: Hijack Execution Flow

Sub-Technique: DLL Side-Loading

## Description
The following rule identifies suspicious DLL modules loaded by calc.exe that are not in windows `%systemroot%\system32` or `%systemroot%\sysWoW64` folder. This technique is well used by Qakbot malware to execute its malicious DLL file via dll side loading technique in calc process execution. This TTP detection is a good indicator that a suspicious dll was loaded in a public or non-common installation folder of Windows Operating System that needs further investigation.

## SPL
```spl
`sysmon` 
| search EventCode=7 Image = "*\calc.exe" AND NOT (Image IN ("*:\\windows\\system32\\*", "*:\\windows\\sysWow64\\*")) AND NOT(ImageLoaded IN("*:\\windows\\system32\\*", "*:\\windows\\sysWow64\\*", "*:\\windows\\WinSXS\\*")) 
| stats count by Image ImageLoaded OriginalFileName Product process_name Computer EventCode Signed ProcessId
```