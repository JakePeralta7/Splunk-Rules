# Windows COM Hijacking InprocServer32 Modification

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1546/015/)
Tactic: Persistence

Technique: Event Triggered Execution

Sub-Technique: Component Object Model Hijacking

## Description
The following rule identifies the use of reg.exe or regedit.exe performing an add to the InProcServer32, which may be related to COM hijacking. Adversaries can use the COM system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead.

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Registry 
    where Registry.process_name IN ("reg.exe", "regedit.exe") Registry.registry_path="*\\CLSID\\*\\InprocServer32\\*"
    by _time Registry.dest Registry.process_name Registry.user Registry.action Registry.registry_path Registry.registry_value_name Registry.registry_value_data
| `drop_dm_object_name("Registry")`
```