# Splunk Command and Scripting Interpreter Delete Usage

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/)
Tactic: Execution

Technique: Command and Scripting Interpreter

## Description
The following rule identifies the use of the risky command - Delete - that may be utilized in Splunk to delete some or all data queried for. In order to use Delete in Splunk, one must be assigned the role. This is typically not used and should generate an anomaly if it is used.

## SPL
```spl
| tstats count 
    from datamodel=Splunk_Audit.Search_Activity 
    where Search_Activity.search IN ("*delete*") Search_Activity.search_type=adhoc Search_Activity.user!=splunk-system-user 
    by Search_Activity.search Search_Activity.info Search_Activity.total_run_time Search_Activity.user Search_Activity.search_type 
| `drop_dm_object_name(Search_Activity)`
```