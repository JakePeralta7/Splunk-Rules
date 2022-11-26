# Detect Execution of Sysinternals Tools

## [MITRE ATT&CK]()

## Description

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Registry 
    where Registry.registry_path="HKU*\\SOFTWARE\\Sysinternals\\*\\EulaAccepted"
    by _time Registry.dest Registry.user Registry.action Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid
```