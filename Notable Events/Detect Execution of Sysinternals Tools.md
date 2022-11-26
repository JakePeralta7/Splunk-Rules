# Detect Execution of Sysinternals Tools

## Description
This rule detects usage of Sysinternals tools, when it first executed it asks the user to accept the EULA (End User License Agreement) - the result is saved to the registry.

During triage, check which Sysinternals tool was executed (in the registry path) and the user executing it (Sysinternals also has a legitimate use).

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Registry 
    where Registry.registry_path="HKU*\\SOFTWARE\\Sysinternals\\*\\EulaAccepted"
    by _time host Registry.user Registry.action Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid
| `drop_dm_object_name(Registry)`
```