# Windows Interactive Logons

## Description
The following rule identifies when a user logged in to a windows machine interactively, 
this detection is based on the modification of the registry value `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\LastLoggedOnUser`

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Registry 
    where Registry.registry_path="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI\\LastLoggedOnUser"
    by _time Registry.dest Registry.user Registry.action Registry.registry_path Registry.registry_value_name Registry.registry_value_data
| `drop_dm_object_name("Registry")`
```