# Scheduled Task was Created

## Description
This rule's goal is to let us know us when a scheduled task was created, 
this detection is based on the creation of file in the C:\Windows\System32\Tasks directory

## SPL
```spl
| from datamodel "Endpoint.Filesystem"
| search file_path=C:\\Windows\\System32\\Tasks\\*
```