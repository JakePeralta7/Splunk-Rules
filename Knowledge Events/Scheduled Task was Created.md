# Scheduled Task was Created

## Description
The following rule identifies when a scheduled task is being created, 
this detection is based on the creation of file in the `C:\Windows\System32\Tasks` directory

## SPL
```spl
| tstats count 
    from datamodel=Endpoint.Filesystem 
    where Filesystem.file_path="*:\\Windows\\System32\\Tasks\\*" AND Filesystem.action=created
    by _time Filesystem.dest Filesystem.process_name Filesystem.user Filesystem.action Filesystem.file_path Filesystem.file_name Filesystem.file_create_time
| `drop_dm_object_name("Filesystem")`
```