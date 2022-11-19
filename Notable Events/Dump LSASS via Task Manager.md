# Dump LSASS via Task Manager

## Overview

## SPL
```spl
| tstats count
from datamodel=Endpoint.Filesystem 
where Filesystem.file_name=lsass.DMP AND Filesystem.action=created
by host Filesystem.user Filesystem.action Filesystem.file_path Filesystem.process_id
```