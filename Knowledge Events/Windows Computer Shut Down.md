# Windows Computer Shut Down

## Description
This rule will let us know when a computer has been shutdown

## SPL
index=* sourcetype="WinEventLog:System" Shutdown_Type=*
| table ComputerName Message