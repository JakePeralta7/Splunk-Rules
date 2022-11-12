# Windows Computer Shut Down

## Description
This rule will let us know when a computer has been shutdown

## SPL
index=* sourcetype="WinEventLog:System" EventCode=1074
| table _time ComputerName Shutdown_Type Message
| sort - _time