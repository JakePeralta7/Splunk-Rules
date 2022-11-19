# Certutil exe certificate extraction

## Description
This search looks for arguments to certutil.exe indicating the manipulation or extraction of Certificate. This certificate can then be used to sign new authentication tokens specially inside Federated environments such as Windows ADFS.

## SPL
```spl
| tstats count
    from datamodel=Endpoint.Processes
    where Processes.process_name=certutil.exe Processes.process="*-exportPFX*"
    by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
```