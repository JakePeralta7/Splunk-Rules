# Usage of Debugger in Image File Execution Options

## Description
The Debugger registry key can allow an adversary to intercept the execution of files, causing a different process to be executed. This functionality can be abused by an adversary to establish persistence.

## SPL
|  from datamodel "Endpoint.Registry"
| search registry_path="*SOFTWARE\\Microsoft\\*\\Image File Execution Options\\*\\Debugger"