# Fast Statistics

The command `tstats` allows us to display highly customizable and fast questions about our data

## Analyzing content of an index
1. Displaying 
```spl
| tstats count
    where index=sysmon
    by sourcetype
| sort - count
```