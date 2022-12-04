# Fast Statistics

The command `tstats` allows us to display highly customizable and fast questions about our data

## Analyzing content of an index
1. Displaying all the sourcetypes in the index sysmon
```spl
| tstats count
    where index=sysmon
    by sourcetype
| sort - count
```

2. Displaying all the sourcetypes from all the indexes
```spl
| tstats count 
    where index=* 
    by index sourcetype
| sort - count
```

## Analyzing search usage
1. Displaying amount of searches by user and app
```spl
index=_audit action=search
| stats count by app user
| sort - count
```