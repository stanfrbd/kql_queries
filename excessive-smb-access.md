# Excessive SMB access

### Description

This query aims to detect excessive SMB access activity by identifying accounts that access a high number of distinct machines via SMB within a short time frame. Such behavior may indicate an attacker is attempting to move laterally across the network by accessing multiple systems.

### References

- N/A

### Microsoft Defender XDR

```
```

### Microsoft Sentinel

```
SecurityEvent
| where EventID == 5145
| where ObjectType == "File" or ObjectType == "Share"
| extend TargetMachine = Computer, SourceAccount = Account, SourceIP = IpAddress
| summarize DistinctMachines = dcount(TargetMachine), Machines = make_set(TargetMachine)
    by SourceAccount, SourceIP, bin(TimeGenerated, 5m)
| where DistinctMachines > 10
| project TimeGenerated, SourceAccount, SourceIP, DistinctMachines, Machines
```

### MITRE ATT&CK Mapping
- T1021.002 – Remote Services: SMB/Windows Admin Shares
- T1039 – Data from Network Shared Drive
- T1018 – Remote System Discovery
- T1083 – File and Directory Discovery

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 2025-09-19    | Initial commit                    |
