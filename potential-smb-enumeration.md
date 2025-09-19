# Potential SMB enumeration

### Description

This query aims to detect potential SMB enumeration activity by identifying multiple connection attempts to different SMB shares on a remote host within a short time frame. Such behavior may indicate an attacker is attempting to discover accessible shares on the network.

### References

- N/A

### Microsoft Defender XDR

```
DeviceNetworkEvents
| where ActionType in ("ConnectionSuccess", "ConnectionFailed")
| where RemotePort == 445
| summarize 
    ShareCount = dcount(RemoteUrl), 
    AttemptCount = count() 
    by bin(Timestamp, 5m), DeviceId, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, ReportId
| where ShareCount > 5 and AttemptCount > 5
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, ShareCount, AttemptCount, ReportId
```

### Microsoft Sentinel

```
```

### MITRE ATT&CK Mapping
- T1021.002 – Remote Services: SMB/Windows Admin Shares
- T1018 – Remote System Discovery
- T1039 – Data from Network Shared Drive
- T1083 – File and Directory Discovery

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 2025-09-19    | Initial commit                    |
