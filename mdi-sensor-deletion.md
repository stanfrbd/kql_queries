# Microsoft Defender for Identity (MDI) Sensor Deletion

### Description

This query aims to detect the deletion of Microsoft Defender for Identity (MDI) sensors in the environment. Such activity may indicate potential tampering or removal of security monitoring capabilities by an attacker.

### References

- N/A

### Microsoft Defender XDR / Microsoft Defender for Cloud Apps

```
CloudAppEvents
| where ActionType == "SensorDeleted"
| extend Sensor = tostring(parse_json(RawEventData).ResultDescription), AccountUPN = tostring(parse_json(RawEventData).UserId)
| project Timestamp, Sensor, AccountObjectId, AccountUPN, AccountDisplayName, AccountType, ReportId
```

### Microsoft Sentinel

```
```

### MITRE ATT&CK Mapping
- T1562.001 – Impair Defenses: Disable or Modify Tools
- T1089 – Disabling Security Tools
- T1078 – Valid Accounts (if the deletion is done using compromised credentials)

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 2025-09-19    | Initial commit                    |
