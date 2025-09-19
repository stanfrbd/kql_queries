# Microsoft Defender for Endpoint (MDE) Offboarding Package Downloaded

### Description

This query aims to detect when a Microsoft Defender for Endpoint offboarding package has been downloaded. This activity may indicate that a device is being prepared for removal from management or decommissioning. Admin can be an insider threat or an attacker who has gained access to an admin account.

### References

- N/A

### Microsoft Defender XDR / Microsoft Defender for Cloud Apps

```
CloudAppEvents
| where ActionType == "DownloadOffboardingPkg"
| extend RawData = parse_json(RawEventData)
| extend
AccountUpn = tostring(RawData.UserId),
OrgId = tostring(RawData.OrganizationId),
ClientIP = tostring(RawData.ClientIP),
DeploymentMethod = tostring(RawData.DeploymentMethod),
OsFamily = tostring(RawData.OsFamily),
PackageExpiration = tostring(RawData.PackageExpiration)
| project Timestamp, AccountUpn, AccountDisplayName, DeploymentMethod, OsFamily, PackageExpiration, ClientIP, OrgId, ReportId
```

### Microsoft Sentinel

```
```

### MITRE ATT&CK Mapping
- T1562.001 – Impair Defenses: Disable or Modify Tools
- T1070.004 – Indicator Removal on Host: File Deletion
- T1562 – Impair Defenses

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 2025-09-19    | Initial commit                    |
