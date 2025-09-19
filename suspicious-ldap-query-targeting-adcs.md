# Suspicious LDAP Query targeting ADCS

### Description

This query aims to detect suspicious LDAP queries that target Active Directory Certificate Services (ADCS) by looking for specific attributes commonly associated with certificate templates and enrollment flags. Such queries may indicate reconnaissance activity by an attacker attempting to gather information about certificate templates in the environment.

### References

- N/A

### Microsoft Defender XDR

```
let excluded_devices = dynamic(["example"]); // can be used with a watchlist - future versions
IdentityQueryEvents
| where ActionType =~ "LDAP query"
| where Query has "objectClass=certTemplate"
    or Query has "msPKI-Enrollment-Flag"
    or Query has "ntSecurityDescriptor"
| where not(DeviceName has_any (excluded_devices))
| project Timestamp, Application, DeviceName, IPAddress, AccountName, Query, QueryTarget, DestinationDeviceName, ReportId
```

### Microsoft Sentinel

```
```

### MITRE ATT&CK Mapping
- T1018 – Remote System Discovery
- T1069.002 – Permission Groups Discovery: Active Directory
- T1069.002 – Permission Groups Discovery: Active Directory
- T1003.008 – Credential Dumping: AD CS
- T1552.004 – Unsecured Credentials: Private Keys

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 2025-09-19    | Initial commit                    |
