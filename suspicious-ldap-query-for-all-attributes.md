# Suspicious LDAP Query for All Attributes

### Description

This query aims to detect suspicious LDAP queries that request all attributes of objects, which may indicate an attacker attempting to gather extensive information about users or devices in the environment.

### References

- N/A

### Microsoft Defender XDR

```
let excluded_accounts = dynamic(["example"]); // can be used with a watchlist - future versions
let excluded_devices = dynamic(["example"]); // can be used with a watchlist - future versions
IdentityQueryEvents
| where ActionType == "LDAP query"
| where QueryType == "AllObjects"
| extend LDAPQueryCount = toint(parse_json(AdditionalFields)["Count"])
| where LDAPQueryCount > 500
| where not(DestinationDeviceName has_any (excluded_devices))
| where not(TargetAccountUpn has_any(excluded_accounts))
```

### Microsoft Sentinel

```
```

### MITRE ATT&CK Mapping
- T1087.002 – Account Discovery: Domain Account
- T1069.002 – Permission Groups Discovery: Domain Groups
- T1018 – Remote System Discovery
- T1033 – System Owner/User Discovery

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 2025-09-19    | Initial commit                    |
