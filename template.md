# Title

### Description

This query aims to ...

### References

- [Link](URL)
- [Link](URL)

### Microsoft Defender XDR

```
DeviceNetworkEvents
| where RemoteUrl has "stealer.cy"
```

### Microsoft Sentinel

```
SecurityEvent
| where EventID == 4624
```

### MITRE ATT&CK Mapping
- TTPs

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | date          | Initial commit                    |
