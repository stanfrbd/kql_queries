# Infostealer using Python to exfiltrate data 

### Description

This query aims to detect the use of Python-based infostealers that exfiltrate sensitive data from compromised systems. The focus is on identifying suspicious process activity and network connections associated with known infostealer behaviors. This query can produce a lot of false positives, so tuning / exclusions may be required. A dashboard can be created to monitor this activity over time and view weak signals that may indicate the presence of infostealers in the environment.

### References

- [Pentagon Stealer analysis - Any.Run](https://any.run/cybersecurity-blog/pentagon-stealer-malware-analysis/)

### Microsoft Defender XDR

```
let excludedArgs = dynamic(["debugpy", "gitlab", "blender", "vscode", "selenium", "jupyter", "jupyterlab", "anaconda", "autodesk", "tokenize", "flask", "pre-commit", "localhost"]); // can be used with a watchlist - future versions
let keywords = dynamic(["discord", "telegram", "wallet", "clipboard", "cookie", "edge", "chrome", "firefox", "token"]);
let targetExecutables = dynamic(["py.exe", "python.exe", "pythonw.exe"]);
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName in~ (targetExecutables)
| where ProcessCommandLine has_any (keywords)
| where not(ProcessCommandLine has_any (excludedArgs))
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, AccountUpn, DeviceId, ReportId
```

### Microsoft Sentinel

```
```

### MITRE ATT&CK Mapping
- T1555 – Credentials from Password Stores
- T1539 – Steal Web Session Cookie
- T1059.006 – Command and Scripting Interpreter: Python

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 2025-09-19    | Initial commit                    |
