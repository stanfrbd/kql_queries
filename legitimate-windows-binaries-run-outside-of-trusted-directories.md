# Legitimate windows binaries run outside of trusted directories

### Description

This query aims to detect legitimate Windows binaries being executed from non-standard directories. This behavior may indicate potential malicious activity, such as DLL hijacking or the use of living-off-the-land techniques by attackers. Even if this behavior can be detected out of the box in MDE, this query can help to have a more focused view. There can be a lot of false positives, so tuning is recommended.

### References

- N/A

### Microsoft Defender XDR

```
let trusted_binaries = dynamic([
"cmd.exe",
"powershell.exe",
"rundll32.exe",
"regedit.exe",
"reg.exe",
"wscript.exe",
"cscript.exe",
"mshta.exe",
"explorer.exe",
"svchost.exe",
"services.exe",
"taskmgr.exe",
"schtasks.exe",
"tasklist.exe",
"taskkill.exe",
"notepad.exe",
"calc.exe",
"mmc.exe",
"msconfig.exe",
"control.exe",
"dllhost.exe",
"lsass.exe",
"winlogon.exe",
"conhost.exe",
"searchprotocolhost.exe",
"searchfilterhost.exe",
"wininit.exe",
"winver.exe",
"mspaint.exe",
"mstsc.exe",
"cleanmgr.exe",
"dism.exe",
"msiexec.exe",
"at.exe",
"bcdedit.exe",
"bcdboot.exe",
"fsutil.exe",
"icacls.exe",
"netstat.exe",
"net.exe",
"ping.exe",
"tracert.exe",
"xcopy.exe",
"robocopy.exe",
"whoami.exe",
"hostname.exe",
"systeminfo.exe",
"gpupdate.exe",
"gpresult.exe"
]); // can be used with a watchlist - future versions
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName in~ (trusted_binaries)
| where not(FolderPath startswith @"C:\Windows\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessFileName, ProcessVersionInfoOriginalFileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, ReportId
```

### Microsoft Sentinel

```
```

### MITRE ATT&CK Mapping
- T1036.005 – Masquerading: Match Legitimate Name or Location
- T1218 – System Binary Proxy Execution
- T1071 – Application Layer Protocol (if used for C2)
- T1059 – Command and Scripting Interpreter

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 2025-09-19    | Initial commit                    |
