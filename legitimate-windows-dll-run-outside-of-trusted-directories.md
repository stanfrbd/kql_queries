# Legitimate windows DLLs run outside of trusted directories

### Description

This query aims to detect legitimate Windows DLLs being loaded from non-standard directories. This behavior may indicate potential malicious activity, such as DLL hijacking or the use of living-off-the-land techniques by attackers. Even if this behavior can be detected out of the box in MDE, this query can help to have a more focused view. There can be a lot of false positives, so tuning is recommended.

### References

- N/A

### Microsoft Defender XDR

```
DeviceImageLoadEvents
| where FileName in~ (
    "ntdll.dll", "kernel32.dll", "user32.dll", "advapi32.dll", "ws2_32.dll",
    "shell32.dll", "ole32.dll", "oleaut32.dll", "comctl32.dll", "comdlg32.dll",
    "gdi32.dll", "rpcrt4.dll", "shlwapi.dll", "wininet.dll", "wintrust.dll",
    "crypt32.dll", "msvcrt.dll", "secur32.dll", "urlmon.dll", "netapi32.dll",
    "version.dll", "mswsock.dll", "dbghelp.dll", "imagehlp.dll", "setupapi.dll"
) // can be used with a watchlist - future versions
| where not(FolderPath startswith @"C:\Windows\" or FolderPath startswith @"C:\Program")
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessAccountUpn,
    InitiatingProcessVersionInfoCompanyName,
    InitiatingProcessVersionInfoProductName,
    ReportId
```

### Microsoft Sentinel

```
```

### MITRE ATT&CK Mapping
- T1073.001 – DLL Side-Loading
- T1055.001 – Process Injection via DLLs
- T1036.005 – Masquerading: Match Legitimate Name or Location

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 2025-09-19    | Initial commit                    |
