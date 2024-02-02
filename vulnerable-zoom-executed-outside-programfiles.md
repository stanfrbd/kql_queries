# Vulnerable Zoom version executed outside of Program Files

### Description

This query aims to track devices where Zoom.exe was executed outside of Program Files (obviously unpackaged version).
Zoom before version 5.6.10 is vulnerable to CVE-2023-49647, which allows an unauthenticated attacker to gain a LPE.

### References

- https://nvd.nist.gov/vuln/detail/CVE-2023-49647
- https://www.zoom.com/en/trust/security-bulletin/ZSB-24001/

### Microsoft Defender XDR & Sentinel

```
// Track vulnerable zoom versions executed outside of Program Files
DeviceProcessEvents
| where FileName contains "zoom.exe" 
and not(FolderPath contains "program files") 
and FileName != "CleanZoom.exe"
// add more excluded versions here and not(ProcessVersionInfoProductVersion startswith ...)
and not(ProcessVersionInfoProductVersion startswith "5,17" or ProcessVersionInfoProductVersion startswith "5.17")
and not(ProcessVersionInfoProductVersion startswith "5,16,10" or ProcessVersionInfoProductVersion startswith "5.16.10")
| summarize count() by FileName,ProcessVersionInfoProductVersion, DeviceName, AccountName
```

### MITRE ATT&CK Mapping
- Tactic: <TBD>
- Technique ID: <TBD>

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 2024-02-02    | Initial commit                    |
