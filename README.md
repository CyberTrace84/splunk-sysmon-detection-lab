# Splunk + Sysmon Detection Lab

## Objective
Build a small SOC lab to collect Windows logs, detect suspicious
activity, and document findings as an L1 analyst would.

## Architecture
- Windows 11 VM with Sysmon (SwiftOnSecurity config)
- Splunk Universal Forwarder sending to a Splunk Enterprise server
- Ubuntu Server VM running Splunk, firewalled with UFW
- Built in VMware Workstation Pro

## Log sources
- Windows Security (logons, privileges)
- Windows System
- Sysmon Operational (process creation and more)

## Detections
| Name | ATT&CK | Log source | Logic | False positives |
|---|---|---|---|---|
| Multiple failed logons | T1110.001 | Security 4625 | 5+ failures in 5 min per user/source | Forgotten passwords |

## Testing
 Simulated a password-guessing attack with failed network logons:
```powershell
   1..10 | ForEach-Object {
     net use \\localhost\IPC$ /user:fakeadmin "WrongPass$_" 2>$null
     Start-Sleep -Seconds 2
   }
```
   Result: 10 failed logons (Event ID 4625, Logon Type 3) for `fakeadmin`; the alert triggered within the 5-minute schedule.

## Screenshots

**Failed logon events (Event ID 4625)**
![Failed logons](screenshots/01-failed-logons-events.png)

**Brute-force alert configuration**
![Alert config](screenshots/02-brute-force-alert-config.png)

**Alert triggered**
![Alert triggered](screenshots/03-alert-triggered.png)

## Challenges and fixes
- Stats table was empty because I grouped by a field that didn't exist
- Sysmon logs were missing until I corrected the forwarder inputs.conf

## Next steps
- Suspicious PowerShell detection
- Incident tickets from the alerts
