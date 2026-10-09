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
Simulated failed network logons with a PowerShell loop. The alert fired as expected.

## Screenshots
(add links)

## Challenges and fixes
- Stats table was empty because I grouped by a field that didn't exist
- Sysmon logs were missing until I corrected the forwarder inputs.conf

## Next steps
- Suspicious PowerShell detection
- Incident tickets from the alerts
