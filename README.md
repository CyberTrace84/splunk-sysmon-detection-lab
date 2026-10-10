# Splunk + Sysmon Detection Lab

## Objective
Build a small SOC lab that collects Windows logs, detects suspicious activity, and documents findings the way an L1 analyst would.

## Architecture
- **Endpoint:** Windows 11 VM with Sysmon (SwiftOnSecurity config)
- **Forwarding:** Splunk Universal Forwarder sends logs to the server
- **SIEM:** Splunk Enterprise on an Ubuntu Server VM, firewalled with UFW (only ports 8000 and 9997 allowed)
- **Platform:** VMware Workstation Pro

## Log sources
- Windows Security (logons, privileges)
- Windows System
- Sysmon Operational (process creation and more)

## Detections

| Name | ATT&CK | Log source | Logic | False positives |
|---|---|---|---|---|
| Brute Force - Multiple Failed Logons | T1110.001 | Security 4625 | 5+ failures in 10 min per user and source | User forgetting their password |
| Suspicious PowerShell Execution | T1059.001 | Sysmon Event ID 1 | Encoded, hidden, bypass or download flags on powershell.exe | Admin scripts and installers using Bypass |

### Brute-force detection: analyst notes
**Query:** [detections/brute-force-4625.spl](detections/brute-force-4625.spl)

**Triage steps when it fires:**
1. Check the target account: does it exist, and is it privileged?
2. Check the source address and logon type (Type 3 network or Type 10 RDP is more suspicious than Type 2 at the keyboard).
3. Check whether a successful logon (4624) follows the failures from the same source.
4. Escalate if a success follows, the account is privileged, or the source is external.

**Tuning:** threshold of 5 failures catches guessing while ignoring a single typo. The search looks back 10 minutes and repeats are suppressed per user for 30 minutes, so one attack produces one alert.

### PowerShell detection: analyst notes
**Query:** [detections/suspicious-powershell-t1059-001.spl](detections/suspicious-powershell-t1059-001.spl)

**Triage steps when it fires:**
1. Check the `reason` field: which suspicious flag matched?
2. Check `ParentImage`: PowerShell launched by Word, Excel or a browser is a major red flag; launched by an admin's terminal is less so.
3. Decode any encoded command (base64, UTF-16) to see what it actually runs.
4. Check the user and host, and whether the same activity is scheduled or recurring.
5. Escalate if the parent is an Office app or browser, the payload downloads or runs remote content, or the account isn't expected to use PowerShell.

**Tuning:** 10-minute lookback, suppression per host for 30 minutes. Expected false positives are deployment scripts that use `-ExecutionPolicy Bypass`.

## Testing
Simulated a password-guessing attack with failed network logons:

```powershell
1..10 | ForEach-Object {
  net use \\localhost\IPC$ /user:fakeadmin "WrongPass$_" 2>$null
  Start-Sleep -Seconds 2
}
```

Result: failed logons (Event ID 4625) for `fakeadmin`, and the alert triggered.

Simulated attacker-style PowerShell with harmless commands:

```powershell
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("whoami"))
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $enc
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'test'"
```

Result: both commands were detected, with reasons "Encoded command", "Hidden window" and "Execution policy bypass".

## Screenshots

**Failed logon events (Event ID 4625)**

![Failed logons](screenshots/01-failed-logons-events.png)

### Before tuning
**Alert configuration (v1)**

![Alert config v1](screenshots/02-brute-force-alert-config.png)

**11 alerts for a single test**

![Duplicate alerts](screenshots/03-alert-triggered.png)

### After tuning
**Tuned search and schedule (v2)**

![Tuned search](screenshots/04-alert-config-tuned-search.png)

**Trigger and throttle settings**

![Throttle](screenshots/05-alert-config-tuned-throttle.png)

**One alert for the same test (Mode: Per Result)**

![Single alert](screenshots/06-alert-triggered-after-tuning.png)

### PowerShell detection
![Sysmon events](screenshots/07-powershell-sysmon-events.png)
![Detection results](screenshots/08-powershell-detection-results.png)
![Alert config](screenshots/09-powershell-alert-config.png)
![Throttle](screenshots/10-powershell-alert-throttle.png)
![Triggered](screenshots/11-powershell-alert-triggered.png)

## Challenges and fixes
- **Empty statistics table.** My `stats` search grouped by `IpAddress`, which didn't exist in the 4625 events, so every row was dropped. Fixed by inspecting a raw event and using the real field names.
- **Sysmon logs missing in Splunk.** Sysmon was logging locally, but the forwarder wasn't sending it. Fixed by correcting the `inputs.conf` stanza, restarting the forwarder service, and verifying with `btool`.
- **Real-time time range returned nothing.** Real-time searches only show new events, so I used a "last 24 hours" window for historical data.
- **Duplicate alerts.** The first version re-triggered every 5 minutes (11 alerts for one test) because the search had no tight time window and no throttling. Fixed with a 10-minute lookback and a 30-minute per-user supp- **Query syntax error.** Splunk rejected my first PowerShell search with "'-' only takes numbers" because text patterns beginning with a dash were broken by misplaced quotes. Fixed by splitting the logic into small `eval` steps with patterns that don't start with a dash.
- **Wrong `User` value.** Sysmon events returned two `User` values, one of them `NOT_TRANSLATED`. Fixed by selecting the last value with `mvindex(User,-1)`.ression.

## Roadmap
- [x] Suspicious PowerShell detection (T1059.001) using Sysmon Event ID 1
- [ ] L1 incident tickets for each alert (in `/reports`)
- [ ] Architecture diagram
- [ ] Rebuild detections in Microsoft Sentinel (KQL)
