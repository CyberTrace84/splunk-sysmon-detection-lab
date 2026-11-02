# INC-004: Suspicious Scheduled Task Creation

> **Note:** This is a lab exercise. The task was created by me as a
> controlled simulation on my own test VM. The ticket is written as I would
> handle a real alert.

| Field | Value |
|---|---|
| Ticket ID | INC-004 |
| Alert | Suspicious Scheduled Task Creation (T1053.005) |
| Severity | High (alert rating); assessed as Low in this lab because I created the task |
| Status | Closed - true positive (simulated) |
| Task created | 2026-11-02 HH:MM:SS UTC (GST is UTC+4) |
| Alert triggered (UTC) | 2026-11-02 12:25:00 UTC |
| Host | DESKTOP-QGD5SNC |
| Actor | DESKTOP-QGD5SNC\Thoufeeq |
| Task name | LabUpdater2 |
| Analyst | Mohamed Thoufeeq |
| Data source | Sysmon Event ID 1 (process creation) in Splunk |

## 1. Summary
The detection fired when `schtasks.exe` was used to create a task that runs a
command prompt as SYSTEM every time a user logs on.

## 2. Evidence
- **Command:** `schtasks /create /tn LabUpdater2 /tr "C:\Windows\System32\cmd.exe /c echo lab-test2" /sc onlogon /ru SYSTEM /f`
- **Alert flags (3 of 4):** Runs as SYSTEM, Logon trigger, Script or LOLBin action
- **Parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Screenshots:** `screenshots/17-schtasks-sysmon-events.png`,
  `screenshots/18-schtasks-detection-results.png`,
  `screenshots/21-schtasks-alert-triggered.png`

## 3. Analysis
1. **Why it matters:** a task that runs as SYSTEM at every logon lets an
   attacker re-run a program after a reboot or after the original session is
   closed (persistence, T1053.005). Running as SYSTEM also means any program
   it launches has the highest local privileges.
2. **Who created it:** an interactive PowerShell session, started by the
   logged-in local user. This is not an Office application or a browser, which
   would be a bigger red flag.
3. **The action:** `cmd.exe /c echo lab-test2` only prints text. A real
   attacker would point the task at a script or binary, often in a
   user-writable folder such as Temp or AppData.
4. **Did it run?** I searched Sysmon for `cmd.exe` processes containing the
   task's command text over the previous 24 hours and found none. The task is
   triggered by user logon, and no logon happened before I deleted it.
5. **Related activity:** the same actor created two other tasks earlier on the
   same host from the same shell: `LabUpdater` at 12:08:00 UTC (3 flags) and
   `LabPS` at 12:08:13 UTC (2 flags, a hidden PowerShell action). Several
   persistence tasks created minutes apart from one shell would raise
   concern in a real environment.

## 4. Verdict
**True positive for the technique, not a real incident.** The detection works
as designed. In production this alert would stay High until the task's
purpose is confirmed.

## 5. Escalation decision
**Not escalated** in this case. I would escalate to L2 immediately if:
- the task runs as SYSTEM and launches a script, LOLBin or unknown binary;
- the action path is in Temp, AppData, ProgramData or Public;
- the parent process is an Office application, browser or remote-access tool;
- several tasks or other persistence appear on the same host or user.

## 6. Recommended actions (if this were real)
- Export the task definition and identify the program it runs.
- Check whether the task executed, and what it launched.
- If unauthorised: disable and delete the task, isolate the host, reset the
  actor's credentials, and search other hosts for the same task name or command.

## 7. Detection notes
- Expected false positives: installers, updaters and admin maintenance tasks.
- Requiring 2 or more risk flags reduces noise from tasks that have only one
  common trait, such as a logon trigger.
- Limitation: this detection depends on `schtasks.exe`. Tasks created through
  the PowerShell `Register-ScheduledTask` cmdlet or other APIs would not
  appear. Adding Security event 4698 (task created) would cover them.
- 10-minute lookback; suppression per host for 30 minutes.
