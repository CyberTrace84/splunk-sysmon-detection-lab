# INC-003: New Local Administrator Account

> **Note:** This is a lab exercise. The account was created by me as a
> controlled simulation on my own test VM. The ticket is written as I would
> handle a real alert.

| Field | Value |
|---|---|
| Ticket ID | INC-003 |
| Alert | New Local Admin Account (T1136.001) |
| Severity | High (alert rating); assessed as Low in this lab because I created the account |
| Status | Closed - true positive (simulated) |
| Account created | 2026-10-19 14:38:55 GST (UTC+4) / 10:38:55 UTC |
| Added to Administrators | 2026-10-19 14:38:56 GST / 10:38:56 UTC |
| Alert triggered (UTC) | 2026-10-19 10:40:01 UTC |
| Removed and deleted | 10:46:51 and 10:46:57 UTC (about 8 minutes later) |
| Host | DESKTOP-QGD5SNC |
| Actor | Thoufeeq (local account) |
| New account | labtest10 (SID ending -1004) |
| Analyst | Mohamed Thoufeeq |
| Data source | Windows Security events 4720, 4732, 4733, 4726 in Splunk |

## 1. Summary
The detection fired when a new local account, `labtest10`, was added to the
local Administrators group about one second after it was created.

## 2. Evidence
- **4720:** account `labtest10` created by `Thoufeeq` at 10:38:55 UTC
- **4732 (Users):** automatic add to the Users group at 10:38:55 UTC (normal)
- **4732 (Administrators):** added to group SID S-1-5-32-544 at 10:38:56 UTC
- **4733 x2 and 4726:** removed from both groups and deleted at 10:46:51 to 10:46:57 UTC
- **Screenshots:** `screenshots/12-new-admin-raw-events.png`,
  `screenshots/13-new-admin-detection-results.png`,
  `screenshots/16-new-admin-alert-triggered.png`

## 3. Analysis
1. **Who and what:** a local user created a new account and gave it
   administrator rights within about one second, which suggests a command
   sequence or script rather than manual work in the user-management console.
2. **Why it matters:** an admin account gives an attacker a way back in after
   the original account's password is reset (persistence, T1136.001).
3. **Use of the account:** I searched for logons (4624, 4648) and process
   creation (4688) by `labtest10` between 10:38 and 10:48 UTC and found none.
4. **Lifetime:** the account existed for about 8 minutes and was then removed
   from both groups and deleted by the same actor. In a real case, removal does
   not close the investigation, because attackers also delete accounts to hide
   their tracks.
5. **Related activity:** the same actor created other test accounts on this
   host earlier the same day (`labtest9`, and an earlier `labtest10` with a
   different SID). Repeated create-and-delete activity in one day would raise
   concern in a real environment. The SID, not the name, identified each
   account, which is why the detection correlates on SID.

## 4. Verdict
**True positive for the technique, not a real incident.** The detection works
as designed. In production this alert would stay High until the activity is
confirmed as authorised.

## 5. Escalation decision
**Not escalated** in this case. I would escalate to L2 immediately if:
- no change request or onboarding ticket explains the account;
- the actor is not an IT administrator or the activity is outside working hours;
- the account was used to log on or run processes;
- the same actor created other accounts or other persistence (scheduled
  tasks, services).

## 6. Recommended actions (if this were real)
- Confirm with the IT team or the actor whether the change was authorised.
- Disable the account and review everything it did, using its SID.
- If unauthorised: reset the actor's credentials, check for other persistence,
  and review all local admin group memberships on the host and similar hosts.

## 7. Detection notes
- Expected false positives: IT onboarding and deployment tools.
- Windows adds every new account to Users automatically, so the query alerts
  only on the Administrators SID.
- Event 4732 shows the member only as a SID, so events are joined by SID.
- 10-minute lookback; suppression per member SID for 30 minutes.
